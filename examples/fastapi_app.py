"""
Example: FastAPI app with rai-guard middleware.

Run with: uvicorn examples.fastapi_app:app --reload
Open:     http://127.0.0.1:8000
"""

import json
import os
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Any

from fastapi import FastAPI, Query
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from raiguard.middleware import AIGuardMiddleware
from raiguard.evidence.store import EvidenceStore
from raiguard.evidence.report import _HTML_TEMPLATE
from raiguard.compliance.owasp_llm import OWASP_LLM_TOP10
from raiguard.compliance.eu_ai_act import EU_AI_ACT_ARTICLES
from raiguard.compliance.nist_ai_rmf import NIST_AI_RMF

_static_dir = os.path.join(os.path.dirname(__file__), "static")
_DB_PATH = os.getenv("RAI_DB_PATH", "raiguard_audit.db")

_store: EvidenceStore | None = None


@asynccontextmanager
async def lifespan(app: FastAPI):  # type: ignore[type-arg]
    global _store
    _store = EvidenceStore(_DB_PATH)
    try:
        await _store.connect()
    except Exception:
        _store = None
    yield
    if _store:
        await _store.close()


app = FastAPI(title="rai-guard Demo App", lifespan=lifespan)
app.mount("/static", StaticFiles(directory=_static_dir), name="static")


# ── request capture middleware (runs AFTER rai-guard, logs everything) ─────────

from starlette.middleware.base import BaseHTTPMiddleware as _BaseHTTPMiddleware
from starlette.requests import Request as _Request
from starlette.responses import Response as _Response


class _RequestLogger(_BaseHTTPMiddleware):
    async def dispatch(self, request: _Request, call_next: Any) -> _Response:
        if request.method == "POST" and request.url.path == "/ask":
            body_bytes = await request.body()
            try:
                body = json.loads(body_bytes)
                prompt = body.get("prompt", "")
            except Exception:
                prompt = ""

            # Rebuild a receivable body for downstream middleware/routes
            from starlette.datastructures import Headers
            from io import BytesIO

            async def _receive():  # type: ignore[return]
                return {"type": "http.request", "body": body_bytes}

            request = _Request(request.scope, _receive)

            response = await call_next(request)

            if response.status_code == 400 and prompt:
                # Blocked by rai-guard
                try:
                    body_out = b""
                    async for chunk in response.body_iterator:
                        body_out += chunk
                    resp_data = json.loads(body_out)
                    _log_request(
                        prompt=prompt,
                        passed=False,
                        risk_score=resp_data.get("risk_score") or 0.0,
                        blocked_by=resp_data.get("blocked_by") or [],
                        session_id=resp_data.get("session_id") or "",
                        remediation=resp_data.get("remediation") or [],
                    )
                    from starlette.responses import Response as _Resp
                    return _Resp(
                        content=body_out,
                        status_code=400,
                        headers=dict(response.headers),
                        media_type="application/json",
                    )
                except Exception:
                    pass
            return response
        return await call_next(request)


app.add_middleware(_RequestLogger)

# Add rai-guard middleware — inspects all JSON request/response bodies
app.add_middleware(
    AIGuardMiddleware,
    block_on_fail=True,
    score_threshold=0.7,
    store=None,  # middleware store wiring kept separate; we expose our own API endpoints
    exclude_paths=["/api/hub/validate"],  # allow test payloads through to the validation endpoint
)


# ── helpers ───────────────────────────────────────────────────────────────────

async def _get_store() -> EvidenceStore | None:
    if _store and _store._db:
        return _store
    try:
        s = EvidenceStore(_DB_PATH)
        await s.connect()
        return s
    except Exception:
        return None


# ── demo request store (lightweight, in-memory log for the Web UI) ────────────
# Because the middleware does not wire into our EvidenceStore directly in this
# demo, we maintain a simple in-memory list of the last 500 requests so the
# audit-log tab in the UI can show something without requiring aiosqlite to be
# connected through the middleware.

_request_log: list[dict] = []
_MAX_LOG = 500


def _log_request(
    prompt: str,
    passed: bool,
    risk_score: float,
    blocked_by: list[str],
    session_id: str,
    remediation: list[str],
) -> None:
    _request_log.insert(0, {
        "id": str(uuid.uuid4())[:8],
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "prompt": prompt[:300],
        "passed": passed,
        "risk_score": risk_score,
        "blocked_by": blocked_by,
        "session_id": session_id,
        "remediation": remediation,
    })
    if len(_request_log) > _MAX_LOG:
        _request_log.pop()


# ── models ────────────────────────────────────────────────────────────────────

class PromptRequest(BaseModel):
    prompt: str


class PromptResponse(BaseModel):
    response: str


# ── routes ────────────────────────────────────────────────────────────────────

@app.post("/ask", response_model=PromptResponse)
async def ask(body: PromptRequest) -> PromptResponse:
    # Middleware already blocked harmful prompts before this executes.
    # Log the successful pass.
    _log_request(
        prompt=body.prompt,
        passed=True,
        risk_score=0.0,
        blocked_by=[],
        session_id="",
        remediation=[],
    )
    response_text = f"Echo (protected): {body.prompt}"
    return PromptResponse(response=response_text)


@app.get("/health")
async def health() -> dict:
    return {"status": "ok"}


@app.get("/")
async def ui() -> FileResponse:
    return FileResponse(os.path.join(_static_dir, "index.html"))


# ── API: stats ────────────────────────────────────────────────────────────────

@app.get("/api/stats")
async def api_stats() -> dict:
    """Live stats for the dashboard."""
    total = len(_request_log)
    blocked = sum(1 for r in _request_log if not r["passed"])
    avg_risk = (sum(r["risk_score"] for r in _request_log) / total) if total else 0.0
    return {
        "total_requests": total,
        "blocked_requests": blocked,
        "passed_requests": total - blocked,
        "pass_rate": round((total - blocked) / total * 100, 1) if total else 100.0,
        "average_risk_score": round(avg_risk, 3),
        "checks_enabled": [
            "prompt_injection", "pii", "toxicity",
            "hallucination", "insecure_output",
        ],
    }


# ── API: audit log ────────────────────────────────────────────────────────────

@app.get("/api/events")
async def api_events(
    limit: int = Query(50, ge=1, le=200),
    failed_only: bool = False,
    offset: int = Query(0, ge=0),
) -> list:
    """Paginated audit log for the Web UI."""
    rows = [r for r in _request_log if (not failed_only or not r["passed"])]
    return rows[offset: offset + limit]


# ── API: compliance ───────────────────────────────────────────────────────────

@app.get("/api/compliance")
async def api_compliance() -> dict:
    """Return OWASP / EU AI Act / NIST compliance summary."""
    # Build per-category scores from the in-memory log
    blocked_checks: dict[str, int] = {}
    for r in _request_log:
        for chk in r.get("blocked_by", []):
            blocked_checks[chk] = blocked_checks.get(chk, 0) + 1

    total = len(_request_log)

    # OWASP LLM Top 10
    owasp_categories = []
    check_to_owasp = {
        "prompt_injection": "LLM01",
        "pii": "LLM06",
        "toxicity": "LLM02",
        "hallucination": "LLM09",
        "insecure_output": "LLM02",
    }
    owasp_hit: dict[str, int] = {}
    for chk, cat in check_to_owasp.items():
        owasp_hit[cat] = owasp_hit.get(cat, 0) + blocked_checks.get(chk, 0)

    for cat_id, meta in OWASP_LLM_TOP10.items():
        hits = owasp_hit.get(cat_id, 0)
        risk = round(min(1.0, hits / max(total, 1)), 3) if total else 0.0
        owasp_categories.append({
            "id": cat_id,
            "name": meta["name"],
            "risk_score": risk,
            "compliant": risk < 0.3,
            "description": meta["description"],
            "mitigation": meta["mitigation"],
        })

    owasp_pct = round(
        100 * sum(1 for c in owasp_categories if c["compliant"]) / len(owasp_categories), 1
    )

    # EU AI Act
    eu_articles = []
    article_checks = {
        "Article 9": ["prompt_injection", "toxicity"],
        "Article 10": ["pii"],
        "Article 12": [],  # always contribute evidence
        "Article 13": ["hallucination", "pii", "toxicity"],
        "Article 14": [],
        "Article 15": ["prompt_injection", "insecure_output"],
        "Article 17": [],
    }
    for art, meta in EU_AI_ACT_ARTICLES.items():
        checks = article_checks.get(art, [])
        hits = sum(blocked_checks.get(c, 0) for c in checks)
        score = round(max(0.0, 1.0 - min(1.0, hits / max(total, 1))), 3) if total else 1.0
        eu_articles.append({
            "article": art,
            "title": meta["title"],
            "compliance_score": score,
            "compliant": score >= 0.7,
            "risk_level": "high" if score < 0.5 else ("medium" if score < 0.8 else "low"),
        })

    eu_pct = round(
        100 * sum(1 for a in eu_articles if a["compliant"]) / len(eu_articles), 1
    )

    # NIST AI RMF
    nist_functions = []
    for fn, meta in NIST_AI_RMF.items():
        nist_functions.append({
            "function": fn,
            "description": meta["description"],
            "maturity": "Implemented" if total > 0 else "Planned",
            "subcategories": list(meta["subcategories"].values()),
        })

    return {
        "owasp": {"score": owasp_pct, "categories": owasp_categories},
        "eu_ai_act": {"score": eu_pct, "articles": eu_articles},
        "nist": {"functions": nist_functions},
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }


# ── API: report download ──────────────────────────────────────────────────────

@app.get("/api/report/json")
async def api_report_json() -> Response:
    """Download the compliance report as JSON."""
    compliance = (await api_compliance())
    stats = (await api_stats())
    report = {
        "report_id": str(uuid.uuid4()),
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "stats": stats,
        "compliance": compliance,
        "audit_log": _request_log[:100],
    }
    return Response(
        content=json.dumps(report, indent=2),
        media_type="application/json",
        headers={"Content-Disposition": "attachment; filename=rai-guard-report.json"},
    )


@app.get("/api/report/html")
async def api_report_html() -> HTMLResponse:
    """Download / view the compliance report as HTML."""
    compliance = (await api_compliance())
    stats = (await api_stats())

    owasp_rows = ""
    for c in compliance["owasp"]["categories"]:
        s = "badge-green" if c["compliant"] else "badge-red"
        lbl = "Compliant" if c["compliant"] else "Review needed"
        owasp_rows += (
            f"<tr><td>{c['id']}</td><td>{c['name']}</td>"
            f"<td>{c['risk_score']:.2f}</td>"
            f"<td><span class='{s}'>{lbl}</span></td></tr>"
        )

    eu_rows = ""
    for a in compliance["eu_ai_act"]["articles"]:
        risk = a["risk_level"]
        rc = "badge-red" if risk == "high" else ("badge-amber" if risk == "medium" else "badge-green")
        sc = "badge-green" if a["compliant"] else "badge-red"
        mark = "✓" if a["compliant"] else "✗"
        eu_rows += (
            f"<tr><td>{a['article']}</td><td>{a['title']}</td>"
            f"<td>{a['compliance_score']:.0%}</td>"
            f"<td><span class='{rc}'>{risk.title()}</span></td>"
            f"<td><span class='{sc}'>{mark}</span></td></tr>"
        )

    nist_rows = ""
    for n in compliance["nist"]["functions"]:
        nist_rows += (
            f"<tr><td><strong>{n['function']}</strong></td><td>{n['description']}</td>"
            f"<td><span class='badge-green'>{n['maturity']}</span></td></tr>"
        )

    incidents = "".join(
        f"<tr><td style='font-size:.8rem;color:#6b7280'>{r['timestamp'][:19]}</td>"
        f"<td style='max-width:300px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap'>{r['prompt']}</td>"
        f"<td><span class='badge badge-red'>Blocked</span></td>"
        f"<td>{', '.join(r['blocked_by'])}</td>"
        f"<td>{r['risk_score']:.2f}</td></tr>"
        for r in _request_log if not r["passed"]
    )[:5000]  # cap HTML size

    incidents_section = (
        f"<div class='section'><h2>Recent Incidents</h2>"
        f"<table><thead><tr><th>Time</th><th>Prompt</th><th>Status</th><th>Blocked by</th><th>Risk</th></tr></thead>"
        f"<tbody>{incidents or '<tr><td colspan=5 style=text-align:center>No incidents</td></tr>'}</tbody></table></div>"
    )

    def _grade(pct: float) -> str:
        if pct >= 90: return "A"
        if pct >= 80: return "B"
        if pct >= 70: return "C"
        if pct >= 60: return "D"
        return "F"

    owasp_pct = compliance["owasp"]["score"]
    eu_pct = compliance["eu_ai_act"]["score"]

    import uuid as _uuid
    html = _HTML_TEMPLATE.format(
        generated_at=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        total_requests=stats["total_requests"],
        report_id=str(_uuid.uuid4())[:8].upper(),
        owasp_score=owasp_pct,
        owasp_grade=_grade(owasp_pct),
        eu_score=eu_pct,
        eu_grade=_grade(eu_pct),
        blocked=stats["blocked_requests"],
        pass_rate=stats["pass_rate"],
        owasp_rows=owasp_rows,
        eu_rows=eu_rows,
        nist_rows=nist_rows,
        recent_incidents_section=incidents_section,
    )
    return HTMLResponse(
        content=html,
        headers={"Content-Disposition": "attachment; filename=rai-guard-report.html"},
    )


# ── Hub API ───────────────────────────────────────────────────────────────────

@app.get("/api/hub")
async def api_hub(
    risk_category: str | None = Query(None),
    use_case: str | None = Query(None),
    infra: str | None = Query(None),
    available_only: bool = Query(False),
    q: str | None = Query(None),
) -> dict:
    """Return the validator registry, optionally filtered."""
    from raiguard.hub import search
    validators = search(
        risk_category=risk_category,
        use_case=use_case,
        infra=infra,
        available_only=available_only,
        query=q,
    )
    return {
        "total": len(validators),
        "validators": [v.to_dict() for v in validators],
    }


@app.get("/api/hub/{validator_id:path}")
async def api_hub_detail(validator_id: str) -> dict:
    """Return metadata for a single validator."""
    from raiguard.hub import get
    meta = get(validator_id)
    if meta is None:
        from fastapi import HTTPException
        raise HTTPException(status_code=404, detail=f"Validator '{validator_id}' not found")
    return meta.to_dict()


@app.post("/api/hub/generate")
async def api_hub_generate(body: dict) -> dict:
    """Generate Guard code for a list of validator IDs.

    Body: {"validator_ids": ["raiguard/prompt_injection", ...], "on_fail": "BLOCK", "guard_name": "my_guard"}
    """
    from raiguard.hub import get
    validator_ids: list[str] = body.get("validator_ids", [])
    on_fail: str = body.get("on_fail", "BLOCK").upper()
    guard_name: str = body.get("guard_name", "guard")

    imports = ["from raiguard import Guard, OnFailAction"]
    hub_imports = []
    uses = []
    unknown = []

    for vid in validator_ids:
        meta = get(vid)
        if meta is None:
            unknown.append(vid)
            continue
        cls_name = meta.check_class.__name__ if meta.check_class else meta.name.replace(" ", "")
        if cls_name not in hub_imports:
            hub_imports.append(cls_name)
        uses.append(f"    .use({cls_name}, on_fail=OnFailAction.{on_fail})")

    if hub_imports:
        imports.append(f"from raiguard.hub import {', '.join(hub_imports)}")

    lines = imports + ["", f"{guard_name} = (", "    Guard()"] + uses + [")", ""]
    lines += [
        f"result = {guard_name}.validate(user_prompt)",
        "if not result.passed:",
        '    print("Blocked:", result.violations)',
    ]

    return {
        "code": "\n".join(lines),
        "unknown_validators": unknown,
    }


@app.post("/api/hub/validate")
async def api_hub_validate(body: dict) -> dict:
    """Run a live Guard validation against text using selected validators.

    Body:
        text: str              — the text to validate
        validator_ids: list    — e.g. ["raiguard/prompt_injection", "raiguard/pii_detector"]
        on_fail: str           — OnFailAction name (default: "BLOCK")
        direction: str         — "input" or "output" (default: "input")
    """
    from raiguard import Guard, OnFailAction, GuardValidationError
    from raiguard.hub import get as hub_get

    text: str = body.get("text", "")
    validator_ids: list[str] = body.get("validator_ids", [])
    on_fail_str: str = body.get("on_fail", "BLOCK").upper()
    direction: str = body.get("direction", "input")

    if not text:
        return {"error": "text is required"}
    if not validator_ids:
        return {"error": "at least one validator_id is required"}

    try:
        on_fail = OnFailAction(on_fail_str.lower())
    except ValueError:
        on_fail = OnFailAction.BLOCK

    guard = Guard(name="hub-live-test")
    skipped: list[str] = []

    for vid in validator_ids:
        meta = hub_get(vid)
        if meta is None:
            skipped.append(f"{vid} (not found)")
            continue
        if meta.check_class is None:
            skipped.append(f"{vid} (requires {meta.requires_extra or 'extra deps'})")
            continue
        try:
            guard.use(meta.check_class, on_fail=on_fail)
        except Exception as exc:
            skipped.append(f"{vid} ({exc})")

    try:
        result = guard.validate(text, direction=direction)
    except GuardValidationError as exc:
        # EXCEPTION action raises — convert to a blocked result dict
        return {
            "passed": False,
            "original_value": text,
            "fixed_value": text,
            "risk_score": max((v.score for v in exc.violations), default=1.0),
            "needs_reask": False,
            "violations": [
                {
                    "validator": v.validator_name,
                    "message": v.message,
                    "score": v.score,
                    "severity": v.severity.value,
                    "on_fail": v.on_fail.value,
                }
                for v in exc.violations
            ],
            "skipped_validators": skipped,
            "exception_raised": True,
        }

    out = result.to_dict()
    out["skipped_validators"] = skipped
    out["exception_raised"] = False
    return out
