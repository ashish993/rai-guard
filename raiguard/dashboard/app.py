"""
rai-guard Web Dashboard — FastAPI app serving live risk metrics.

Start with: raiguard dashboard  or  uvicorn raiguard.dashboard.app:app

Authentication:
    Set RAI_DASHBOARD_USER and RAI_DASHBOARD_PASSWORD env vars to enable
    HTTP Basic Auth (strongly recommended when exposed beyond localhost).
    If neither is set, the dashboard is open (suitable for local dev only).
"""

from __future__ import annotations

import logging
import os
import secrets
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Annotated, Any

from fastapi import Depends, FastAPI, HTTPException, Request, status
from fastapi.responses import HTMLResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from fastapi.templating import Jinja2Templates

from raiguard.evidence.store import EvidenceStore
from raiguard.compliance.owasp_llm import map_to_owasp, owasp_compliance_score
from raiguard.compliance.eu_ai_act import map_to_eu_ai_act, eu_ai_act_overall_score

logger = logging.getLogger("raiguard.dashboard")

_DB_PATH = os.getenv("RAI_DB_PATH", "raiguard_audit.db")
_TEMPLATES_DIR = Path(__file__).parent / "templates"

_DASH_USER = os.getenv("RAI_DASHBOARD_USER", "")
_DASH_PASS = os.getenv("RAI_DASHBOARD_PASSWORD", "")
_AUTH_ENABLED = bool(_DASH_USER and _DASH_PASS)

_security = HTTPBasic(auto_error=False)

# ── Persistent store connection ───────────────────────────────────────────────

_store: EvidenceStore | None = None


@asynccontextmanager
async def lifespan(app: FastAPI):  # type: ignore[type-arg]
    global _store
    _store = EvidenceStore(_DB_PATH)
    try:
        await _store.connect()
        logger.info("Dashboard connected to evidence store: %s", _DB_PATH)
    except Exception:
        logger.warning("Evidence store unavailable at startup; will retry per-request")
        _store = None
    yield
    if _store:
        await _store.close()


# ── App ───────────────────────────────────────────────────────────────────────

app = FastAPI(title="rai-guard Dashboard", version="0.1.0", lifespan=lifespan)
templates = Jinja2Templates(directory=str(_TEMPLATES_DIR))


@app.middleware("http")
async def _security_headers(request: Request, call_next: Any) -> Any:
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    return response


if not _AUTH_ENABLED:
    logger.warning(
        "Dashboard auth is DISABLED. Set RAI_DASHBOARD_USER and "
        "RAI_DASHBOARD_PASSWORD to protect sensitive audit data."
    )


# ── Auth dependency ───────────────────────────────────────────────────────────

def _require_auth(credentials: Annotated[HTTPBasicCredentials | None, Depends(_security)]) -> None:
    if not _AUTH_ENABLED:
        return
    if credentials is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
            headers={"WWW-Authenticate": "Basic"},
        )
    user_ok = secrets.compare_digest(credentials.username.encode(), _DASH_USER.encode())
    pass_ok = secrets.compare_digest(credentials.password.encode(), _DASH_PASS.encode())
    if not (user_ok and pass_ok):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
            headers={"WWW-Authenticate": "Basic"},
        )


AuthDep = Annotated[None, Depends(_require_auth)]


# ── Helper: get store (falls back to per-request connection if needed) ────────

async def _get_store() -> EvidenceStore | None:
    if _store and _store._db:
        return _store
    # Fallback: open a short-lived connection
    try:
        s = EvidenceStore(_DB_PATH)
        await s.connect()
        return s
    except Exception as exc:
        logger.warning("Could not open evidence store: %s", exc)
        return None


# ── Routes ────────────────────────────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
async def index(request: Request, _auth: AuthDep) -> HTMLResponse:
    stats = {"total_requests": 0, "blocked_requests": 0, "pass_rate": 100.0, "average_risk_score": 0.0}
    recent: list[dict] = []
    store = await _get_store()

    if store:
        try:
            stats = await store.stats()
            recent = await store.query(limit=20, failed_only=False)
        except Exception as exc:
            logger.warning("Error reading evidence store: %s", exc)
        finally:
            # Close only if this was a fallback connection (not the persistent one)
            if store is not _store:
                await store.close()

    owasp_score = owasp_compliance_score([])
    eu_score = eu_ai_act_overall_score([])

    return templates.TemplateResponse(
        "index.html",
        {
            "request": request,
            "stats": stats,
            "recent": recent,
            "owasp_score": owasp_score,
            "eu_score": eu_score,
        },
    )


@app.get("/api/stats")
async def api_stats(_auth: AuthDep) -> dict:
    """JSON endpoint for live stats (for polling dashboards)."""
    store = await _get_store()
    if not store:
        return {"total_requests": 0, "blocked_requests": 0, "pass_rate": 100.0, "average_risk_score": 0.0}
    try:
        result = await store.stats()
        return result
    except Exception as exc:
        logger.warning("Error reading stats: %s", exc)
        return {"total_requests": 0, "blocked_requests": 0, "pass_rate": 100.0, "average_risk_score": 0.0}
    finally:
        if store is not _store:
            await store.close()


@app.get("/api/recent")
async def api_recent(_auth: AuthDep, limit: int = 50, failed_only: bool = False) -> list:
    limit = max(1, min(limit, 200))  # clamp to prevent full-table dumps
    store = await _get_store()
    if not store:
        return []
    try:
        return await store.query(limit=limit, failed_only=failed_only)
    except Exception as exc:
        logger.warning("Error reading recent events: %s", exc)
        return []
    finally:
        if store is not _store:
            await store.close()
