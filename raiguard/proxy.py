"""
OpenAI-compatible proxy server.

Runs as a drop-in replacement for the OpenAI API endpoint.
Set OPENAI_API_BASE=http://localhost:8000/v1 in your app — no code changes needed.

Start with:  raiguard serve  or  uvicorn raiguard.proxy:app

Security notes:
- RAI_UPSTREAM_URL is validated at startup against SSRF-prone destinations.
- Streaming responses (stream=true) are NOT inspected for output violations;
  callers should use the Python SDK integration instead for full coverage.
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import logging
import os
import uuid
from contextlib import asynccontextmanager
from typing import Any, Literal
from urllib.parse import urlparse

import httpx
from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from raiguard.instrument import AIGuard, GuardViolation  # noqa: F401

logger = logging.getLogger("raiguard.proxy")

# ── Configuration ────────────────────────────────────────────────────────────

UPSTREAM_BASE = os.getenv("RAI_UPSTREAM_URL", "https://api.openai.com").rstrip("/")
BLOCK_ON_FAIL = os.getenv("RAI_BLOCK_ON_FAIL", "true").lower() == "true"
SCORE_THRESHOLD = float(os.getenv("RAI_SCORE_THRESHOLD", "0.7"))
# Maximum request body we will read into memory (default 1 MB)
MAX_BODY_BYTES = int(os.getenv("RAI_MAX_BODY_BYTES", str(1 * 1024 * 1024)))

# ── SSRF guard ────────────────────────────────────────────────────────────────

_SSRF_ALLOW_PRIVATE = os.getenv("RAI_ALLOW_PRIVATE_UPSTREAM", "false").lower() == "true"

_PRIVATE_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),  # link-local / cloud metadata
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
]


async def _validate_upstream(url: str) -> None:
    """Raise ValueError if the upstream URL looks SSRF-prone."""
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise ValueError(f"RAI_UPSTREAM_URL must use http/https scheme, got: {parsed.scheme!r}")
    if not parsed.hostname:
        raise ValueError("RAI_UPSTREAM_URL has no hostname")

    # Allow well-known LLM providers by hostname without DNS resolution
    _SAFE_HOSTNAMES = {
        "api.openai.com",
        "api.anthropic.com",
        "generativelanguage.googleapis.com",
    }
    if parsed.hostname in _SAFE_HOSTNAMES:
        return

    if _SSRF_ALLOW_PRIVATE:
        logger.warning("RAI_ALLOW_PRIVATE_UPSTREAM=true — SSRF protection relaxed")
        return

    # Resolve and check every IP the hostname maps to (non-blocking async DNS)
    try:
        loop = asyncio.get_running_loop()
        infos = await loop.getaddrinfo(parsed.hostname, None)
    except OSError:
        raise ValueError(f"Cannot resolve upstream hostname: {parsed.hostname!r}")

    for info in infos:
        addr_str = info[4][0]
        try:
            addr = ipaddress.ip_address(addr_str)
        except ValueError:
            continue
        for net in _PRIVATE_NETWORKS:
            if addr in net:
                raise ValueError(
                    f"RAI_UPSTREAM_URL resolves to a private/link-local address ({addr_str}). "
                    "Set RAI_ALLOW_PRIVATE_UPSTREAM=true to allow (e.g. local Ollama)."
                )


# ── Shared HTTP client ────────────────────────────────────────────────────────

_http_client: httpx.AsyncClient | None = None
_guard: AIGuard | None = None


@asynccontextmanager
async def lifespan(app: FastAPI):  # type: ignore[type-arg]
    global _http_client, _guard
    # Validate upstream URL at startup — fail fast before accepting traffic
    try:
        await _validate_upstream(UPSTREAM_BASE)
    except ValueError as exc:
        logger.error("Upstream URL validation failed: %s", exc)
        raise

    _http_client = httpx.AsyncClient(
        timeout=httpx.Timeout(connect=5.0, read=90.0, write=10.0, pool=5.0),
        limits=httpx.Limits(max_connections=100, max_keepalive_connections=20),
    )
    _guard = AIGuard(block_on_fail=BLOCK_ON_FAIL, score_threshold=SCORE_THRESHOLD)
    logger.info("rai-guard proxy started. Upstream: %s", UPSTREAM_BASE)
    yield
    await _http_client.aclose()
    logger.info("rai-guard proxy shut down cleanly")


# ── App ───────────────────────────────────────────────────────────────────────

app = FastAPI(
    title="rai-guard Proxy",
    description="OpenAI-compatible proxy with Responsible AI compliance enforcement",
    version="0.1.0",
    lifespan=lifespan,
)

# ── Security + correlation headers ──────────────────────────────────────────

@app.middleware("http")
async def _security_and_correlation(request: Request, call_next: Any) -> Any:
    req_id = request.headers.get("X-Request-ID") or str(uuid.uuid4())
    response = await call_next(request)
    response.headers["X-Request-ID"] = req_id
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    return response


# ── Models ────────────────────────────────────────────────────────────────────

class ChatMessage(BaseModel):
    role: Literal["user", "system", "assistant", "tool", "function"]
    content: str


class ChatCompletionRequest(BaseModel):
    model: str
    messages: list[ChatMessage]
    temperature: float | None = None
    max_tokens: int | None = None
    stream: bool = False
    model_config = {"extra": "allow"}


# ── Routes ────────────────────────────────────────────────────────────────────

@app.get("/health")
async def health() -> dict[str, str]:
    ready = _http_client is not None and _guard is not None
    return {
        "status": "ok" if ready else "starting",
        "service": "rai-guard-proxy",
        "upstream": UPSTREAM_BASE,
    }


@app.post("/v1/chat/completions")
async def chat_completions(
    body: ChatCompletionRequest,
    request: Request,
    authorization: str = Header(default=""),
) -> Any:
    if _http_client is None or _guard is None:
        raise HTTPException(status_code=503, detail="Service initializing, try again shortly")

    if body.stream:
        # Streaming responses cannot be fully buffered for output inspection.
        # Log a warning and pass through — use the Python SDK integration for
        # full coverage of streamed output.
        logger.warning(
            "Streaming request received (session_id unknown). "
            "Output compliance checks are skipped for streaming responses."
        )

    # 1. Inspect all user/system messages
    combined_prompt = " ".join(
        msg.content for msg in body.messages if msg.role in ("user", "system")
    )

    input_result = await _guard.check_input(combined_prompt)
    logger.info(
        "input_check session=%s allowed=%s risk=%.3f blocked=%s",
        input_result.session_id, input_result.allowed,
        input_result.risk_score, input_result.blocked_by,
    )
    if not input_result.allowed:
        raise HTTPException(
            status_code=400,
            detail={
                "error": {
                    "message": "Request blocked by rai-guard policy",
                    "type": "rai_policy_violation",
                    "blocked_by": input_result.blocked_by,
                    "risk_score": input_result.risk_score,
                    "session_id": input_result.session_id,
                },
            },
        )

    # 2. Forward to upstream
    upstream_url = f"{UPSTREAM_BASE}/v1/chat/completions"
    headers = {"Content-Type": "application/json"}
    if authorization:
        headers["Authorization"] = authorization

    payload = body.model_dump(exclude_none=True)
    _known_fields = {"model", "messages", "temperature", "max_tokens", "stream"}
    extra_fields = set(payload) - _known_fields
    if extra_fields:
        _tool_fields = extra_fields & {"tools", "function_call", "functions"}
        _other_extra = extra_fields - _tool_fields
        if _tool_fields:
            logger.warning(
                "session=%s: request includes tools/functions — verify these are operator-defined",
                input_result.session_id,
            )
        if _other_extra:
            logger.info(
                "session=%s: forwarding extra fields to upstream: %s",
                input_result.session_id, sorted(_other_extra),
            )

    upstream_resp = await _http_client.post(upstream_url, json=payload, headers=headers)

    if upstream_resp.status_code != 200:
        logger.warning("Upstream returned %d for session %s", upstream_resp.status_code, input_result.session_id)
        # Return only the status code; do not echo upstream error body which may
        # contain fragments of the original request or internal provider details.
        return JSONResponse(
            status_code=upstream_resp.status_code,
            content={"error": {"message": "Upstream request failed", "code": upstream_resp.status_code}},
        )

    upstream_body: dict[str, Any] = upstream_resp.json()

    # 3. Inspect response (skipped for streaming — already warned above)
    if not body.stream:
        response_text = _extract_response_text(upstream_body)
        if response_text:
            output_result = await _guard.check_output(response_text, session_id=input_result.session_id)
            logger.info(
                "output_check session=%s allowed=%s risk=%.3f blocked=%s",
                input_result.session_id, output_result.allowed,
                output_result.risk_score, output_result.blocked_by,
            )
            if not output_result.allowed:
                raise HTTPException(
                    status_code=500,
                    detail={
                        "error": {
                            "message": "LLM response blocked by rai-guard output policy",
                            "type": "rai_output_violation",
                            "blocked_by": output_result.blocked_by,
                            "risk_score": output_result.risk_score,
                        },
                    },
                )
            upstream_body["rai_guard"] = {
                "input_risk_score": input_result.risk_score,
                "output_risk_score": output_result.risk_score,
                "session_id": input_result.session_id,
            }

    return JSONResponse(content=upstream_body)


@app.post("/v1/completions")
async def completions(
    request: Request,
    authorization: str = Header(default=""),
) -> Any:
    if _http_client is None or _guard is None:
        raise HTTPException(status_code=503, detail="Service initializing, try again shortly")

    content_length = request.headers.get("content-length")
    try:
        if content_length and int(content_length) > MAX_BODY_BYTES:
            raise HTTPException(status_code=413, detail="Request body too large")
    except ValueError:
        pass  # Malformed Content-Length header — body size check below is authoritative

    body_bytes = await request.body()
    if len(body_bytes) > MAX_BODY_BYTES:
        raise HTTPException(status_code=413, detail="Request body too large")

    body = json.loads(body_bytes)
    prompt = body.get("prompt", "")

    input_result = await _guard.check_input(str(prompt))
    if not input_result.allowed:
        raise HTTPException(
            status_code=400,
            detail={
                "error": {
                    "message": "Request blocked by rai-guard policy",
                    "type": "rai_policy_violation",
                    "blocked_by": input_result.blocked_by,
                    "risk_score": input_result.risk_score,
                },
            },
        )

    headers = {"Content-Type": "application/json"}
    if authorization:
        headers["Authorization"] = authorization

    upstream_resp = await _http_client.post(
        f"{UPSTREAM_BASE}/v1/completions", json=body, headers=headers,
    )

    if upstream_resp.status_code != 200:
        logger.warning("Upstream /v1/completions returned %d for session %s", upstream_resp.status_code, input_result.session_id)
        return JSONResponse(
            status_code=upstream_resp.status_code,
            content={"error": {"message": "Upstream request failed", "code": upstream_resp.status_code}},
        )

    upstream_body: dict[str, Any] = upstream_resp.json()

    # Inspect output for policy violations (mirrors chat/completions behaviour)
    response_text = _extract_response_text(upstream_body)
    if response_text:
        output_result = await _guard.check_output(response_text, session_id=input_result.session_id)
        if not output_result.allowed:
            raise HTTPException(
                status_code=500,
                detail={
                    "error": {
                        "message": "LLM response blocked by rai-guard output policy",
                        "type": "rai_output_violation",
                        "blocked_by": output_result.blocked_by,
                        "risk_score": output_result.risk_score,
                    },
                },
            )

    return JSONResponse(content=upstream_body)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _extract_response_text(body: dict[str, Any]) -> str | None:
    """Extract first assistant message content from a chat completion response."""
    choices = body.get("choices", [])
    if not choices:
        return None
    first = choices[0]
    if "message" in first:
        return first["message"].get("content")
    if "text" in first:
        return first["text"]
    return None
