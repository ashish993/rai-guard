"""
ASGI middleware for FastAPI / Starlette apps.

Usage:
    from fastapi import FastAPI
    from raiguard.middleware import AIGuardMiddleware

    app = FastAPI()
    app.add_middleware(AIGuardMiddleware, block_on_fail=True)
"""

from __future__ import annotations

import json
import os
import uuid
from typing import Any

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.types import ASGIApp

from raiguard.instrument import AIGuard
from raiguard.conversation import ConversationBuffer, get_default_buffer

# Maximum request body to buffer in memory (default 1 MB)
MAX_BODY_BYTES = int(os.getenv("RAI_MAX_BODY_BYTES", str(1 * 1024 * 1024)))


class AIGuardMiddleware(BaseHTTPMiddleware):
    """
    Starlette/FastAPI middleware that inspects request bodies for AI prompts
    and response bodies for policy violations.

    Intercepts JSON bodies with a 'prompt', 'content', or 'messages' key.

    Multi-turn context
    ------------------
    Each request is associated with a *session ID* resolved from (in order):
      1. ``X-Session-ID`` request header
      2. ``session_id`` JSON body field
      3. A new UUID (first turn; returned in the 400 response as ``session_id``)

    Prior turns are stored in a ``ConversationBuffer`` and passed to all
    context-aware checks (LLMIntentCheck, etc.) on each new request.

    Parameters
    ----------
    conversation_buffer:
        Provide a custom ``ConversationBuffer`` (e.g. backed by Redis).
        Defaults to the module-level singleton from ``raiguard.conversation``.
    track_assistant_responses:
        When True (default) the middleware records assistant responses in the
        buffer so checks see the full alternating user/assistant history.
    """

    def __init__(
        self,
        app: ASGIApp,
        checks: list[str] | None = None,
        block_on_fail: bool = True,
        score_threshold: float = 0.7,
        store: Any | None = None,
        inspect_fields: list[str] | None = None,
        conversation_buffer: ConversationBuffer | None = None,
        track_assistant_responses: bool = True,
        exclude_paths: list[str] | None = None,
    ) -> None:
        super().__init__(app)
        self.guard = AIGuard(
            checks=checks,
            block_on_fail=block_on_fail,
            score_threshold=score_threshold,
            store=store,
        )
        self.inspect_fields = inspect_fields or ["prompt", "content", "text", "input", "query"]
        self._buffer: ConversationBuffer = conversation_buffer or get_default_buffer()
        self._track_assistant = track_assistant_responses
        self._exclude_paths: set[str] = set(exclude_paths or [])

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        # Skip inspection for excluded paths
        if request.url.path in self._exclude_paths:
            return await call_next(request)

        # Only inspect POST/PUT with JSON body
        if request.method in ("POST", "PUT") and "application/json" in request.headers.get("content-type", ""):
            try:
                content_length = request.headers.get("content-length")
                if content_length and int(content_length) > MAX_BODY_BYTES:
                    return JSONResponse(status_code=413, content={"error": "Request body too large"})

                body_bytes = await request.body()

                if len(body_bytes) > MAX_BODY_BYTES:
                    return JSONResponse(status_code=413, content={"error": "Request body too large"})

                body = json.loads(body_bytes)
            except (json.JSONDecodeError, UnicodeDecodeError):
                body = {}

            prompt_text = self._extract_text(body)

            if prompt_text:
                # Resolve session ID: header > body field > new UUID
                session_id = (
                    request.headers.get("x-session-id")
                    or (body.get("session_id") if isinstance(body, dict) else None)
                    or str(uuid.uuid4())
                )

                # Retrieve prior turns from the buffer
                history = self._buffer.get_history(session_id)

                # Record the current user turn before running checks so that
                # the LLM classifier sees it as part of the history window too.
                self._buffer.add_turn(session_id, role="user", content=prompt_text)

                result = await self.guard.check_input(
                    prompt_text, session_id=session_id, history=history
                )
                if not result.allowed:
                    return JSONResponse(
                        status_code=400,
                        content={
                            "error": "RAI policy violation",
                            "blocked_by": result.blocked_by,
                            "risk_score": result.risk_score,
                            "session_id": result.session_id,
                            "remediation": self._remediation(result),
                        },
                    )

                # Stash session_id on request state so the route handler can
                # echo it back in the response if desired.
                request.state.rai_session_id = session_id

        response = await call_next(request)

        # Optionally inspect JSON response bodies
        if response.headers.get("content-type", "").startswith("application/json"):
            try:
                body_bytes = b""
                oversized = False
                async for chunk in response.body_iterator:
                    body_bytes += chunk
                    if len(body_bytes) > MAX_BODY_BYTES:
                        oversized = True
                        break  # stop accumulating — remaining chunks are discarded
                if oversized:
                    # Response too large to inspect safely — pass through untouched
                    return Response(
                        content=body_bytes,
                        status_code=response.status_code,
                        headers=dict(response.headers),
                        media_type="application/json",
                    )
                resp_body = json.loads(body_bytes)
                resp_text = self._extract_text(resp_body)

                if resp_text:
                    # Retrieve session state stored earlier in this request cycle
                    session_id: str | None = getattr(getattr(request, "state", None), "rai_session_id", None)
                    history = self._buffer.get_history(session_id) if session_id else []

                    out_result = await self.guard.check_output(
                        resp_text, session_id=session_id, history=history
                    )
                    if not out_result.allowed:
                        return JSONResponse(
                            status_code=500,
                            content={
                                "error": "RAI output policy violation",
                                "blocked_by": out_result.blocked_by,
                                "risk_score": out_result.risk_score,
                            },
                        )

                    # Record assistant response in conversation buffer
                    if self._track_assistant and session_id:
                        self._buffer.add_turn(session_id, role="assistant", content=resp_text)

                # Re-stream the body
                return Response(
                    content=body_bytes,
                    status_code=response.status_code,
                    headers=dict(response.headers),
                    media_type="application/json",
                )
            except Exception:
                pass  # If we can't parse the response, pass through

        return response

    def _extract_text(self, body: Any) -> str | None:
        if not isinstance(body, dict):
            return None

        # OpenAI-style messages array
        if "messages" in body and isinstance(body["messages"], list):
            parts = []
            for msg in body["messages"]:
                if isinstance(msg, dict) and "content" in msg:
                    parts.append(str(msg["content"]))
            return " ".join(parts) if parts else None

        # Flat field inspection
        for field in self.inspect_fields:
            if field in body and isinstance(body[field], str):
                return body[field]

        return None

    def _remediation(self, result: Any) -> list[str]:
        remediations = []
        for r in result.check_results:
            if not r.passed and r.remediation:
                remediations.append(r.remediation)
        return remediations
