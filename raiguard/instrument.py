"""
Instrumentation layer — AIGuard class and instrument() helper.

Usage:
    from raiguard import AIGuard

    guard = AIGuard()

    @guard.protect
    async def call_llm(prompt: str) -> str:
        return openai_client.chat.completions.create(...)

    # Or with explicit session ID:
    result = await guard.check_input(prompt, session_id="user-123")
"""

from __future__ import annotations

import asyncio
import atexit
import concurrent.futures
import functools
import logging
import os
import uuid
from dataclasses import dataclass, field
from typing import Any, Callable

logger = logging.getLogger("raiguard.instrument")

# Bounded thread pool for concurrent synchronous checks.
# Override worker count via RAI_EXECUTOR_WORKERS env var.
_executor = concurrent.futures.ThreadPoolExecutor(
    max_workers=int(os.getenv("RAI_EXECUTOR_WORKERS", "8")),
    thread_name_prefix="raiguard-check",
)
atexit.register(_executor.shutdown, wait=True)

from raiguard.checks.base import CheckResult, Severity
from raiguard.checks.prompt_injection import PromptInjectionCheck
from raiguard.checks.pii import PIICheck
from raiguard.checks.toxicity import ToxicityCheck
from raiguard.checks.hallucination import HallucinationCheck
from raiguard.checks.insecure_output import InsecureOutputCheck


@dataclass
class GuardResult:
    """Result of a guard evaluation."""
    allowed: bool
    session_id: str
    check_results: list[CheckResult] = field(default_factory=list)
    risk_score: float = 0.0
    blocked_by: list[str] = field(default_factory=list)

    @property
    def highest_severity(self) -> Severity:
        if not self.check_results:
            return Severity.LOW
        return max(
            (r.severity for r in self.check_results if not r.passed),
            default=Severity.LOW,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "allowed": self.allowed,
            "session_id": self.session_id,
            "risk_score": self.risk_score,
            "blocked_by": self.blocked_by,
            "highest_severity": self.highest_severity.value,
            "checks": [
                {
                    "name": r.check_name,
                    "passed": r.passed,
                    "score": r.score,
                    "severity": r.severity.value,
                    "details": r.details,
                    "owasp": r.owasp_refs,
                }
                for r in self.check_results
            ],
        }


class GuardViolation(Exception):
    """Raised when a guarded call is blocked due to a policy violation."""
    def __init__(self, result: GuardResult) -> None:
        self.result = result
        blocked = ", ".join(result.blocked_by)
        super().__init__(f"AI Guard blocked request: {blocked} (risk={result.risk_score:.3f})")


class AIGuard:
    """
    Runtime AI compliance guard.

    Parameters
    ----------
    checks:
        List of check names to enable. Defaults to all.
        Options: 'prompt_injection', 'pii', 'toxicity', 'hallucination', 'insecure_output'
    block_on_fail:
        If True, raise GuardViolation when any check fails. If False, log only.
    score_threshold:
        Risk score (0–1) above which a request is blocked regardless of check pass/fail.
    store:
        Optional EvidenceStore instance for audit logging.
    """

    _ALL_CHECKS = ["prompt_injection", "pii", "toxicity", "hallucination", "insecure_output"]

    def __init__(
        self,
        checks: list[str] | None = None,
        block_on_fail: bool = True,
        score_threshold: float = 0.7,
        store: Any | None = None,
    ) -> None:
        self.block_on_fail = block_on_fail
        self.score_threshold = score_threshold
        self.store = store
        enabled = set(checks or self._ALL_CHECKS)

        self._input_checks = []
        self._output_checks = []

        if "prompt_injection" in enabled:
            self._input_checks.append(PromptInjectionCheck())
        if "pii" in enabled:
            # Separate instances — input vs output checks must not share state
            self._input_checks.append(PIICheck())
            self._output_checks.append(PIICheck())
        if "toxicity" in enabled:
            self._input_checks.append(ToxicityCheck())
            self._output_checks.append(ToxicityCheck())
        if "hallucination" in enabled:
            self._output_checks.append(HallucinationCheck())
        if "insecure_output" in enabled:
            self._output_checks.append(InsecureOutputCheck())

    async def check_input(self, text: str, session_id: str | None = None) -> GuardResult:
        """Run all input checks against a prompt (concurrent, thread-pool)."""
        session_id = session_id or str(uuid.uuid4())
        loop = asyncio.get_running_loop()
        raw = await asyncio.gather(
            *[loop.run_in_executor(_executor, c.check_input, text) for c in self._input_checks],
            return_exceptions=True,
        )
        results = []
        for i, r in enumerate(raw):
            if isinstance(r, BaseException):
                logger.error(
                    "Check %s raised during input inspection: %s",
                    self._input_checks[i].name, r, exc_info=r,
                )
            else:
                results.append(r)
        return self._evaluate(results, session_id, direction="input")

    async def check_output(self, text: str, session_id: str | None = None) -> GuardResult:
        """Run all output checks against an LLM response (concurrent, thread-pool)."""
        session_id = session_id or str(uuid.uuid4())
        loop = asyncio.get_running_loop()
        raw = await asyncio.gather(
            *[loop.run_in_executor(_executor, c.check_output, text) for c in self._output_checks],
            return_exceptions=True,
        )
        results = []
        for i, r in enumerate(raw):
            if isinstance(r, BaseException):
                logger.error(
                    "Check %s raised during output inspection: %s",
                    self._output_checks[i].name, r, exc_info=r,
                )
            else:
                results.append(r)
        return self._evaluate(results, session_id, direction="output")

    def _evaluate(self, results: list[CheckResult], session_id: str, direction: str) -> GuardResult:
        risk_score = max((r.score for r in results), default=0.0)
        failed = [r for r in results if not r.passed]
        blocked_by = [r.check_name for r in failed]

        if risk_score >= self.score_threshold and not blocked_by:
            blocked_by = [r.check_name for r in sorted(results, key=lambda x: x.score, reverse=True)[:1]]

        allowed = (len(blocked_by) == 0) or (not self.block_on_fail)

        if self.store and asyncio.iscoroutinefunction(self.store.record):
            # Fire-and-forget async record — log exceptions instead of silently dropping
            def _on_record_done(t: "asyncio.Task[Any]") -> None:
                if t.cancelled():
                    return
                exc = t.exception()
                if exc:
                    logger.warning("Evidence store record failed: %s", exc)

            try:
                loop = asyncio.get_running_loop()
                task = loop.create_task(
                    self.store.record(results, direction=direction, session_id=session_id)
                )
                task.add_done_callback(_on_record_done)
            except RuntimeError:
                pass  # Not in async context, skip

        return GuardResult(
            allowed=allowed,
            session_id=session_id,
            check_results=results,
            risk_score=risk_score,
            blocked_by=blocked_by,
        )

    def protect(self, func: Callable) -> Callable:
        """
        Decorator that guards the first string argument of an async function.

        The decorated function should accept `prompt: str` as its first positional
        argument and return a `str` response.

        Raises GuardViolation if input or output fails checks (when block_on_fail=True).
        """
        @functools.wraps(func)
        async def wrapper(*args: Any, **kwargs: Any) -> Any:
            # Extract first string arg as the prompt
            session_id = kwargs.pop("_guard_session_id", None) or str(uuid.uuid4())
            prompt = args[0] if args else kwargs.get("prompt", "")

            input_result = await self.check_input(str(prompt), session_id=session_id)
            if not input_result.allowed:
                raise GuardViolation(input_result)

            response = await func(*args, **kwargs)

            if isinstance(response, str):
                output_result = await self.check_output(response, session_id=session_id)
                if not output_result.allowed:
                    raise GuardViolation(output_result)

            return response

        return wrapper


PROVIDER_DEFAULTS: dict[str, dict[str, Any]] = {
    "openai": {
        "base_url": "https://api.openai.com/v1",
        "default_model": "gpt-4o",
    },
    "anthropic": {
        "base_url": "https://api.anthropic.com",
        "default_model": "claude-3-5-sonnet-20241022",
    },
    "ollama": {
        "base_url": "http://localhost:11434/v1",
        "default_model": "llama3.2",
        # Ollama responses may contain code blocks → enable insecure output check prominently
        "recommended_checks": ["prompt_injection", "pii", "toxicity", "hallucination", "insecure_output"],
    },
    "lm_studio": {
        "base_url": "http://localhost:1234/v1",
        "default_model": "local-model",
    },
    "custom": {},
}


def instrument(
    provider: str = "openai",
    checks: list[str] | None = None,
    block_on_fail: bool = True,
    store: Any | None = None,
) -> AIGuard:
    """
    Create and return a pre-configured AIGuard instance.

    Parameters
    ----------
    provider:
        LLM provider name. One of: 'openai', 'anthropic', 'ollama', 'lm_studio', 'custom'.
        Ollama and LM Studio point at localhost by default.
    checks:
        Subset of checks to enable. Defaults to all (or provider-recommended set).
    block_on_fail:
        Raise GuardViolation on failure.
    store:
        EvidenceStore for audit logging.

    Returns the configured AIGuard instance along with provider metadata as
    ``guard.provider_info`` (base_url, default_model).
    """
    defaults = PROVIDER_DEFAULTS.get(provider, {})
    effective_checks = checks or defaults.get("recommended_checks", None)

    guard = AIGuard(checks=effective_checks, block_on_fail=block_on_fail, store=store)
    guard.provider_info = {  # type: ignore[attr-defined]
        "provider": provider,
        "base_url": defaults.get("base_url", ""),
        "default_model": defaults.get("default_model", ""),
    }
    return guard
