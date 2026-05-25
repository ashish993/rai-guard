"""
Guard — composable validator chain API, modelled after GuardrailsAI's Guard.

Usage:
    from raiguard import Guard, OnFailAction
    from raiguard.hub import PromptInjection, PIIDetector, ToxicLanguage

    guard = (
        Guard()
        .use(PromptInjection, on_fail=OnFailAction.EXCEPTION)
        .use(PIIDetector, on_fail=OnFailAction.FIX)
        .use(ToxicLanguage, threshold=0.7, on_fail=OnFailAction.BLOCK)
    )

    result = guard.validate("Hello, my SSN is 123-45-6789")
    print(result.passed, result.fixed_value, result.violations)
"""

from __future__ import annotations

import asyncio
import functools
import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Type

from raiguard.checks.base import BaseCheck, CheckResult, Severity

logger = logging.getLogger("raiguard.guard")


# ── OnFailAction ──────────────────────────────────────────────────────────────

class OnFailAction(str, Enum):
    """What to do when a validator fails."""
    EXCEPTION  = "exception"   # raise GuardValidationError
    BLOCK      = "block"       # return passed=False, no exception
    FIX        = "fix"         # apply validator's fix() method if available
    FILTER     = "filter"      # remove the offending span / return empty
    NOOP       = "noop"        # record failure but still return original value
    REASK      = "reask"       # signal caller to re-prompt the LLM


# ── Exceptions ────────────────────────────────────────────────────────────────

class GuardValidationError(Exception):
    """Raised by Guard.validate() when on_fail=OnFailAction.EXCEPTION."""
    def __init__(self, violations: list["Violation"]) -> None:
        self.violations = violations
        msgs = "; ".join(f"{v.validator_name}: {v.message}" for v in violations)
        super().__init__(f"Validation failed: {msgs}")


# ── Data classes ──────────────────────────────────────────────────────────────

@dataclass
class Violation:
    validator_name: str
    message: str
    score: float
    severity: Severity
    on_fail: OnFailAction
    details: dict[str, Any] = field(default_factory=dict)


@dataclass
class GuardValidationResult:
    """Returned by Guard.validate()."""
    passed: bool
    original_value: str
    fixed_value: str           # equals original_value if no fix applied
    violations: list[Violation] = field(default_factory=list)
    check_results: list[CheckResult] = field(default_factory=list)
    needs_reask: bool = False

    @property
    def risk_score(self) -> float:
        if not self.check_results:
            return 0.0
        return max((r.score for r in self.check_results), default=0.0)

    def to_dict(self) -> dict[str, Any]:
        return {
            "passed": self.passed,
            "original_value": self.original_value,
            "fixed_value": self.fixed_value,
            "risk_score": self.risk_score,
            "needs_reask": self.needs_reask,
            "violations": [
                {
                    "validator": v.validator_name,
                    "message": v.message,
                    "score": v.score,
                    "severity": v.severity.value,
                    "on_fail": v.on_fail.value,
                }
                for v in self.violations
            ],
        }


# ── ValidatorEntry (internal) ─────────────────────────────────────────────────

@dataclass
class _ValidatorEntry:
    check: BaseCheck
    on_fail: OnFailAction
    kwargs: dict[str, Any]


# ── Guard ─────────────────────────────────────────────────────────────────────

class Guard:
    """
    Composable guard that chains multiple validators.

    Example::

        guard = Guard(name="my-guard").use(PromptInjection).use(PIIDetector)
        result = guard.validate(user_prompt)
        if not result.passed:
            raise HTTPException(400, result.violations[0].message)
    """

    def __init__(self, name: str = "default-guard", description: str = "") -> None:
        self.name = name
        self.description = description
        self._validators: list[_ValidatorEntry] = []

    # ── Builder API ───────────────────────────────────────────────────────────

    def use(
        self,
        validator: Type[BaseCheck] | BaseCheck,
        *,
        on_fail: OnFailAction = OnFailAction.BLOCK,
        **kwargs: Any,
    ) -> "Guard":
        """Add a validator to the chain. Returns self for chaining."""
        if isinstance(validator, type):
            instance: BaseCheck = validator(**kwargs)
        else:
            instance = validator
        self._validators.append(_ValidatorEntry(
            check=instance, on_fail=on_fail, kwargs=kwargs
        ))
        return self

    # ── Validate (sync) ───────────────────────────────────────────────────────

    def validate(
        self,
        value: str,
        *,
        direction: str = "input",
        context: dict[str, Any] | None = None,
    ) -> GuardValidationResult:
        """Run all validators synchronously. direction='input' or 'output'."""
        violations: list[Violation] = []
        check_results: list[CheckResult] = []
        current_value = value
        needs_reask = False

        for entry in self._validators:
            try:
                if direction == "output":
                    result = entry.check.check_output(current_value, context=context)
                else:
                    result = entry.check.check_input(current_value, context=context)
            except Exception as exc:
                logger.warning("Validator %s raised: %s", entry.check.name, exc)
                continue

            check_results.append(result)

            if not result.passed:
                v = Violation(
                    validator_name=result.check_name,
                    message=result.remediation or f"{result.check_name} check failed",
                    score=result.score,
                    severity=result.severity,
                    on_fail=entry.on_fail,
                    details=result.details,
                )
                violations.append(v)

                if entry.on_fail == OnFailAction.EXCEPTION:
                    raise GuardValidationError([v])
                elif entry.on_fail == OnFailAction.FIX:
                    fixed = self._try_fix(entry.check, current_value, result)
                    if fixed is not None:
                        current_value = fixed
                elif entry.on_fail == OnFailAction.FILTER:
                    current_value = self._filter(entry.check, current_value, result)
                elif entry.on_fail == OnFailAction.REASK:
                    needs_reask = True
                # BLOCK / NOOP: record but continue

        passed = len([v for v in violations if v.on_fail == OnFailAction.BLOCK]) == 0
        # EXCEPTION violations never reach here (raised above)
        # NOOP violations don't block
        hard_violations = [
            v for v in violations
            if v.on_fail not in (OnFailAction.NOOP, OnFailAction.FIX, OnFailAction.FILTER)
        ]
        passed = len(hard_violations) == 0

        return GuardValidationResult(
            passed=passed,
            original_value=value,
            fixed_value=current_value,
            violations=violations,
            check_results=check_results,
            needs_reask=needs_reask,
        )

    # ── Async validate ────────────────────────────────────────────────────────

    async def avalidate(
        self,
        value: str,
        *,
        direction: str = "input",
        context: dict[str, Any] | None = None,
    ) -> GuardValidationResult:
        """Async version — runs validators concurrently then applies actions."""
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(
            None, functools.partial(self.validate, value, direction=direction, context=context)
        )

    # ── Decorator ─────────────────────────────────────────────────────────────

    def protect(self, func: Callable) -> Callable:
        """
        Decorator that validates the first string argument before calling func.

            @guard.protect
            async def call_llm(prompt: str) -> str: ...
        """
        import inspect

        @functools.wraps(func)
        async def _async_wrapper(*args: Any, **kwargs: Any) -> Any:
            prompt = args[0] if args else next(iter(kwargs.values()), "")
            result = await self.avalidate(str(prompt), direction="input")
            if not result.passed:
                raise GuardValidationError(result.violations)
            return await func(*args, **kwargs)

        @functools.wraps(func)
        def _sync_wrapper(*args: Any, **kwargs: Any) -> Any:
            prompt = args[0] if args else next(iter(kwargs.values()), "")
            result = self.validate(str(prompt), direction="input")
            if not result.passed:
                raise GuardValidationError(result.violations)
            return func(*args, **kwargs)

        if inspect.iscoroutinefunction(func):
            return _async_wrapper
        return _sync_wrapper

    # ── Internals ─────────────────────────────────────────────────────────────

    @staticmethod
    def _try_fix(check: BaseCheck, value: str, result: CheckResult) -> str | None:
        """Call check.fix() if it exists, otherwise return None."""
        fix_fn = getattr(check, "fix", None)
        if callable(fix_fn):
            try:
                return fix_fn(value)
            except Exception as exc:
                logger.debug("fix() failed for %s: %s", check.name, exc)
        return None

    @staticmethod
    def _filter(check: BaseCheck, value: str, result: CheckResult) -> str:
        """Filter/remove offending content from value.

        Prefers check.fix() if available. Falls back to regex-subbing matched_patterns.
        """
        # Prefer check.fix() which has proper knowledge of what to remove
        fix_fn = getattr(check, "fix", None)
        if callable(fix_fn):
            try:
                return fix_fn(value)
            except Exception as exc:
                logger.debug("fix() in FILTER mode failed for %s: %s", check.name, exc)

        # Fallback: regex sub on matched_patterns (only if they look like regex)
        cleaned = value
        for pattern in result.matched_patterns:
            import re
            try:
                cleaned = re.sub(pattern, "[FILTERED]", cleaned)
            except re.error:
                cleaned = cleaned.replace(pattern, "[FILTERED]")
        return cleaned

    def __repr__(self) -> str:
        validators = ", ".join(e.check.name for e in self._validators)
        return f"Guard(name={self.name!r}, validators=[{validators}])"
