"""Base classes for all rai-guard checks."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class CheckResult:
    check_name: str
    passed: bool
    severity: Severity
    score: float  # 0.0 (safe) to 1.0 (most risky)
    details: dict[str, Any] = field(default_factory=dict)
    matched_patterns: list[str] = field(default_factory=list)
    owasp_refs: list[str] = field(default_factory=list)   # e.g. ["LLM01", "LLM06"]
    eu_ai_act_refs: list[str] = field(default_factory=list)  # e.g. ["Article 9", "Article 13"]
    remediation: str = ""


class BaseCheck:
    """All checks inherit from this."""

    name: str = "base"
    description: str = ""
    owasp_refs: list[str] = []
    eu_ai_act_refs: list[str] = []

    def check_input(self, text: str, context: dict[str, Any] | None = None) -> CheckResult:
        raise NotImplementedError

    def check_output(self, text: str, prompt: str = "", context: dict[str, Any] | None = None) -> CheckResult:
        raise NotImplementedError

    def _make_result(self, passed: bool, score: float, severity: Severity,
                     details: dict | None = None, patterns: list[str] | None = None,
                     remediation: str = "") -> CheckResult:
        return CheckResult(
            check_name=self.name,
            passed=passed,
            severity=severity,
            score=score,
            details=details or {},
            matched_patterns=patterns or [],
            owasp_refs=self.owasp_refs,
            eu_ai_act_refs=self.eu_ai_act_refs,
            remediation=remediation,
        )
