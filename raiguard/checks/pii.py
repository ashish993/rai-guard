"""
PII (Personally Identifiable Information) detection — OWASP LLM06.

Detects PII in both prompts (user sending PII unnecessarily) and
LLM outputs (model leaking sensitive data).
"""

from __future__ import annotations

import re
from typing import Any

from raiguard.checks.base import BaseCheck, CheckResult, Severity


_PII_PATTERNS: list[tuple[str, str, Severity, str]] = [
    # (pattern, label, severity, eu_risk_level)
    # Financial — accept both raw digits and common space/dash-separated formats
    (r"\b(?:4[0-9]{3}[\s\-]?[0-9]{4}[\s\-]?[0-9]{4}[\s\-]?[0-9]{1,4}"
     r"|5[1-5][0-9]{2}[\s\-]?[0-9]{4}[\s\-]?[0-9]{4}[\s\-]?[0-9]{4}"
     r"|3[47][0-9]{2}[\s\-]?[0-9]{6}[\s\-]?[0-9]{5}"
     r"|6(?:011|5[0-9]{2})[\s\-]?[0-9]{4}[\s\-]?[0-9]{4}[\s\-]?[0-9]{4})\b",
     "credit_card", Severity.CRITICAL, "high"),
    (r"\b[0-9]{3}-[0-9]{2}-[0-9]{4}\b",
     "ssn_us", Severity.CRITICAL, "high"),
    (r"\b(?:IBAN\s*:?\s*)?[A-Z]{2}[0-9]{2}[A-Z0-9]{4}[0-9]{7}(?:[A-Z0-9]{0,16})?\b",
     "iban", Severity.HIGH, "high"),

    # Identity
    (r"\b[A-Z]{1,2}[0-9]{6,9}\b",
     "passport_number", Severity.HIGH, "high"),
    (r"\b[0-9]{3}-[0-9]{3}-[0-9]{4}\b",
     "phone_us", Severity.MEDIUM, "medium"),
    # Require an explicit + country-code prefix to avoid false positives on dates,
    # scores, version strings, and other common number sequences.
    (r"\b\+[0-9]{1,3}[\s\-](?:\([0-9]{1,4}\)[\s\-])?[0-9]{3,4}[\s\-][0-9]{3,4}(?:[\s\-][0-9]{2,4})?\b",
     "phone_intl", Severity.MEDIUM, "medium"),

    # Contact
    (r"\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b",
     "email", Severity.MEDIUM, "medium"),

    # Medical
    (r"\b(?:patient\s+id|mrn|medical\s+record(?:\s+number)?)\s*:?\s*[A-Z0-9\-]{4,}\b",
     "medical_record", Severity.CRITICAL, "high"),
    (r"\b(?:diagnosis|prescribed|medication|dosage)\s*:?\s*[a-zA-Z0-9\s,]+\b",
     "medical_info", Severity.HIGH, "medium"),

    # Technical secrets
    (r"\b(?:sk-|pk_live_|rk_live_|sk_live_)[a-zA-Z0-9]{20,}\b",
     "api_key_stripe_openai", Severity.CRITICAL, "high"),
    (r"\b(?:ghp_|gho_|ghu_|ghs_|ghr_)[a-zA-Z0-9]{36}\b",
     "github_token", Severity.CRITICAL, "high"),
    (r"\b(?:AKIA|AGPA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}\b",
     "aws_access_key", Severity.CRITICAL, "high"),
    (r"\bAIza[0-9A-Za-z\-_]{35}\b",
     "google_api_key", Severity.CRITICAL, "high"),
    (r"\b(?:xox[baprs]-)[0-9a-zA-Z\-]{10,48}\b",
     "slack_token", Severity.CRITICAL, "high"),
    (r"(?i)password\s*[=:]\s*['\"]?[^\s'\"]{6,}",
     "password_in_text", Severity.HIGH, "high"),
    (r"(?i)(?:private_key|secret_key|api_secret)\s*[=:]\s*['\"]?[^\s'\"]{8,}",
     "secret_credential", Severity.CRITICAL, "high"),

    # Location
    (r"\b\d{1,5}\s+[a-zA-Z0-9\s,\.]+(?:street|st|avenue|ave|road|rd|boulevard|blvd|drive|dr|lane|ln|court|ct|way|wy)\b",
     "street_address", Severity.LOW, "low"),
    (r"\b\d{5}(?:[-\s]\d{4})?\b",
     "zip_code_us", Severity.LOW, "low"),

    # EU-specific
    (r"\b[0-9]{8,12}\b(?=.*\b(?:bsn|citizen|national\s+id)\b)",
     "eu_national_id", Severity.HIGH, "high"),
]

_COMPILED_PII = [
    (re.compile(pattern, re.IGNORECASE | re.MULTILINE), label, sev, risk)
    for pattern, label, sev, risk in _PII_PATTERNS
]


def _redact(text: str, matches: list[tuple[str, str]]) -> str:
    """Redact detected PII from text."""
    result = text
    for value, label in matches:
        redacted = f"[REDACTED:{label.upper()}]"
        result = result.replace(value, redacted)
    return result


class PIICheck(BaseCheck):
    name = "pii_detection"
    description = "Detects PII exposure in prompts and LLM outputs (OWASP LLM06)"
    owasp_refs = ["LLM06"]
    eu_ai_act_refs = ["Article 10", "Article 13"]

    def __init__(self, threshold: float = 0.3, redact: bool = False):
        self.threshold = threshold
        self.redact = redact

    def _scan(self, text: str) -> tuple[list[dict], float]:
        found: list[dict] = []
        severity_scores = {Severity.LOW: 0.1, Severity.MEDIUM: 0.4,
                           Severity.HIGH: 0.7, Severity.CRITICAL: 1.0}
        max_score = 0.0

        for compiled, label, sev, risk in _COMPILED_PII:
            matches = compiled.findall(text)
            if matches:
                score = severity_scores[sev]
                max_score = max(max_score, score)
                found.append({
                    "type": label,
                    "severity": sev.value,
                    "count": len(matches),
                    "eu_risk_level": risk,
                    # Only show first match partially masked
                    "sample": matches[0][:6] + "***" if matches else "",
                })

        return found, round(min(1.0, max_score + (len(found) - 1) * 0.03) if found else 0.0, 3)

    def check_input(self, text: str, context: dict[str, Any] | None = None) -> CheckResult:
        found, score = self._scan(text)
        if not found:
            return self._make_result(True, 0.0, Severity.LOW)

        max_sev = max(found, key=lambda x: ["low","medium","high","critical"].index(x["severity"]))["severity"]
        return self._make_result(
            passed=score < self.threshold,
            score=score,
            severity=Severity(max_sev),
            details={"pii_types_found": found, "total_matches": sum(f["count"] for f in found)},
            patterns=[f["type"] for f in found],
            remediation=(
                "Remove or anonymize PII before sending to LLM. Under GDPR/EU AI Act, "
                "sending personal data to external LLM APIs may require explicit consent. "
                "Consider using local models for PII-heavy workloads."
            ),
        )

    def check_output(self, text: str, prompt: str = "", context: dict[str, Any] | None = None) -> CheckResult:
        found, score = self._scan(text)
        if not found:
            return self._make_result(True, 0.0, Severity.LOW)

        max_sev = max(found, key=lambda x: ["low","medium","high","critical"].index(x["severity"]))["severity"]
        return self._make_result(
            passed=score < self.threshold,
            score=score,
            severity=Severity(max_sev),
            details={"pii_types_found": found, "output_contains_pii": True},
            patterns=[f["type"] for f in found],
            remediation=(
                "LLM output contains PII. This may indicate training data leakage (OWASP LLM06). "
                "Implement output filtering. Under EU AI Act Article 10, training data must be free "
                "of unnecessary personal data."
            ),
        )
