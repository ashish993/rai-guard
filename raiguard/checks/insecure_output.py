"""
Insecure output handling check — OWASP LLM02.

Detects when LLM output could be unsafe if rendered/executed directly:
- SQL injection in generated queries
- XSS payloads in generated HTML/JS
- Shell command injection
- Path traversal
- SSRF-prone URLs
"""

from __future__ import annotations

import re
from typing import Any

from raiguard.checks.base import BaseCheck, CheckResult, Severity

_OUTPUT_RISKS: list[tuple[str, str, Severity]] = [
    # SQL injection payloads
    (r"(?i)\b(SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|EXEC|UNION)\b.*\b(FROM|WHERE|TABLE|INTO|DATABASE)\b",
     "sql_query_in_output", Severity.HIGH),
    (r"(?i)('\s*OR\s*'1'\s*=\s*'1|'\s*;\s*DROP\s+TABLE|1\s*=\s*1[\s;]*--|xp_cmdshell|'\s*OR\s*\d+\s*=\s*\d+)",
     "sql_injection_payload", Severity.CRITICAL),

    # XSS
    (r"<script[^>]*>.*?</script>",
     "xss_script_tag", Severity.CRITICAL),
    (r"(?i)javascript\s*:[^\s]",
     "xss_javascript_protocol", Severity.HIGH),
    (r"(?i)on(load|click|error|mouseover|focus|blur)\s*=",
     "xss_event_handler", Severity.HIGH),

    # Template injection
    (r"\$\{[^}]+\}|\{\{[^}]+\}\}",
     "template_injection", Severity.HIGH),

    # JS fetch/exfil with parens or URL
    (r"(?i)fetch\s*\(?['\"]?https?://",
     "js_fetch_exfil", Severity.HIGH),

    # Shell injection
    (r"(?:;|\||&&|\$\(|`)\s*(?:rm|wget|curl|bash|sh|python|nc|netcat|ncat)\s",
     "shell_injection_payload", Severity.CRITICAL),
    (r"\$\([^)]+\)|`[^`]+`",
     "command_substitution", Severity.HIGH),

    # Path traversal
    (r"(?:\.\./){2,}|(?:\.\.\\){2,}",
     "path_traversal", Severity.HIGH),
    (r"(?i)/etc/(?:passwd|shadow|cron|crontab|sudoers|hosts|ssh)|/proc/self|C:\\Windows\\System32",
     "sensitive_path_reference", Severity.CRITICAL),

    # SSRF-prone patterns
    (r"(?i)(?:http|ftp|file|dict|ldap|sftp|tftp)://(?:169\.254\.169\.254|127\.\d+\.\d+\.\d+|10\.\d+\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+|192\.168\.\d+\.\d+)",
     "ssrf_internal_url", Severity.CRITICAL),

    # Sensitive data exfiltration patterns
    (r"(?i)(?:curl|wget|fetch)\s+['\"]?https?://[^'\">\s]+['\"]?\s+--data\b",
     "data_exfiltration_pattern", Severity.HIGH),
]

_COMPILED_OUTPUT = [(re.compile(p, re.IGNORECASE | re.DOTALL), label, sev)
                    for p, label, sev in _OUTPUT_RISKS]


class InsecureOutputCheck(BaseCheck):
    name = "insecure_output"
    description = "Detects dangerous patterns in LLM outputs (OWASP LLM02)"
    owasp_refs = ["LLM02"]
    eu_ai_act_refs = ["Article 9", "Article 15"]

    def __init__(self, threshold: float = 0.4):
        self.threshold = threshold

    def check_input(self, text: str, context: dict[str, Any] | None = None) -> CheckResult:
        """Block SQL/shell injection payloads in user prompts (OWASP LLM01 / A03)."""
        if not text:
            return self._make_result(True, 0.0, Severity.LOW)
        matches = []
        severity_scores = {Severity.LOW: 0.1, Severity.MEDIUM: 0.4,
                           Severity.HIGH: 0.7, Severity.CRITICAL: 1.0}
        max_score = 0.0
        max_sev = Severity.LOW
        for compiled, label, sev in _COMPILED_OUTPUT:
            if compiled.search(text):
                score = severity_scores[sev]
                matches.append({"pattern": label, "severity": sev.value})
                if score > max_score:
                    max_score = score
                    max_sev = sev
        if not matches:
            return self._make_result(True, 0.0, Severity.LOW)
        return self._make_result(
            passed=max_score < self.threshold,
            score=max_score,
            severity=max_sev,
            details={"matches": matches},
            patterns=[m["pattern"] for m in matches],
            remediation="Reject user input containing injection patterns. Sanitise before passing to any downstream system.",
        )

    def check_output(self, text: str, prompt: str = "", context: dict[str, Any] | None = None) -> CheckResult:
        if not text:
            return self._make_result(True, 0.0, Severity.LOW)

        matches = []
        severity_scores = {Severity.LOW: 0.1, Severity.MEDIUM: 0.4,
                           Severity.HIGH: 0.7, Severity.CRITICAL: 1.0}
        max_score = 0.0
        max_sev = Severity.LOW

        for compiled, label, sev in _COMPILED_OUTPUT:
            if compiled.search(text):
                score = severity_scores[sev]
                max_score = max(max_score, score)
                if score > severity_scores[max_sev]:
                    max_sev = sev
                matches.append({"type": label, "severity": sev.value})

        if not matches:
            return self._make_result(True, 0.0, Severity.LOW)

        final_score = round(min(1.0, max_score + (len(matches) - 1) * 0.05), 3)
        return self._make_result(
            passed=final_score < self.threshold,
            score=final_score,
            severity=max_sev,
            details={"risks_detected": matches},
            patterns=[m["type"] for m in matches],
            remediation=(
                "LLM output contains potentially dangerous code/payloads. "
                "Never pass LLM output directly to eval(), exec(), os.system(), or render as raw HTML. "
                "Sanitize all LLM-generated code before execution (OWASP LLM02)."
            ),
        )

    def fix(self, text: str) -> str:
        """Sanitize dangerous patterns from LLM output.

        - Strips <script> tags and JS event handlers (XSS)
        - Escapes SQL keywords in dangerous contexts
        - Removes shell injection characters
        - Replaces internal SSRF URLs with [BLOCKED:URL]
        """
        import re as _re
        result = text

        # Strip <script>...</script> blocks
        result = _re.sub(r'<script[^>]*>.*?</script>', '[REMOVED:SCRIPT]', result, flags=_re.IGNORECASE | _re.DOTALL)
        # Strip JS event handlers from HTML attributes
        result = _re.sub(r'\s+on\w+\s*=\s*["\'][^"\']*["\']', '', result, flags=_re.IGNORECASE)
        # Replace javascript: URIs
        result = _re.sub(r'javascript\s*:', 'javascript_blocked:', result, flags=_re.IGNORECASE)
        # Block internal SSRF URLs
        result = _re.sub(
            r'(?i)(?:http|ftp|file|dict|ldap)://(?:169\.254\.169\.254|127\.\d+\.\d+\.\d+|10\.\d+\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+|192\.168\.\d+\.\d+)[^\s]*',
            '[BLOCKED:INTERNAL_URL]', result
        )
        # Remove backtick and $() command substitutions
        result = _re.sub(r'`[^`]+`', '[REMOVED:CMD]', result)
        result = _re.sub(r'\$\([^)]+\)', '[REMOVED:CMD]', result)
        # Strip path traversal sequences
        result = _re.sub(r'(?:\.\./){2,}|(?:\.\.\\){2,}', '', result)
        return result
