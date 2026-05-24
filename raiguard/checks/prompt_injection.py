"""
Prompt injection detection — OWASP LLM01.

Detects attempts to override system instructions, hijack agent behavior,
or inject malicious instructions into LLM prompts.
"""

from __future__ import annotations

import re
from typing import Any

from raiguard.checks.base import BaseCheck, CheckResult, Severity

# Core injection patterns — inspired by research from:
# - OWASP LLM Top 10 (LLM01)
# - protectai/llm-guard (Apache 2.0)
# - vigil-llm detection patterns
_INJECTION_PATTERNS: list[tuple[str, str, Severity]] = [
    # Direct instruction override
    (r"ignore\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions?|prompts?|rules?|constraints?)",
     "Direct instruction override", Severity.CRITICAL),
    (r"disregard\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions?|prompts?|rules?)",
     "Instruction disregard attempt", Severity.CRITICAL),
    (r"forget\s+(everything|all)\s+(you('ve)?\s+been|i\s+said|above)",
     "Memory wipe attempt", Severity.HIGH),

    # Role hijacking
    (r"you\s+are\s+now\s+(an?\s+)?(new|different|another|evil|unfiltered|unrestricted)",
     "Role hijacking attempt", Severity.HIGH),
    (r"act\s+as\s+(if\s+you\s+(are|were)\s+)?(a\s+)?(DAN|jailbroken|unrestricted|evil)",
     "DAN/jailbreak role injection", Severity.CRITICAL),
    (r"pretend\s+(you\s+are|to\s+be)\s+(an?\s+)?(different|evil|unrestricted|uncensored)",
     "Persona override attempt", Severity.HIGH),

    # System prompt extraction
    (r"(print|show|display|reveal|output|repeat|tell\s+me)\s+(your\s+)?(system\s+prompt|instructions|initial\s+prompt|original\s+prompt)",
     "System prompt extraction attempt", Severity.HIGH),
    (r"what\s+(are\s+your|were\s+you)\s+(given|told|instructed|programmed)",
     "Instruction probing", Severity.MEDIUM),

    # Delimiter injection
    (r"```\s*(system|instructions?|prompt)\b",
     "Delimiter-based injection attempt", Severity.HIGH),
    (r"<\s*(system|instructions?|prompt)\s*>",
     "XML-style injection attempt", Severity.HIGH),
    (r"\[INST\]|\[/INST\]|\[SYS\]|\[/SYS\]|\<\|im_start\|\>|\<\|im_end\|\>",
     "Model-specific delimiter injection", Severity.CRITICAL),

    # Indirect injection markers
    (r"(translate|summarize|analyze)\s+the\s+following.*ignore",
     "Indirect injection via task prefix", Severity.MEDIUM),
    (r"payload\s*[:=]|injection\s*[:=]|jailbreak\s*[:=]",
     "Explicit injection marker", Severity.CRITICAL),

    # Privilege escalation
    (r"(enable|unlock|activate)\s+(developer|admin|god|root|debug|maintenance)\s+mode",
     "Privilege escalation attempt", Severity.HIGH),
    (r"override\s+(safety|content|ethical|moral)\s+(filter|guideline|policy|constraint)",
     "Safety override attempt", Severity.CRITICAL),
]

_COMPILED = [(re.compile(pattern, re.IGNORECASE | re.DOTALL), desc, sev)
             for pattern, desc, sev in _INJECTION_PATTERNS]


class PromptInjectionCheck(BaseCheck):
    name = "prompt_injection"
    description = "Detects prompt injection and jailbreak attempts (OWASP LLM01)"
    owasp_refs = ["LLM01"]
    eu_ai_act_refs = ["Article 9", "Article 15"]

    def __init__(self, threshold: float = 0.5):
        self.threshold = threshold

    def check_input(self, text: str, context: dict[str, Any] | None = None) -> CheckResult:
        if not text or not text.strip():
            return self._make_result(True, 0.0, Severity.LOW)

        matched: list[tuple[str, Severity]] = []
        for compiled, desc, sev in _COMPILED:
            if compiled.search(text):
                matched.append((desc, sev))

        if not matched:
            return self._make_result(True, 0.0, Severity.LOW)

        # Score based on highest severity found
        severity_scores = {Severity.LOW: 0.2, Severity.MEDIUM: 0.5,
                           Severity.HIGH: 0.75, Severity.CRITICAL: 1.0}
        max_sev = max(matched, key=lambda x: severity_scores[x[1]])[1]
        score = min(1.0, severity_scores[max_sev] + (len(matched) - 1) * 0.05)
        passed = score < self.threshold

        return self._make_result(
            passed=passed,
            score=round(score, 3),
            severity=max_sev,
            details={"matches": [{"pattern": d, "severity": s.value} for d, s in matched]},
            patterns=[d for d, _ in matched],
            remediation=(
                "Sanitize or reject this input. Apply input validation and consider "
                "using a separate system prompt that cannot be overridden by user input."
            ),
        )

    def check_output(self, text: str, prompt: str = "", context: dict[str, Any] | None = None) -> CheckResult:
        # For output, check if the model was successfully manipulated
        output_injection_patterns = [
            (r"i\s+(am|will)\s+(now|no\s+longer)\s+(follow|ignore|bypass)", Severity.HIGH),
            (r"as\s+(DAN|an?\s+unrestricted|an?\s+evil)\s+(ai|assistant|model)", Severity.CRITICAL),
            (r"(my|all)\s+(safety|ethical|content)\s+(filters?|guidelines?|policies?)\s+(are|have\s+been)\s+(disabled|removed|lifted)", Severity.CRITICAL),
        ]
        for pattern, sev in output_injection_patterns:
            if re.search(pattern, text, re.IGNORECASE):
                return self._make_result(
                    passed=False, score=0.9, severity=sev,
                    details={"type": "successful_injection_in_output"},
                    remediation="LLM output indicates successful injection. Review system prompts and add output validation.",
                )
        return self._make_result(True, 0.0, Severity.LOW)
