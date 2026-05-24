"""
Toxicity and harmful content detection — OWASP LLM02.

Uses keyword/pattern matching locally. Optionally uses the `detoxify`
model if the ml extra is installed.
"""

from __future__ import annotations

import re
from typing import Any

from raiguard.checks.base import BaseCheck, CheckResult, Severity

_TOXIC_CATEGORIES: dict[str, tuple[list[str], Severity]] = {
    "hate_speech": ([
        r"\b(kill|murder|exterminate|genocide)\s+(all\s+)?(jews?|muslims?|blacks?|whites?|gays?|women|men)\b",
        r"\b(n[i1][g9]{2}[e3]r|f[a4][g9]{2}[o0]t|ch[i1]nk|sp[i1][c])\b",
        r"\bwhite\s+supremac|ethnic\s+cleansing|racial\s+purity\b",
    ], Severity.CRITICAL),

    "violence": ([
        r"\b(how\s+to|instructions?\s+for|steps?\s+to)\s+(build|make|create|assemble)\s+(a\s+)?(bomb|weapon|explosive|poison)\b",
        r"\b(shoot|stab|attack|harm|hurt|injure)\s+(them|people|civilians|crowd)\b",
        r"\bmass\s+(shooting|killing|murder|casualt)",
    ], Severity.CRITICAL),

    "self_harm": ([
        r"\b(how\s+to|ways?\s+to|methods?\s+of)\s+(commit\s+suicide|kill\s+(my)?self|end\s+(my\s+)?life)\b",
        r"\bsuicide\s+(method|instruction|plan|note)\b",
        r"\bself[\s\-]harm\s+(technique|method|instruction)\b",
    ], Severity.CRITICAL),

    "sexual_content": ([
        r"\b(explicit|pornographic|nsfw|xxx)\s+(content|material|image|video)\b",
        r"\b(sexual|nude|naked)\s+(content|image|photo)\s+(of|featuring)\s+(minor|child|teen|kid)\b",
        r"\bchild\s+(pornography|sexual\s+abuse\s+material|csam)\b",
    ], Severity.CRITICAL),

    "harassment": ([
        r"\b(you\s+are|ur|you're)\s+(stupid|idiot|moron|retard|worthless|ugly|fat|disgusting)\b",
        r"\b(i\s+will|gonna|going\s+to)\s+(find|hurt|kill|destroy|ruin)\s+you\b",
        r"\bdox(xing)?\s+(someone|this\s+person|them|you)\b",
    ], Severity.HIGH),

    "misinformation": ([
        r"\b(vaccines?\s+(cause|causes?|caused?)\s+autism)\b",
        r"\b(covid|coronavirus)\s+(is|was)\s+(a\s+)?(hoax|fake|planned|engineered)\b",
        r"\b(5g\s+(causes?|spreads?|transmits?)\s+covid|coronavirus)\b",
    ], Severity.HIGH),
}

_COMPILED_TOXIC: list[tuple[re.Pattern, str, Severity]] = []
for category, (patterns, severity) in _TOXIC_CATEGORIES.items():
    for pattern in patterns:
        _COMPILED_TOXIC.append((re.compile(pattern, re.IGNORECASE | re.DOTALL), category, severity))


def _try_detoxify(text: str) -> dict[str, float] | None:
    """Attempt to use detoxify model if available."""
    try:
        from detoxify import Detoxify  # type: ignore
        results = Detoxify("original").predict(text)
        return {k: float(v) for k, v in results.items()}
    except ImportError:
        return None


class ToxicityCheck(BaseCheck):
    name = "toxicity"
    description = "Detects harmful, toxic, and unsafe content (OWASP LLM02)"
    owasp_refs = ["LLM02"]
    eu_ai_act_refs = ["Article 9", "Article 13"]

    def __init__(self, threshold: float = 0.5, use_ml_model: bool = True):
        self.threshold = threshold
        self.use_ml_model = use_ml_model

    def _scan(self, text: str) -> tuple[list[dict], float, Severity]:
        matched_categories: list[dict] = []
        severity_scores = {Severity.LOW: 0.2, Severity.MEDIUM: 0.5,
                           Severity.HIGH: 0.75, Severity.CRITICAL: 1.0}
        max_score = 0.0
        max_sev = Severity.LOW

        for compiled, category, sev in _COMPILED_TOXIC:
            if compiled.search(text):
                score = severity_scores[sev]
                max_score = max(max_score, score)
                if severity_scores[sev] > severity_scores[max_sev]:
                    max_sev = sev
                matched_categories.append({"category": category, "severity": sev.value})

        # Try ML model for additional coverage
        ml_scores = None
        if self.use_ml_model and not matched_categories:
            ml_scores = _try_detoxify(text)
            if ml_scores:
                toxicity_score = ml_scores.get("toxicity", 0.0)
                if toxicity_score > 0.7:
                    max_score = max(max_score, toxicity_score)
                    matched_categories.append({
                        "category": "ml_detected_toxicity",
                        "severity": Severity.HIGH.value,
                        "ml_score": round(toxicity_score, 3),
                    })
                    max_sev = Severity.HIGH

        if ml_scores:
            return matched_categories, round(min(1.0, max_score), 3), max_sev
        return matched_categories, round(min(1.0, max_score), 3), max_sev

    def check_input(self, text: str, context: dict[str, Any] | None = None) -> CheckResult:
        matches, score, severity = self._scan(text)
        if not matches:
            return self._make_result(True, 0.0, Severity.LOW)
        return self._make_result(
            passed=score < self.threshold,
            score=score,
            severity=severity,
            details={"categories": matches},
            patterns=[m["category"] for m in matches],
            remediation="Block or flag this input. Log for human review per EU AI Act Article 14 (human oversight).",
        )

    def check_output(self, text: str, prompt: str = "", context: dict[str, Any] | None = None) -> CheckResult:
        matches, score, severity = self._scan(text)
        if not matches:
            return self._make_result(True, 0.0, Severity.LOW)
        return self._make_result(
            passed=score < self.threshold,
            score=score,
            severity=severity,
            details={"categories": matches, "source": "llm_output"},
            patterns=[m["category"] for m in matches],
            remediation=(
                "LLM is generating harmful content. Review system prompt safety instructions. "
                "This may indicate insufficient safety tuning — log for OWASP LLM02 compliance."
            ),
        )
