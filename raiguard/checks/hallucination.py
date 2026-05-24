"""
Hallucination risk scoring — OWASP LLM09 (Overreliance).

Uses linguistic analysis to identify uncertainty markers, fabrication signals,
and overconfidence indicators. Does NOT require external API calls.
"""

from __future__ import annotations

import re
from typing import Any

from raiguard.checks.base import BaseCheck, CheckResult, Severity

# High-confidence fabrication signals — model stating uncertain things as fact
_FABRICATION_SIGNALS: list[tuple[str, float]] = [
    # Specific false citations
    (r"\b(published|authored|written)\s+in\s+\d{4}\s+by\s+[A-Z][a-z]+\s+[A-Z][a-z]+", 0.6),
    (r"\baccording\s+to\s+(?:the\s+)?(?:study|research|paper|report)\s+(?:published|from)\s+(?:in\s+)?\d{4}", 0.5),
    (r"\bISBN\s*:?\s*[\d\-X]{10,17}", 0.7),
    (r"\bDOI\s*:?\s*10\.\d{4,}/\S+", 0.6),
    # Specific statistics without citation
    (r"\b(?:exactly|precisely)\s+\d+(?:\.\d+)?%\s+of\s+(?:people|users|cases|instances)", 0.5),
    (r"\b\d{1,3}(?:,\d{3})*\s+(?:people|individuals|cases)\s+(?:died|were killed|were affected)", 0.55),
]

# Appropriate uncertainty markers (model hedging — this is GOOD, lowers hallucination risk)
_UNCERTAINTY_MARKERS: list[str] = [
    r"\b(I|i)\s+(think|believe|assume|suppose|reckon|imagine)",
    r"\b(might|may|could|can|should)\s+(be|have|indicate)",
    r"\b(probably|likely|possibly|perhaps|maybe|approximately|roughly|around|about)\b",
    r"\b(I'm|I am)\s+not\s+(sure|certain|confident|aware)",
    r"\b(to\s+my\s+knowledge|as\s+far\s+as\s+I\s+know|based\s+on\s+my\s+training)",
    r"\b(please\s+verify|you\s+should\s+check|I\s+recommend\s+confirming)",
    r"\b(I\s+don't\s+have|I\s+lack)\s+(access\s+to|information\s+about)",
    r"\bmy\s+(training\s+data|knowledge\s+cutoff|information)\s+(has|is\s+limited|may\s+be\s+outdated)",
]

# Overconfidence signals — stating highly specific facts without hedging
_OVERCONFIDENCE_SIGNALS: list[tuple[str, float]] = [
    (r"\bthe\s+(?:answer|fact|truth|reality)\s+is\s+(?:definitively|absolutely|certainly)", 0.4),
    (r"\b(?:I\s+can\s+confirm|I\s+guarantee|I\s+assure\s+you)\s+that\b", 0.35),
    (r"\b100%\s+(?:accurate|correct|certain|sure|guaranteed)\b", 0.5),
    (r"\bno\s+(?:doubt|question)\s+(?:about\s+it|that)\b", 0.3),
]

_COMPILED_FAB = [(re.compile(p, re.IGNORECASE), s) for p, s in _FABRICATION_SIGNALS]
_COMPILED_UNCERTAIN = [re.compile(p, re.IGNORECASE) for p in _UNCERTAINTY_MARKERS]
_COMPILED_OVERCONF = [(re.compile(p, re.IGNORECASE), s) for p, s in _OVERCONFIDENCE_SIGNALS]


class HallucinationCheck(BaseCheck):
    name = "hallucination_risk"
    description = "Scores hallucination risk via linguistic analysis (OWASP LLM09)"
    owasp_refs = ["LLM09"]
    eu_ai_act_refs = ["Article 9", "Article 13", "Article 14"]

    def __init__(self, threshold: float = 0.6):
        self.threshold = threshold

    def check_input(self, text: str, context: dict[str, Any] | None = None) -> CheckResult:
        # For input, check if user is asking for highly specific factual claims
        # that are likely to cause hallucinations
        hallucination_bait = [
            r"\bwhat\s+(?:is|are)\s+the\s+exact\s+(?:number|date|name|amount)\b",
            r"\b(?:cite|list|name)\s+(?:all|every)\s+(?:the\s+)?(?:studies|papers|sources|authors)\b",
            r"\bwhat\s+(?:did|does)\s+[A-Z][a-z]+\s+[A-Z][a-z]+\s+(?:say|write|publish)\s+(?:about|on)\b",
        ]
        bait_matches = []
        for pattern in hallucination_bait:
            if re.search(pattern, text, re.IGNORECASE):
                bait_matches.append(pattern)

        if bait_matches:
            return self._make_result(
                passed=True,  # input itself is not dangerous, but flag it
                score=0.3,
                severity=Severity.LOW,
                details={"hallucination_prone_request": True, "patterns": len(bait_matches)},
                remediation="This query type is prone to hallucinations. Append retrieval-augmented context.",
            )
        return self._make_result(True, 0.0, Severity.LOW)

    def check_output(self, text: str, prompt: str = "", context: dict[str, Any] | None = None) -> CheckResult:
        if not text or len(text.strip()) < 20:
            return self._make_result(True, 0.0, Severity.LOW)

        details: dict[str, Any] = {}
        risk_score = 0.0

        # Count uncertainty markers (good — reduces risk)
        uncertainty_count = sum(1 for p in _COMPILED_UNCERTAIN if p.search(text))
        details["uncertainty_markers_found"] = uncertainty_count

        # Check for fabrication signals (bad — increases risk)
        fab_signals = []
        for compiled, score in _COMPILED_FAB:
            if compiled.search(text):
                fab_signals.append({"signal": compiled.pattern[:50], "weight": score})
                risk_score += score
        details["fabrication_signals"] = len(fab_signals)

        # Check for overconfidence (bad)
        overconf_signals = []
        for compiled, score in _COMPILED_OVERCONF:
            if compiled.search(text):
                overconf_signals.append({"signal": compiled.pattern[:50], "weight": score})
                risk_score += score
        details["overconfidence_signals"] = len(overconf_signals)

        # Adjust: uncertainty markers reduce risk
        if uncertainty_count > 0:
            risk_score *= max(0.2, 1.0 - (uncertainty_count * 0.15))

        # Long outputs with specific numbers/dates without hedging = higher risk
        word_count = len(text.split())
        specific_numbers = len(re.findall(r"\b\d{4,}\b|\b\d+\.\d+%\b", text))
        if specific_numbers > 3 and uncertainty_count == 0:
            risk_score += 0.2
            details["unhedged_specific_claims"] = specific_numbers

        risk_score = round(min(1.0, risk_score), 3)
        details["final_risk_score"] = risk_score
        details["word_count"] = word_count

        severity = (Severity.CRITICAL if risk_score >= 0.8 else
                    Severity.HIGH if risk_score >= 0.6 else
                    Severity.MEDIUM if risk_score >= 0.3 else Severity.LOW)

        return self._make_result(
            passed=risk_score < self.threshold,
            score=risk_score,
            severity=severity,
            details=details,
            remediation=(
                "High hallucination risk detected. Consider: (1) Adding RAG context, "
                "(2) Instructing model to cite sources, (3) Enabling human review for "
                "high-stakes outputs per EU AI Act Article 14."
            ) if risk_score >= self.threshold else "",
        )
