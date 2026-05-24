"""
OWASP LLM Top 10 compliance mapper.

Maps check results to OWASP LLM Top 10 (2025 edition) categories.
Reference: https://owasp.org/www-project-top-10-for-large-language-model-applications/
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from raiguard.checks.base import CheckResult

OWASP_LLM_TOP10 = {
    "LLM01": {
        "name": "Prompt Injection",
        "description": (
            "Manipulating LLM behavior through crafted inputs that override system instructions, "
            "hijack agent actions, or exfiltrate data."
        ),
        "mitigation": "Input validation, privilege separation, least-privilege agents, output validation.",
        "severity_weight": 1.0,
    },
    "LLM02": {
        "name": "Insecure Output Handling",
        "description": (
            "Downstream vulnerabilities when LLM output is passed to interpreters "
            "(shell, SQL, HTML) without sanitization."
        ),
        "mitigation": "Treat LLM output as untrusted input. Sanitize before eval/exec/render.",
        "severity_weight": 0.95,
    },
    "LLM03": {
        "name": "Training Data Poisoning",
        "description": "Manipulation of training data to introduce backdoors or biased behavior.",
        "mitigation": "Data provenance tracking, anomaly detection in training pipelines.",
        "severity_weight": 0.85,
    },
    "LLM04": {
        "name": "Model Denial of Service",
        "description": "Consuming excessive resources through crafted inputs (long contexts, recursive prompts).",
        "mitigation": "Rate limiting, token budget enforcement, timeout controls.",
        "severity_weight": 0.70,
    },
    "LLM05": {
        "name": "Supply Chain Vulnerabilities",
        "description": "Risks from third-party models, plugins, training datasets, or deployment infrastructure.",
        "mitigation": "Model provenance verification, dependency scanning, SBOM for AI components.",
        "severity_weight": 0.80,
    },
    "LLM06": {
        "name": "Sensitive Information Disclosure",
        "description": "LLM reveals confidential data, PII, proprietary information, or system prompts.",
        "mitigation": "PII detection/redaction, output filtering, minimize sensitive data in context.",
        "severity_weight": 0.90,
    },
    "LLM07": {
        "name": "Insecure Plugin Design",
        "description": "LLM plugins/tools with insufficient access controls, input validation, or authorization.",
        "mitigation": "Least privilege plugins, parameter validation, user consent for actions.",
        "severity_weight": 0.85,
    },
    "LLM08": {
        "name": "Excessive Agency",
        "description": "LLM granted too much autonomy, leading to unintended consequential actions.",
        "mitigation": "Minimal permissions, human-in-the-loop for high-impact actions, action reversibility.",
        "severity_weight": 0.88,
    },
    "LLM09": {
        "name": "Overreliance / Hallucination",
        "description": "Users or systems trusting LLM outputs that are factually incorrect or fabricated.",
        "mitigation": "Calibration, RAG, citation requirements, human oversight for high-stakes decisions.",
        "severity_weight": 0.82,
    },
    "LLM10": {
        "name": "Model Theft",
        "description": "Unauthorized extraction of model weights, architecture, or proprietary training data.",
        "mitigation": "Rate limiting, query monitoring, watermarking, API access controls.",
        "severity_weight": 0.75,
    },
}


@dataclass
class OWASPFinding:
    category_id: str
    category_name: str
    triggered_by: list[str]  # check names that triggered this
    risk_score: float
    compliant: bool
    evidence: list[dict[str, Any]] = field(default_factory=list)


def map_to_owasp(check_results: list[CheckResult]) -> list[OWASPFinding]:
    """Map a list of CheckResults to OWASP LLM Top 10 findings."""
    category_map: dict[str, list[CheckResult]] = {}

    for result in check_results:
        for ref in result.owasp_refs:
            if ref not in category_map:
                category_map[ref] = []
            category_map[ref].append(result)

    findings = []
    for category_id, results in category_map.items():
        meta = OWASP_LLM_TOP10.get(category_id, {})
        failed = [r for r in results if not r.passed]
        max_score = max((r.score for r in results), default=0.0)
        weight = meta.get("severity_weight", 1.0)

        findings.append(OWASPFinding(
            category_id=category_id,
            category_name=meta.get("name", category_id),
            triggered_by=[r.check_name for r in results],
            risk_score=round(max_score * weight, 3),
            compliant=len(failed) == 0,
            evidence=[{
                "check": r.check_name,
                "score": r.score,
                "passed": r.passed,
                "patterns": r.matched_patterns,
            } for r in results],
        ))

    return sorted(findings, key=lambda f: f.risk_score, reverse=True)


def owasp_compliance_score(findings: list[OWASPFinding]) -> dict[str, Any]:
    """Compute overall OWASP LLM compliance posture."""
    if not findings:
        return {"score": 100.0, "grade": "A", "compliant_categories": 0, "total_categories": 0}

    total = len(findings)
    compliant = sum(1 for f in findings if f.compliant)
    avg_risk = sum(f.risk_score for f in findings) / total
    score = round(max(0.0, (1.0 - avg_risk) * 100), 1)

    grade = "A" if score >= 90 else "B" if score >= 75 else "C" if score >= 60 else "D" if score >= 45 else "F"

    return {
        "score": score,
        "grade": grade,
        "compliant_categories": compliant,
        "total_categories": total,
        "high_risk_categories": [f.category_id for f in findings if f.risk_score >= 0.7],
    }
