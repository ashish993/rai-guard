"""
EU AI Act compliance mapper.

Maps rai-guard findings to specific EU AI Act articles.
Covers Regulation (EU) 2024/1689 (AI Act), in force August 2024,
fully applicable from August 2026.

Focus: High-Risk AI systems (Annex III categories).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from raiguard.checks.base import CheckResult

EU_AI_ACT_ARTICLES = {
    "Article 9": {
        "title": "Risk Management System",
        "requirement": (
            "High-risk AI systems must have a continuous risk management system "
            "identifying, analysing and estimating known and foreseeable risks."
        ),
        "evidence_needed": [
            "Risk identification logs",
            "Risk mitigation measures documentation",
            "Residual risk assessment",
        ],
        "mapped_checks": ["prompt_injection", "toxicity", "hallucination_risk", "insecure_output"],
    },
    "Article 10": {
        "title": "Data and Data Governance",
        "requirement": (
            "Training, validation and testing data must be relevant, sufficiently representative, "
            "free of errors and complete. Personal data minimization required."
        ),
        "evidence_needed": [
            "Data source documentation",
            "PII scan results",
            "Data quality metrics",
        ],
        "mapped_checks": ["pii_detection"],
    },
    "Article 12": {
        "title": "Record-Keeping",
        "requirement": (
            "High-risk AI systems must automatically log events throughout their lifetime "
            "with sufficient detail to trace decisions and identify risks post-market."
        ),
        "evidence_needed": [
            "Audit log with timestamps",
            "Input/output logs",
            "Incident records",
            "Decision traces",
        ],
        "mapped_checks": ["*"],  # All checks contribute to record-keeping
    },
    "Article 13": {
        "title": "Transparency and Provision of Information",
        "requirement": (
            "High-risk AI systems must be designed to ensure that deployers can interpret "
            "the system's output and use it appropriately. Instructions for use required."
        ),
        "evidence_needed": [
            "Hallucination risk scores per response",
            "Confidence indicators",
            "Capability and limitation documentation",
        ],
        "mapped_checks": ["hallucination_risk", "pii_detection", "toxicity"],
    },
    "Article 14": {
        "title": "Human Oversight",
        "requirement": (
            "High-risk AI systems must be designed to enable human oversight. "
            "Natural persons must be able to monitor, intervene, interrupt, and override."
        ),
        "evidence_needed": [
            "Human review triggers log",
            "Override event records",
            "High-risk decision escalation records",
        ],
        "mapped_checks": ["hallucination_risk", "toxicity", "prompt_injection"],
    },
    "Article 15": {
        "title": "Accuracy, Robustness and Cybersecurity",
        "requirement": (
            "High-risk AI systems must achieve an appropriate level of accuracy, robustness, "
            "and cybersecurity, and resilient to adversarial inputs."
        ),
        "evidence_needed": [
            "Accuracy benchmarks",
            "Adversarial robustness test results",
            "Prompt injection test results",
            "Security scan reports",
        ],
        "mapped_checks": ["prompt_injection", "insecure_output"],
    },
    "Article 17": {
        "title": "Quality Management System",
        "requirement": (
            "Providers must implement a quality management system covering the entire lifecycle, "
            "including design, development, testing, deployment, and monitoring."
        ),
        "evidence_needed": [
            "Continuous monitoring records",
            "Incident response documentation",
            "Post-market surveillance logs",
        ],
        "mapped_checks": ["*"],
    },
}


@dataclass
class EUAIActFinding:
    article: str
    title: str
    requirement_summary: str
    compliant: bool
    compliance_score: float  # 0-100
    evidence_collected: list[str]
    evidence_gaps: list[str]
    triggered_checks: list[str]
    risk_level: str  # "low", "medium", "high", "critical"


def map_to_eu_ai_act(
    check_results: list[CheckResult],
    audit_log_enabled: bool = True,
) -> list[EUAIActFinding]:
    """Map check results to EU AI Act article compliance status."""
    check_map: dict[str, CheckResult] = {r.check_name: r for r in check_results}

    findings = []
    for article, meta in EU_AI_ACT_ARTICLES.items():
        mapped_checks = meta["mapped_checks"]
        relevant_results = []

        if mapped_checks == ["*"]:
            relevant_results = list(check_results)
        else:
            relevant_results = [check_map[c] for c in mapped_checks if c in check_map]

        # Determine evidence collected vs gaps
        evidence_collected = []
        evidence_gaps = list(meta["evidence_needed"])

        if article == "Article 12" and audit_log_enabled:
            evidence_collected.append("Audit log with timestamps")
            if "Audit log with timestamps" in evidence_gaps:
                evidence_gaps.remove("Audit log with timestamps")

        for result in relevant_results:
            # Each check that ran provides evidence
            check_label = f"{result.check_name} scan results"
            if check_label not in evidence_collected:
                evidence_collected.append(check_label)
            # Remove matching gaps
            evidence_gaps = [g for g in evidence_gaps
                             if result.check_name.replace("_", " ") not in g.lower()]

        # Compliance score
        if not relevant_results:
            compliance_score = 50.0  # unknown
            compliant = False
        else:
            failed = [r for r in relevant_results if not r.passed]
            max_risk = max((r.score for r in relevant_results), default=0.0)
            compliance_score = round((1.0 - max_risk) * 100, 1)
            compliant = len(failed) == 0

        risk_level = (
            "critical" if compliance_score < 40 else
            "high" if compliance_score < 60 else
            "medium" if compliance_score < 80 else "low"
        )

        findings.append(EUAIActFinding(
            article=article,
            title=meta["title"],
            requirement_summary=meta["requirement"][:200] + "...",
            compliant=compliant,
            compliance_score=compliance_score,
            evidence_collected=evidence_collected,
            evidence_gaps=evidence_gaps,
            triggered_checks=[r.check_name for r in relevant_results],
            risk_level=risk_level,
        ))

    return findings


def eu_ai_act_overall_score(findings: list[EUAIActFinding]) -> dict[str, Any]:
    """Compute overall EU AI Act compliance posture."""
    if not findings:
        return {"score": 0.0, "grade": "F", "articles_compliant": 0, "total_articles": 0}

    total = len(findings)
    compliant_count = sum(1 for f in findings if f.compliant)
    avg_score = sum(f.compliance_score for f in findings) / total

    grade = "A" if avg_score >= 90 else "B" if avg_score >= 75 else "C" if avg_score >= 60 else "D" if avg_score >= 45 else "F"

    critical_gaps = [f.article for f in findings if f.risk_level in ("critical", "high")]

    return {
        "score": round(avg_score, 1),
        "grade": grade,
        "articles_compliant": compliant_count,
        "total_articles": total,
        "critical_gaps": critical_gaps,
        "deployment_recommendation": (
            "APPROVED for deployment" if avg_score >= 75 else
            "CONDITIONAL — remediate critical gaps before production" if avg_score >= 50 else
            "NOT APPROVED — significant compliance gaps detected"
        ),
    }
