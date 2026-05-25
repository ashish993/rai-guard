"""
NIST AI Risk Management Framework (AI RMF 1.0) mapper.

Maps rai-guard findings to NIST AI RMF core functions:
GOVERN, MAP, MEASURE, MANAGE
"""

from __future__ import annotations

from dataclasses import dataclass, field

from raiguard.checks.base import CheckResult

NIST_AI_RMF = {
    "GOVERN": {
        "description": "Establish policies, processes, and organizational roles for AI risk management.",
        "subcategories": {
            "GV-1.1": "AI risk management policies are established and maintained.",
            "GV-1.2": "Accountability mechanisms for AI risk are in place.",
            "GV-4.1": "Organizational teams have defined roles for AI risk.",
        },
        "mapped_checks": ["*"],
    },
    "MAP": {
        "description": "Categorize and prioritize AI risks in context of deployment.",
        "subcategories": {
            "MP-2.1": "Scientific findings support AI risk claims.",
            "MP-2.3": "AI system's risk context is understood.",
            "MP-5.1": "Likelihood and magnitude of impacts are mapped.",
        },
        "mapped_checks": ["prompt_injection", "pii_detection", "toxicity", "hallucination_risk"],
    },
    "MEASURE": {
        "description": "Analyse and assess AI risks using quantitative and qualitative methods.",
        "subcategories": {
            "MS-1.1": "Metrics are established for assessing AI risks.",
            "MS-2.1": "AI system performance is evaluated against established metrics.",
            "MS-2.5": "AI system robustness is tested under adverse conditions.",
            "MS-2.6": "Risk metrics are tracked over time.",
        },
        "mapped_checks": ["prompt_injection", "pii_detection", "toxicity", "hallucination_risk", "insecure_output"],
    },
    "MANAGE": {
        "description": "Prioritize and address AI risks with response and recovery plans.",
        "subcategories": {
            "MG-1.1": "Risks are prioritized by impact and likelihood.",
            "MG-2.2": "Risk responses are selected and implemented.",
            "MG-3.1": "Post-deployment AI risk monitoring is operational.",
            "MG-4.1": "Residual risks are tracked and disclosed.",
        },
        "mapped_checks": ["*"],
    },
}


@dataclass
class NISTFinding:
    function: str
    description: str
    maturity_level: int  # 1 (Initial) to 4 (Optimizing)
    maturity_label: str
    subcategory_scores: dict[str, float] = field(default_factory=dict)
    recommendations: list[str] = field(default_factory=list)


_MATURITY_LABELS = {1: "Initial", 2: "Managed", 3: "Defined", 4: "Optimizing"}


def map_to_nist_ai_rmf(
    check_results: list[CheckResult],
    has_audit_log: bool = True,
    has_monitoring: bool = True,
) -> list[NISTFinding]:
    check_map = {r.check_name: r for r in check_results}
    any_critical = any(r.score >= 0.8 for r in check_results)

    findings = []
    for function, meta in NIST_AI_RMF.items():
        mapped = meta["mapped_checks"]
        relevant = check_results if mapped == ["*"] else [check_map[c] for c in mapped if c in check_map]

        avg_score = sum(r.score for r in relevant) / len(relevant) if relevant else 0.0

        # Maturity level: based on presence of checks + results
        if not relevant:
            maturity = 1
        elif any_critical:
            maturity = 1
        elif avg_score > 0.5:
            maturity = 2
        elif has_audit_log and has_monitoring:
            maturity = 3 if avg_score < 0.3 else 2
        else:
            maturity = 2 if avg_score < 0.2 else 1

        recommendations = []
        if maturity < 3:
            recommendations.append(f"Increase to NIST AI RMF Maturity Level 3 by implementing continuous {function.lower()} processes.")
        if not has_audit_log:
            recommendations.append("Enable audit logging to satisfy MEASURE MS-2.6 (risk metrics tracked over time).")
        if any_critical:
            recommendations.append("Address critical-severity findings immediately to advance past Initial maturity.")

        findings.append(NISTFinding(
            function=function,
            description=meta["description"],
            maturity_level=maturity,
            maturity_label=_MATURITY_LABELS[maturity],
            subcategory_scores={k: round(max(0.0, 1.0 - avg_score), 2) for k in meta["subcategories"]},
            recommendations=recommendations,
        ))

    return findings
