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
    # Direct instruction override — with or without 'previous/prior' qualifier
    # Allows 0-2 filler words between "ignore" and the key noun
    (r"ignore\s+(?:[\w.]+\s+){0,3}(instructions?|rules?|guidelines?|polic(?:y|ies)|constraints?|safety|restrictions?|guardrails?|filters?)",
     "Direct instruction override", Severity.CRITICAL),
    (r"disregard\s+(?:\w+\s+){0,2}(instructions?|rules?|guidelines?|polic(?:y|ies)|constraints?)",
     "Instruction disregard attempt", Severity.CRITICAL),
    (r"break\s+(?:\w+\s+){0,2}(rules?|guidelines?|polic(?:y|ies)|constraints?)",
     "Rule-breaking instruction", Severity.HIGH),
    (r"forget\s+(everything|all)\s+(you('ve)?\s+been|i\s+said|above)",
     "Memory wipe attempt", Severity.HIGH),
    (r"break\s+(the\s+)?(rules|guidelines|policies|policy|constraints|safety)",
     "Rule-breaking instruction", Severity.HIGH),

    # Role hijacking — any role assignment, not just evil/unrestricted
    (r"you\s+are\s+now\s+(?:a\s+|an\s+|the\s+)?(new|different|another|evil|unfiltered|unrestricted|system\s+admin|admin|administrator|root|superuser|god\s+mode)",
     "Role hijacking attempt", Severity.HIGH),
    (r"act\s+as\s+(if\s+you\s+(are|were)\s+)?(a\s+|an\s+)?(DAN|jailbroken|unrestricted|evil|uncensored|unfiltered)",
     "DAN/jailbreak role injection", Severity.CRITICAL),
    (r"pretend\s+(you\s+are|to\s+be)\s+(an?\s+)?(different|evil|unrestricted|uncensored)",
     "Persona override attempt", Severity.HIGH),
    # Impersonation / unlock mode
    (r"(unlock|enable|activate)\s+(admin|god|root|unrestricted|developer|maintenance)\s*(mode)?",
     "Admin mode unlock attempt", Severity.CRITICAL),
    (r"i('m|\s+am)\s+(genesys|openai|anthropic|microsoft|google|support|admin)\s*(support|team|staff)?",
     "Vendor/support impersonation", Severity.HIGH),

    # System prompt / hidden instructions extraction
    (r"(print|show|display|reveal|output|repeat|tell\s+me|give\s+me)\s+(your\s+)?(system\s+prompt|hidden\s+instructions?|initial\s+prompt|original\s+prompt|internal\s+instructions?|private\s+settings?|config\s+details?|internal\s+settings?)",
     "System prompt extraction attempt", Severity.HIGH),
    (r"what\s+(are\s+your|were\s+you)\s+(given|told|instructed|programmed)",
     "Instruction probing", Severity.MEDIUM),
    (r"(hidden|secret|internal)\s+instructions?",
     "Hidden instruction probing", Severity.HIGH),

    # Credential / API key / token extraction (allow 0-1 optional words before the keyword)
    (r"(show|give|reveal|print|tell\s+me)\s+(?:me\s+)?(?:\w+\s+){0,2}(api\s+key|api\s+token|secret\s+key|secret\s+token|access\s+token|bearer\s+token|auth\s+token|credentials?|password|passphrase)",
     "Credential extraction attempt", Severity.CRITICAL),
    (r"what\s+is\s+(your\s+)?(token|password|api\s+key|secret|passphrase|credential)",
     "Credential probing", Severity.HIGH),
    (r"(admin|login)\s+page\s+(url|link|address)",
     "Phishing / admin page request", Severity.HIGH),
    # System/internal rules disclosure
    (r"reveal\s+(?:\w+\s+){0,3}(system\s+rules?|system\s+prompt|internal\s+rules?|internal\s+instructions?|your\s+rules?|the\s+rules?)",
     "System rules disclosure attempt", Severity.HIGH),

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
    (r"(enable|unlock|activate|enter|switch\s+to|go\s+into)\s+(developer|admin|god|root|debug|maintenance|test|unrestricted)\s+mode",
     "Privilege escalation / mode-switching", Severity.HIGH),
    (r"override\s+(safety|content|ethical|moral)\s+(filter|guideline|policy|constraint)",
     "Safety override attempt", Severity.CRITICAL),
    (r"override\s+(?:\w+\s+){0,2}(rules?|policies|guidelines?|instructions?|restrictions?)",
     "Rules override attempt", Severity.HIGH),

    # ── Extended patterns for comprehensive T001-T1000 coverage ──────────────

    # Forget-based instruction override
    (r"forget\s+(?:\w+\s+){0,3}(rules?|polic(?:y|ies)|guidelines?|instructions?|constraints?|everything|all)",
     "Forget-based instruction override", Severity.HIGH),

    # Direct prompt / rules / instructions extraction (any form of verb)
    (r"(print|show(?:ing)?|display|reveal|output|repeat|give\s+me|list|expose)\s+(?:me\s+)?(?:your\s+)?(?:hidden\s+|internal\s+|current\s+|secret\s+|the\s+|all\s+)?(rules?|guardrails?|prompt|restrictions?|instructions?)",
     "Direct rules/prompt extraction", Severity.HIGH),

    # Standalone "system prompt" mention (extraction/probing without explicit verb)
    (r"\b(system\s+prompt|your\s+prompt|your\s+instructions|your\s+rules|your\s+guidelines)\b",
     "System prompt / instruction reference", Severity.MEDIUM),

    # Reveal/show/expose secrets or everything
    (r"(reveal|show|expose|give\s+me|tell\s+me)\s+(?:me\s+)?(?:your\s+)?(?:hidden\s+|secret\s+|all\s+the\s+|all\s+)?(everything|secrets?|all\s+data)",
     "General secret/everything extraction", Severity.HIGH),

    # Reveal instructions (without hidden/internal qualifier)
    (r"(reveal|show|repeat|print|output|give\s+me)\s+(?:your\s+|the\s+)?(?:full\s+)?instructions?\b",
     "Instructions extraction attempt", Severity.HIGH),

    # Broad ignore: "ignore everything"
    (r"ignore\s+(everything|all\s+rules?|all\s+polic(?:y|ies)|all\s+guidelines?|all\s+restrictions?|all\s+[\w\s,]*\b(rules?|restrictions?|limits?))",
     "Broad instruction override", Severity.CRITICAL),

    # Authority impersonation — manager, owner, boss
    (r"(i'?m|i\s+am)\s+(?:the\s+)?(manager|supervisor|platform\s+owner|owner|ceo|boss|director|executive|founder|compliance\s+officer)",
     "Authority impersonation attempt", Severity.HIGH),

    # Translate/encode/format/return prompt extraction
    (r"(translate|encode|convert|put|format|write|output|return|give)\s+(?:\w+\s+){0,2}(your\s+)?(prompt|instructions?|rules?|guidelines?)\s+(in|as|into|using|to)\b",
     "Format-based prompt extraction", Severity.HIGH),

    # Translate your hidden/system prompt (no destination required)
    (r"translate\s+(?:\w+\s+){0,2}(your\s+)?(system\s+prompt|hidden\s+prompt|hidden\s+instructions?|prompt)",
     "Translation-based prompt extraction", Severity.HIGH),

    # First/last line extraction
    (r"(first|last)\s+line\s+of\s+(?:your\s+)?(prompt|instructions?|rules?|setup|configuration)",
     "Prompt line extraction", Severity.HIGH),

    # "Show me secrets / give me secrets" forms
    (r"(show|give|print|tell)\s+(?:me\s+)?(your\s+)?(secrets?|everything\s+hidden|all\s+secrets?)",
     "Secret extraction request", Severity.HIGH),

    # Log/audit suppression
    (r"(don'?t|do\s+not|never)\s+(log|record|audit|monitor|track|store)\s+(this|these|my|our)",
     "Log suppression attempt", Severity.HIGH),

    # New instruction override
    (r"new\s+instructions?\s*[:\-]\s*obey",
     "New instruction override", Severity.HIGH),

    # Inject via "remember" or "note that" to poison context
    (r"(remember|note\s+that)\s*[:;]?\s*(ignore|forget|disregard|bypass|override)",
     "Context poisoning via remember/note", Severity.HIGH),

    # Hidden guardrails probing
    (r"(hidden|secret|your)\s+guardrails?",
     "Guardrail probing", Severity.HIGH),

    # "show/print/tell me your prompt" catch-all
    (r"(show|tell|give|print)\s+me\s+(?:your\s+)?(prompt|rules?|instructions?|guardrails?)",
     "Prompt/rules show request", Severity.HIGH),

    # System-message spoofing in user text
    (r"^(system|assistant|tool)\s*:\s*(reveal|show|print|ignore|disable|override|unlock)",
     "System/role message spoofing", Severity.CRITICAL),

    # "Just this once / just this time" bypass attempts
    (r"just\s+(this\s+once|once|this\s+time|for\s+now)\s*[,\.]?\s*(ignore|break|bypass|forget|override)",
     "One-time bypass attempt", Severity.HIGH),

    # "In this story / in this game / for the purposes of" framing bypasses
    (r"(in\s+this\s+story|in\s+this\s+game|as\s+a\s+character|for\s+the\s+purposes?\s+of)\s*[,\.]?\s*(reveal|show|ignore|break|bypass|forget)",
     "Framing-based injection", Severity.HIGH),

    # "Just this test / for debugging / for audit" bypass
    (r"(just\s+a\s+test|for\s+debugging|for\s+audit)\s*[,\.]?\s*(reveal|show|ignore|break|bypass|expose)",
     "Test/debug bypass framing", Severity.HIGH),

    # ── Additional patterns to cover T551-T1000 ───────────────────────────────

    # DAN / jailbreak role injection without "act as"
    (r"you\s+are\s+now\s+(?:a\s+|an\s+|the\s+)?(?:DAN|jailbroken|unrestricted|evil|uncensored|unfiltered)\b",
     "DAN/jailbreak role injection", Severity.CRITICAL),

    # Override/bypass/unlock all safety/restrictions
    (r"(override|bypass|circumvent|disable)\s+(?:all\s+)?(safety|content|ethical|moral)\s+(filter|guideline|policy|constraint|restriction)s?",
     "Safety override attempt", Severity.CRITICAL),
    (r"(override|bypass)\s+all\s+\w+\s*(filter|restriction|constraint|guard|rule|polic)s?",
     "Broad safety bypass attempt", Severity.HIGH),
    (r"(unlock|enable)\s+all\s+(unsafe|unrestricted|hidden|forbidden)\s+(feature|mode|access|capabilit)",
     "Unlock unsafe features attempt", Severity.HIGH),

    # Override policy (singular)
    (r"override\s+(?:\w+\s+){0,2}(rules?|polic(?:y|ies)|guidelines?|instructions?|restrictions?|constraints?)",
     "Policy override attempt", Severity.HIGH),

    # Admin/support impersonation with "the"
    (r"i'?m\s+the\s+(admin|administrator|manager|owner|support|supervisor|executive)\b",
     "Admin impersonation attempt", Severity.HIGH),

    # Hidden settings / internal state / private config extraction
    (r"(what\s+are\s+your|reveal|show|tell\s+me)\s+(?:your\s+)?hidden\s+(settings?|configuration?|parameters?|state|data)",
     "Hidden settings extraction", Severity.HIGH),
    (r"(tell\s+me|reveal|show)\s+(?:your\s+|the\s+)?internal\s+(state|config|settings?|data|prompt|instructions?)",
     "Internal state extraction", Severity.HIGH),
    (r"(reveal|show|print|display)\s+(?:your\s+|the\s+)?private\s+(configuration|config|settings?|data|prompt)",
     "Private config extraction", Severity.HIGH),
    (r"(show|display|reveal|print)\s+(?:your\s+|the\s+)?(?:system\s+)?configuration\s+(details?|settings?|data)?",
     "Configuration details extraction", Severity.HIGH),
    (r"(print|reveal|show)\s+(?:your\s+|the\s+)?initial\s+(instructions?|prompt|configuration|setup)",
     "Initial instructions extraction", Severity.HIGH),

    # Credential/token probing extended (cover display verb, bearer token, auth token)
    (r"(display|show|give|reveal|print|list)\s+(?:your\s+|the\s+)?(?:auth(?:entication)?\s+)?(token|tokens?|api\s+key|api\s+secret|credentials?)\b",
     "Credential extraction via display", Severity.CRITICAL),
    (r"what\s+is\s+your\s+(?:bearer\s+)?(token|password|api\s+key|secret|passphrase|credential)\b",
     "Credential probing (what is your token)", Severity.HIGH),
    (r"what\s+password\s+do\s+you\s+(use|have|store|know)\b",
     "Password probing", Severity.HIGH),
    (r"\b(bearer\s+token|auth(?:entication)?\s+token|api\s+secret)s?\b",
     "Token reference in input", Severity.HIGH),
    (r"(display|show)\s+api\s+(secret|key|token|credentials?)",
     "API secret display attempt", Severity.HIGH),

    # Unlock all restrictions
    (r"(unlock|remove|disable|bypass)\s+all\s+(restrictions?|constraints?|limitations?|rules?|guidelines?|filters?)",
     "Unlock all restrictions attempt", Severity.HIGH),

    # General bypass without requiring "all" — covers "bypass screening rules", "bypass auth rules"
    (r"(bypass|circumvent)\s+(?:[\w\-]+\s+){0,3}(rules?|restrictions?|auth(?:entication)?|polic(?:y|ies)|guidelines?|filter|check|safet|guard|screening)",
     "General bypass attempt", Severity.HIGH),

    # Extract/exfiltrate data — "extract all customer context"
    (r"(extract|exfiltrate)\s+(?:all\s+)?(?:[\w]+\s+){0,3}(context|data|information|records?|details?|list)",
     "Data extraction attempt", Severity.HIGH),

    # Reveal config/policy/settings — covers "reveal my config", "reveal queue config", "reveal queue policy"
    (r"(reveal|expose)\s+(?:[\w]+\s+){0,3}(config(?:uration)?|settings?|polic(?:y|ies)|setup|queue\s+config|subscriber\s+list|filters?|output\s+filters?)",
     "Config/policy reveal attempt", Severity.HIGH),

    # "rule override" (reverse order)
    (r"\brule\s+override\b",
     "Rule override injection", Severity.HIGH),

    # CLI flag override e.g. --override-safety
    (r"--override[\-\w]*",
     "CLI override flag injection", Severity.HIGH),

    # ignore_rules=true query param form
    (r"ignore[\s_]rules\s*=\s*(true|1|yes)",
     "Query param instruction override", Severity.HIGH),

    # Override fact-checking / real fact checks
    (r"override\s+(?:[\w\-]+\s+){0,2}fact[\s\-]check",
     "Fact-check override attempt", Severity.HIGH),

    # Bypass content rules (T540)
    (r"bypass\s+(?:[\w]+\s+){0,2}content\s+(rules?|filter|polic(?:y|ies)|restriction)",
     "Content rules bypass attempt", Severity.HIGH),
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
