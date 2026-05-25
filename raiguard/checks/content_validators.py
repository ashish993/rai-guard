"""
Content validators — semantic / topic / brand content checks on LLM outputs.

Covers: CompetitorCheck, BanList, RedundantSentences, SensitiveTopic,
        ProfanityFree, BiasCheck, ReadingLevel.
"""

from __future__ import annotations

import re
from typing import Any

from raiguard.checks.base import BaseCheck, CheckResult, Severity


class CompetitorCheckCheck(BaseCheck):
    """
    Flags mentions of competitor names in LLM outputs.
    Fixes responses by filtering out sentences containing competitor names.
    """

    name = "competitor_check"
    description = "Flag and optionally filter mentions of competitor brands."
    owasp_refs = ["LLM09"]
    eu_ai_act_refs = []

    def __init__(self, competitors: list[str] | None = None) -> None:
        # Default well-known AI/tech competitors — callers can override
        self.competitors: list[str] = competitors or [
            "OpenAI", "ChatGPT", "GPT-4", "GPT-3",
            "Anthropic", "Claude",
            "Google", "Gemini", "Bard",
            "Microsoft", "Copilot", "Bing",
            "Meta", "LLaMA", "Llama",
            "Mistral", "Cohere", "AI21",
            "Hugging Face", "Stability AI",
        ]
        self._patterns = [
            re.compile(r"\b" + re.escape(c) + r"\b", re.IGNORECASE)
            for c in self.competitors
        ]

    def check_input(self, text: str, context: dict[str, Any] | None = None) -> CheckResult:
        return self._validate(text)

    def check_output(self, text: str, prompt: str = "", context: dict[str, Any] | None = None) -> CheckResult:
        return self._validate(text)

    def _validate(self, text: str) -> CheckResult:
        found: list[str] = []
        for pattern, name in zip(self._patterns, self.competitors):
            if pattern.search(text):
                found.append(name)
        if not found:
            return self._make_result(True, 0.0, Severity.LOW)
        score = min(1.0, len(found) * 0.3)
        return self._make_result(
            False, score, Severity.MEDIUM,
            details={"competitors_mentioned": found},
            patterns=found,
            remediation="Output mentions competitors. Review and remove competitor references.",
        )

    def fix(self, text: str) -> str:
        """Remove sentences that mention competitors."""
        sentences = re.split(r"(?<=[.!?])\s+", text)
        clean: list[str] = []
        for sentence in sentences:
            if not any(p.search(sentence) for p in self._patterns):
                clean.append(sentence)
        return " ".join(clean).strip() or text


class BanListCheck(BaseCheck):
    """
    Validates that the output does not contain banned words.
    Uses exact word-boundary matching (not fuzzy search, no external deps).
    """

    name = "ban_list"
    description = "Ensure output does not contain banned words."
    owasp_refs = ["LLM08"]
    eu_ai_act_refs = []

    def __init__(self, banned_words: list[str] | None = None, case_sensitive: bool = False) -> None:
        self.case_sensitive = case_sensitive
        self.banned_words: list[str] = banned_words or []
        self._patterns = [
            re.compile(
                r"\b" + re.escape(w) + r"\b",
                0 if case_sensitive else re.IGNORECASE,
            )
            for w in self.banned_words
        ]

    def check_input(self, text: str, context: dict[str, Any] | None = None) -> CheckResult:
        return self._validate(text)

    def check_output(self, text: str, prompt: str = "", context: dict[str, Any] | None = None) -> CheckResult:
        return self._validate(text)

    def _validate(self, text: str) -> CheckResult:
        found: list[str] = [
            word for pattern, word in zip(self._patterns, self.banned_words)
            if pattern.search(text)
        ]
        if not found:
            return self._make_result(True, 0.0, Severity.LOW)
        return self._make_result(
            False, 1.0, Severity.HIGH,
            details={"banned_words_found": found},
            patterns=found,
            remediation=f"Output contains banned words: {', '.join(found)}",
        )

    def fix(self, text: str) -> str:
        """Replace banned words with [FILTERED]."""
        result = text
        for pattern in self._patterns:
            result = pattern.sub("[FILTERED]", result)
        return result


class RedundantSentencesCheck(BaseCheck):
    """
    Identifies highly redundant or duplicated sentences in text.
    Uses token-overlap (Jaccard similarity) — no external ML required.
    """

    name = "redundant_sentences"
    description = "Identify and flag redundant or duplicate sentences in output."
    owasp_refs = []
    eu_ai_act_refs = []

    def __init__(self, similarity_threshold: float = 0.85) -> None:
        self.similarity_threshold = similarity_threshold

    def check_input(self, text: str, context: dict[str, Any] | None = None) -> CheckResult:
        return self._validate(text)

    def check_output(self, text: str, prompt: str = "", context: dict[str, Any] | None = None) -> CheckResult:
        return self._validate(text)

    @staticmethod
    def _tokenize(s: str) -> set[str]:
        return set(re.findall(r"\w+", s.lower()))

    def _jaccard(self, a: str, b: str) -> float:
        ta, tb = self._tokenize(a), self._tokenize(b)
        if not ta or not tb:
            return 0.0
        return len(ta & tb) / len(ta | tb)

    def _validate(self, text: str) -> CheckResult:
        sentences = [s.strip() for s in re.split(r"(?<=[.!?])\s+", text) if s.strip()]
        redundant: list[tuple[int, int, float]] = []
        for i in range(len(sentences)):
            for j in range(i + 1, len(sentences)):
                sim = self._jaccard(sentences[i], sentences[j])
                if sim >= self.similarity_threshold:
                    redundant.append((i, j, round(sim, 3)))
        if not redundant:
            return self._make_result(True, 0.0, Severity.LOW)
        score = min(1.0, len(redundant) * 0.25)
        return self._make_result(
            False, score, Severity.LOW,
            details={"redundant_pairs": redundant},
            remediation="Output contains redundant sentences. Consider condensing.",
        )

    def fix(self, text: str) -> str:
        """Remove duplicate sentences, keeping the first occurrence."""
        sentences = [s.strip() for s in re.split(r"(?<=[.!?])\s+", text) if s.strip()]
        seen: list[str] = []
        for sentence in sentences:
            if not any(self._jaccard(sentence, s) >= self.similarity_threshold for s in seen):
                seen.append(sentence)
        return " ".join(seen)


class SensitiveTopicCheck(BaseCheck):
    """
    Detects sensitive topics in text (politics, religion, health, finance, legal,
    violence, drugs) using keyword pattern matching.
    """

    name = "sensitive_topic"
    description = "Detect sensitive topics (politics, religion, health, etc.) in text."
    owasp_refs = ["LLM08"]
    eu_ai_act_refs = ["Article 9"]

    _TOPICS: list[tuple[str, list[str]]] = [
        ("politics", [
            r"\b(election|vote|democrat|republican|liberal|conservative|president|congress|parliament|legislation|partisan)\b",
        ]),
        ("religion", [
            r"\b(god|allah|jesus|bible|quran|torah|hindu|buddhist|christian|muslim|jew(?:ish)?|atheist|religious)\b",
        ]),
        ("health_medical", [
            r"\b(diagnosis|prescri(?:ption|be)|medication|dosage|treat(?:ment)?|symptom|disease|cancer|HIV|vaccine)\b",
        ]),
        ("financial_advice", [
            r"\b(invest(?:ment)?|stock\s+tip|buy\s+shares|sell\s+shares|insider\s+trading|financial\s+advice|portfolio)\b",
        ]),
        ("legal_advice", [
            r"\b(legal\s+advice|sue|lawsuit|court\s+order|legal\s+liability|contract\s+law|attorney)\b",
        ]),
        ("violence", [
            r"\b(kill|murder|assault|weapon|bomb|terrorist|shoot|stab|attack)\b",
            r"\bbomb\s+blast\b",
            r"\b(terror(?:ist)?\s+attack|suicide\s+bomb|blow\s+up|detonate)\b",
        ]),
        ("drugs", [
            r"\b(cocaine|heroin|fentanyl|methamphetamine|overdose|narcotic|illicit\s+drug)\b",
        ]),
    ]

    def __init__(self, topics: list[str] | None = None) -> None:
        """topics: subset of topic names to check; None means check all."""
        active = set(topics) if topics else None
        self._compiled: list[tuple[str, list[re.Pattern[str]]]] = [
            (topic, [re.compile(pat, re.IGNORECASE) for pat in pats])
            for topic, pats in self._TOPICS
            if active is None or topic in active
        ]

    def check_input(self, text: str, context: dict[str, Any] | None = None) -> CheckResult:
        return self._validate(text)

    def check_output(self, text: str, prompt: str = "", context: dict[str, Any] | None = None) -> CheckResult:
        return self._validate(text)

    def _validate(self, text: str) -> CheckResult:
        triggered: list[str] = []
        for topic, patterns in self._compiled:
            if any(p.search(text) for p in patterns):
                triggered.append(topic)
        if not triggered:
            return self._make_result(True, 0.0, Severity.LOW)
        return self._make_result(
            False, min(1.0, len(triggered) * 0.35), Severity.MEDIUM,
            details={"sensitive_topics": triggered},
            remediation=f"Output contains sensitive topics: {', '.join(triggered)}. Add appropriate disclaimers.",
        )


class ProfanityFreeCheck(BaseCheck):
    """
    Checks for profanity and explicit language in text using a curated
    pattern list (no external library required).
    """

    name = "profanity_free"
    description = "Ensure output contains no profanity or explicit language."
    owasp_refs = ["LLM08"]
    eu_ai_act_refs = []

    # Common profanity terms — intentionally obfuscated here for safety
    _PATTERNS: list[str] = [
        r"\bf+u+c+k+(?:ing|er|ed|s)?\b",
        r"\bs+h+i+t+(?:ty|ter|s)?\b",
        r"\ba+s+s+h+o+l+e+s?\b",
        r"\bb+i+t+c+h+(?:es|ing)?\b",
        r"\bc+u+n+t+s?\b",
        r"\bd+a+m+n+(?:it)?\b",
        r"\bh+e+l+l+\b",
        r"\bcrap\b",
        r"\bbastard\b",
        r"\bdick(?:head)?\b",
        r"\bprick\b",
        r"\bwh+o+r+e+s?\b",
        r"\bslut+s?\b",
        r"\bn+i+g+(?:g+a+|g+e+r+)\b",
        r"\bf+a+g+(?:g+o+t+s?)?\b",
    ]
    _COMPILED = [re.compile(p, re.IGNORECASE) for p in _PATTERNS]

    def check_input(self, text: str, context: dict[str, Any] | None = None) -> CheckResult:
        return self._validate(text)

    def check_output(self, text: str, prompt: str = "", context: dict[str, Any] | None = None) -> CheckResult:
        return self._validate(text)

    def _validate(self, text: str) -> CheckResult:
        found: list[str] = [m.group(0) for p in self._COMPILED for m in p.finditer(text)]
        if not found:
            return self._make_result(True, 0.0, Severity.LOW)
        return self._make_result(
            False, 1.0, Severity.HIGH,
            details={"profanity_count": len(found)},
            remediation="Output contains profanity. Filter before serving to users.",
        )

    def fix(self, text: str) -> str:
        """Replace profanity with asterisks."""
        result = text
        for pattern in self._COMPILED:
            result = pattern.sub(lambda m: m.group(0)[0] + "*" * (len(m.group(0)) - 1), result)
        return result


class BiasCheckCheck(BaseCheck):
    """
    Detects potential bias indicators related to gender, age, ethnicity,
    religion, and disability using keyword pattern matching.
    """

    name = "bias_check"
    description = "Detect potential bias related to gender, age, ethnicity, religion, disability."
    owasp_refs = ["LLM08"]
    eu_ai_act_refs = ["Article 9", "Article 10"]

    _BIAS_PATTERNS: list[tuple[str, str]] = [
        ("gender_bias", r"\b(men\s+are|women\s+are|boys\s+are|girls\s+are|(?:males?|females?)\s+(?:always|never|can'?t|are\s+(?:better|worse|inferior|superior)))\b"),
        ("age_bias", r"\b(old(?:er)?\s+people\s+(?:can'?t|always|never)|millennials?\s+(?:are\s+)?(?:lazy|entitled)|boomers?\s+(?:are|always))\b"),
        ("ethnic_bias", r"\b((?:black|white|asian|hispanic|latino|arab|jewish)\s+people\s+(?:always|never|are\s+(?:all|lazy|criminal|violent)))\b"),
        ("religious_bias", r"\b((?:muslims?|christians?|jews?|hindus?|atheists?)\s+(?:always|never|are\s+(?:all|bad|violent|terrorists?)))\b"),
        ("disability_bias", r"\b((?:disabled|handicapped|retarded|crazy|insane)\s+people\s+(?:can'?t|always|are))\b"),
    ]
    _COMPILED = [(cat, re.compile(pat, re.IGNORECASE)) for cat, pat in _BIAS_PATTERNS]

    def check_input(self, text: str, context: dict[str, Any] | None = None) -> CheckResult:
        return self._validate(text)

    def check_output(self, text: str, prompt: str = "", context: dict[str, Any] | None = None) -> CheckResult:
        return self._validate(text)

    def _validate(self, text: str) -> CheckResult:
        triggered: list[str] = [cat for cat, pattern in self._COMPILED if pattern.search(text)]
        if not triggered:
            return self._make_result(True, 0.0, Severity.LOW)
        return self._make_result(
            False, min(1.0, len(triggered) * 0.4), Severity.HIGH,
            details={"bias_categories": triggered},
            remediation=f"Output may contain biased language in: {', '.join(triggered)}. Review for fairness.",
        )


class ReadingLevelCheck(BaseCheck):
    """
    Checks the reading level of output using the Flesch-Kincaid Grade Level formula.
    Pure Python — no external dependencies.
    """

    name = "reading_level"
    description = "Check that output reading level falls within an acceptable grade range."
    owasp_refs = []
    eu_ai_act_refs = ["Article 13"]  # EU AI Act requires understandable communication

    def __init__(self, min_grade: float = 0.0, max_grade: float = 12.0) -> None:
        self.min_grade = min_grade
        self.max_grade = max_grade

    def check_input(self, text: str, context: dict[str, Any] | None = None) -> CheckResult:
        return self._validate(text)

    def check_output(self, text: str, prompt: str = "", context: dict[str, Any] | None = None) -> CheckResult:
        return self._validate(text)

    @staticmethod
    def _count_syllables(word: str) -> int:
        word = word.lower().strip(".,!?;:'\"")
        if not word:
            return 0
        count = len(re.findall(r"[aeiou]+", word))
        if word.endswith("e") and count > 1:
            count -= 1
        return max(1, count)

    def _flesch_kincaid_grade(self, text: str) -> float:
        words = re.findall(r"\b\w+\b", text)
        sentences = len(re.findall(r"[.!?]+", text)) or 1
        if not words:
            return 0.0
        syllables = sum(self._count_syllables(w) for w in words)
        return 0.39 * (len(words) / sentences) + 11.8 * (syllables / len(words)) - 15.59

    def _validate(self, text: str) -> CheckResult:
        grade = round(self._flesch_kincaid_grade(text), 1)
        if self.min_grade <= grade <= self.max_grade:
            return self._make_result(
                True, 0.0, Severity.LOW,
                details={"grade_level": grade},
            )
        score = min(1.0, abs(grade - self.max_grade) / 10.0) if grade > self.max_grade else min(1.0, abs(self.min_grade - grade) / 5.0)
        return self._make_result(
            False, score, Severity.LOW,
            details={"grade_level": grade, "min_grade": self.min_grade, "max_grade": self.max_grade},
            remediation=f"Reading level grade {grade} is outside range [{self.min_grade}, {self.max_grade}].",
        )
