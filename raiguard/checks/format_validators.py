"""
Format validators — structural / syntactic checks on LLM outputs.

Covers: Valid JSON, Valid HTML, Valid SQL, Valid Python, Valid URL,
        Valid Length, Valid Range, Valid Choices, Regex Match,
        Contains String, Ends With, One Line, Reading Time,
        Uppercase, Lowercase, Two Words.
"""

from __future__ import annotations

import json
import re
import urllib.parse
from typing import Any

from raiguard.checks.base import BaseCheck, CheckResult, Severity


class ValidJSONCheck(BaseCheck):
    """Validates that the LLM output is parseable as valid JSON."""

    name = "valid_json"
    description = "Ensure LLM output is parseable as valid JSON."
    owasp_refs = ["LLM02"]
    eu_ai_act_refs = []

    def check_input(self, text: str, context: dict[str, Any] | None = None) -> CheckResult:
        return self._validate(text)

    def check_output(self, text: str, prompt: str = "", context: dict[str, Any] | None = None) -> CheckResult:
        return self._validate(text)

    def _validate(self, text: str) -> CheckResult:
        try:
            json.loads(text.strip())
            return self._make_result(True, 0.0, Severity.LOW)
        except (json.JSONDecodeError, ValueError) as exc:
            return self._make_result(
                False, 1.0, Severity.HIGH,
                details={"error": str(exc)},
                remediation="Output must be valid JSON. Ensure all keys are quoted and values are properly formatted.",
            )


class ValidHTMLCheck(BaseCheck):
    """Validates that the LLM output contains valid/parseable HTML."""

    name = "valid_html"
    description = "Ensure LLM output is parseable as valid HTML."
    owasp_refs = ["LLM02"]
    eu_ai_act_refs = []

    def check_input(self, text: str, context: dict[str, Any] | None = None) -> CheckResult:
        return self._validate(text)

    def check_output(self, text: str, prompt: str = "", context: dict[str, Any] | None = None) -> CheckResult:
        return self._validate(text)

    def _validate(self, text: str) -> CheckResult:
        from html.parser import HTMLParser

        class _Validator(HTMLParser):
            def __init__(self) -> None:
                super().__init__()
                self.error: str = ""

            def handle_error(self, message: str) -> None:  # type: ignore[override]
                self.error = message

        parser = _Validator()
        try:
            parser.feed(text)
            parser.close()
        except Exception as exc:
            return self._make_result(
                False, 1.0, Severity.HIGH,
                details={"error": str(exc)},
                remediation="Output must be valid HTML.",
            )
        if parser.error:
            return self._make_result(
                False, 0.8, Severity.MEDIUM,
                details={"error": parser.error},
                remediation="Output contains malformed HTML.",
            )
        return self._make_result(True, 0.0, Severity.LOW)


class ValidSQLCheck(BaseCheck):
    """
    Validates that the LLM output is syntactically correct SQL.
    Uses Python's built-in sqlite3 for lightweight parsing (explain only).
    """

    name = "valid_sql"
    description = "Validate that LLM-generated SQL is syntactically correct."
    owasp_refs = ["LLM02"]
    eu_ai_act_refs = []

    def check_input(self, text: str, context: dict[str, Any] | None = None) -> CheckResult:
        return self._validate(text)

    def check_output(self, text: str, prompt: str = "", context: dict[str, Any] | None = None) -> CheckResult:
        return self._validate(text)

    def _validate(self, text: str) -> CheckResult:
        import sqlite3
        sql = text.strip()
        conn = sqlite3.connect(":memory:")
        try:
            conn.execute(f"EXPLAIN {sql}")
            return self._make_result(True, 0.0, Severity.LOW)
        except sqlite3.OperationalError as exc:
            return self._make_result(
                False, 1.0, Severity.HIGH,
                details={"error": str(exc)},
                remediation="Output is not valid SQL. Review syntax.",
            )
        finally:
            conn.close()


class ValidPythonCheck(BaseCheck):
    """Validates that the LLM output is syntactically correct Python code."""

    name = "valid_python"
    description = "Validate that LLM-generated Python is syntactically correct."
    owasp_refs = ["LLM02"]
    eu_ai_act_refs = []

    def check_input(self, text: str, context: dict[str, Any] | None = None) -> CheckResult:
        return self._validate(text)

    def check_output(self, text: str, prompt: str = "", context: dict[str, Any] | None = None) -> CheckResult:
        return self._validate(text)

    def _validate(self, text: str) -> CheckResult:
        # Strip markdown code fences if present
        code = re.sub(r"^```(?:python)?\n?", "", text.strip())
        code = re.sub(r"\n?```$", "", code)
        try:
            compile(code, "<string>", "exec")
            return self._make_result(True, 0.0, Severity.LOW)
        except SyntaxError as exc:
            return self._make_result(
                False, 1.0, Severity.HIGH,
                details={"error": str(exc), "line": exc.lineno},
                remediation=f"Python syntax error at line {exc.lineno}: {exc.msg}",
            )


class ValidURLCheck(BaseCheck):
    """Validates that a string is a syntactically valid URL."""

    name = "valid_url"
    description = "Ensure the output is a syntactically valid URL."
    owasp_refs = []
    eu_ai_act_refs = []

    def __init__(self, require_https: bool = False) -> None:
        self.require_https = require_https

    def check_input(self, text: str, context: dict[str, Any] | None = None) -> CheckResult:
        return self._validate(text.strip())

    def check_output(self, text: str, prompt: str = "", context: dict[str, Any] | None = None) -> CheckResult:
        return self._validate(text.strip())

    def _validate(self, url: str) -> CheckResult:
        try:
            parsed = urllib.parse.urlparse(url)
            if not (parsed.scheme and parsed.netloc):
                raise ValueError("Missing scheme or netloc")
            if self.require_https and parsed.scheme != "https":
                return self._make_result(
                    False, 0.8, Severity.MEDIUM,
                    details={"url": url, "scheme": parsed.scheme},
                    remediation="URL must use HTTPS.",
                )
            return self._make_result(True, 0.0, Severity.LOW)
        except Exception as exc:
            return self._make_result(
                False, 1.0, Severity.HIGH,
                details={"error": str(exc), "url": url},
                remediation="Value is not a valid URL.",
            )


class ValidLengthCheck(BaseCheck):
    """Ensures the length of a string falls between a minimum and maximum."""

    name = "valid_length"
    description = "Ensure output length falls within min/max bounds."
    owasp_refs = []
    eu_ai_act_refs = []

    def __init__(self, min_length: int = 0, max_length: int = 10_000) -> None:
        self.min_length = min_length
        self.max_length = max_length

    def check_input(self, text: str, context: dict[str, Any] | None = None) -> CheckResult:
        return self._validate(text)

    def check_output(self, text: str, prompt: str = "", context: dict[str, Any] | None = None) -> CheckResult:
        return self._validate(text)

    def _validate(self, text: str) -> CheckResult:
        length = len(text)
        if self.min_length <= length <= self.max_length:
            return self._make_result(True, 0.0, Severity.LOW, details={"length": length})
        score = 1.0
        remediation = (
            f"Length {length} is outside allowed range [{self.min_length}, {self.max_length}]."
        )
        return self._make_result(False, score, Severity.MEDIUM, details={"length": length}, remediation=remediation)


class ValidChoicesCheck(BaseCheck):
    """Validates that the output is one of a set of allowed choices."""

    name = "valid_choices"
    description = "Ensure output is one of the allowed choices."
    owasp_refs = []
    eu_ai_act_refs = []

    def __init__(self, choices: list[str], case_sensitive: bool = False) -> None:
        self.case_sensitive = case_sensitive
        self.choices = choices if case_sensitive else [c.lower() for c in choices]

    def check_input(self, text: str, context: dict[str, Any] | None = None) -> CheckResult:
        return self._validate(text)

    def check_output(self, text: str, prompt: str = "", context: dict[str, Any] | None = None) -> CheckResult:
        return self._validate(text)

    def _validate(self, text: str) -> CheckResult:
        value = text.strip() if self.case_sensitive else text.strip().lower()
        if value in self.choices:
            return self._make_result(True, 0.0, Severity.LOW)
        return self._make_result(
            False, 1.0, Severity.MEDIUM,
            details={"value": text.strip(), "allowed": self.choices},
            remediation=f"Value must be one of: {', '.join(self.choices)}",
        )


class RegexMatchCheck(BaseCheck):
    """Ensures the output matches a provided regular expression."""

    name = "regex_match"
    description = "Ensure output matches a provided regular expression."
    owasp_refs = []
    eu_ai_act_refs = []

    def __init__(self, pattern: str, full_match: bool = False) -> None:
        self.pattern = pattern
        self.full_match = full_match
        self._compiled = re.compile(pattern)

    def check_input(self, text: str, context: dict[str, Any] | None = None) -> CheckResult:
        return self._validate(text)

    def check_output(self, text: str, prompt: str = "", context: dict[str, Any] | None = None) -> CheckResult:
        return self._validate(text)

    def _validate(self, text: str) -> CheckResult:
        matched = self._compiled.fullmatch(text) if self.full_match else self._compiled.search(text)
        if matched:
            return self._make_result(True, 0.0, Severity.LOW)
        return self._make_result(
            False, 1.0, Severity.MEDIUM,
            details={"pattern": self.pattern},
            remediation=f"Output does not match required pattern: {self.pattern}",
        )


class ContainsStringCheck(BaseCheck):
    """Validates that the output contains a required substring."""

    name = "contains_string"
    description = "Ensure output contains a required substring."
    owasp_refs = []
    eu_ai_act_refs = []

    def __init__(self, substring: str, case_sensitive: bool = False) -> None:
        self.substring = substring
        self.case_sensitive = case_sensitive

    def check_input(self, text: str, context: dict[str, Any] | None = None) -> CheckResult:
        return self._validate(text)

    def check_output(self, text: str, prompt: str = "", context: dict[str, Any] | None = None) -> CheckResult:
        return self._validate(text)

    def _validate(self, text: str) -> CheckResult:
        haystack = text if self.case_sensitive else text.lower()
        needle = self.substring if self.case_sensitive else self.substring.lower()
        if needle in haystack:
            return self._make_result(True, 0.0, Severity.LOW)
        return self._make_result(
            False, 1.0, Severity.MEDIUM,
            details={"required_substring": self.substring},
            remediation=f"Output must contain: '{self.substring}'",
        )


class EndsWithCheck(BaseCheck):
    """Validates that the output ends with a specified string."""

    name = "ends_with"
    description = "Ensure output ends with a specified string."
    owasp_refs = []
    eu_ai_act_refs = []

    def __init__(self, suffix: str, case_sensitive: bool = False) -> None:
        self.suffix = suffix
        self.case_sensitive = case_sensitive

    def check_input(self, text: str, context: dict[str, Any] | None = None) -> CheckResult:
        return self._validate(text)

    def check_output(self, text: str, prompt: str = "", context: dict[str, Any] | None = None) -> CheckResult:
        return self._validate(text)

    def _validate(self, text: str) -> CheckResult:
        haystack = text.strip() if self.case_sensitive else text.strip().lower()
        needle = self.suffix if self.case_sensitive else self.suffix.lower()
        if haystack.endswith(needle):
            return self._make_result(True, 0.0, Severity.LOW)
        return self._make_result(
            False, 1.0, Severity.MEDIUM,
            details={"required_suffix": self.suffix},
            remediation=f"Output must end with: '{self.suffix}'",
        )


class OneLineCheck(BaseCheck):
    """Validates that the output is a single line of text (no newlines)."""

    name = "one_line"
    description = "Ensure output is a single line of text."
    owasp_refs = []
    eu_ai_act_refs = []

    def check_input(self, text: str, context: dict[str, Any] | None = None) -> CheckResult:
        return self._validate(text)

    def check_output(self, text: str, prompt: str = "", context: dict[str, Any] | None = None) -> CheckResult:
        return self._validate(text)

    def _validate(self, text: str) -> CheckResult:
        lines = [ln for ln in text.splitlines() if ln.strip()]
        if len(lines) <= 1:
            return self._make_result(True, 0.0, Severity.LOW)
        return self._make_result(
            False, 1.0, Severity.LOW,
            details={"line_count": len(lines)},
            remediation="Output must be a single line.",
        )

    def fix(self, text: str) -> str:
        """Collapse multi-line output to a single line."""
        return " ".join(ln.strip() for ln in text.splitlines() if ln.strip())


class ReadingTimeCheck(BaseCheck):
    """
    Ensures generated text is less than a maximum reading time.
    Assumes average reading speed of 238 words per minute (research average).
    """

    name = "reading_time"
    description = "Ensure output reading time is within the specified maximum (minutes)."
    owasp_refs = []
    eu_ai_act_refs = []

    _WPM = 238  # average adult reading speed

    def __init__(self, max_minutes: float = 5.0) -> None:
        self.max_minutes = max_minutes

    def check_input(self, text: str, context: dict[str, Any] | None = None) -> CheckResult:
        return self._validate(text)

    def check_output(self, text: str, prompt: str = "", context: dict[str, Any] | None = None) -> CheckResult:
        return self._validate(text)

    def _validate(self, text: str) -> CheckResult:
        word_count = len(text.split())
        minutes = word_count / self._WPM
        if minutes <= self.max_minutes:
            return self._make_result(
                True, 0.0, Severity.LOW,
                details={"word_count": word_count, "estimated_minutes": round(minutes, 2)},
            )
        score = min(1.0, (minutes - self.max_minutes) / self.max_minutes)
        return self._make_result(
            False, score, Severity.LOW,
            details={"word_count": word_count, "estimated_minutes": round(minutes, 2), "max_minutes": self.max_minutes},
            remediation=f"Output takes ~{minutes:.1f} min to read, exceeds {self.max_minutes} min limit.",
        )


class UppercaseCheck(BaseCheck):
    """Passes when the output is entirely uppercase."""

    name = "uppercase"
    description = "Validate that the output is entirely uppercase."
    owasp_refs = []
    eu_ai_act_refs = []

    def check_input(self, text: str, context: dict[str, Any] | None = None) -> CheckResult:
        return self._validate(text)

    def check_output(self, text: str, prompt: str = "", context: dict[str, Any] | None = None) -> CheckResult:
        return self._validate(text)

    def _validate(self, text: str) -> CheckResult:
        if text == text.upper():
            return self._make_result(True, 0.0, Severity.LOW)
        return self._make_result(
            False, 1.0, Severity.LOW,
            remediation="Output must be entirely uppercase.",
        )

    def fix(self, text: str) -> str:
        return text.upper()


class LowercaseCheck(BaseCheck):
    """Passes when the output is entirely lowercase."""

    name = "lowercase"
    description = "Validate that the output is entirely lowercase."
    owasp_refs = []
    eu_ai_act_refs = []

    def check_input(self, text: str, context: dict[str, Any] | None = None) -> CheckResult:
        return self._validate(text)

    def check_output(self, text: str, prompt: str = "", context: dict[str, Any] | None = None) -> CheckResult:
        return self._validate(text)

    def _validate(self, text: str) -> CheckResult:
        if text == text.lower():
            return self._make_result(True, 0.0, Severity.LOW)
        return self._make_result(
            False, 1.0, Severity.LOW,
            remediation="Output must be entirely lowercase.",
        )

    def fix(self, text: str) -> str:
        return text.lower()


class TwoWordsCheck(BaseCheck):
    """Passes when the output is exactly two words."""

    name = "two_words"
    description = "Validate that the output is exactly two words."
    owasp_refs = []
    eu_ai_act_refs = []

    def check_input(self, text: str, context: dict[str, Any] | None = None) -> CheckResult:
        return self._validate(text)

    def check_output(self, text: str, prompt: str = "", context: dict[str, Any] | None = None) -> CheckResult:
        return self._validate(text)

    def _validate(self, text: str) -> CheckResult:
        words = text.strip().split()
        if len(words) == 2:
            return self._make_result(True, 0.0, Severity.LOW)
        return self._make_result(
            False, 1.0, Severity.LOW,
            details={"word_count": len(words)},
            remediation=f"Output must be exactly two words, got {len(words)}.",
        )
