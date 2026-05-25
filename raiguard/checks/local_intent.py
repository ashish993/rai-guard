"""
Local zero-shot intent classification check — OWASP LLM01 / LLM02 / LLM06.

Uses a HuggingFace NLI model (zero-shot classification pipeline) to classify
the *semantic intent* of a prompt and its conversation history entirely
**locally** — no API calls, no network dependency after the initial model
download.

Zero-shot NLI models understand natural language intent without task-specific
fine-tuning.  They perform significantly better than regex for paraphrased,
indirect, or multi-turn jailbreak attempts.

Multi-turn support
------------------
Pass prior conversation turns via the ``context`` dict::

    check.check_input(text, context={"history": [
        {"role": "user",      "content": "Let's play a roleplay game."},
        {"role": "assistant", "content": "Sure, what would you like?"},
    ]})

The check concatenates history + current message into a single window
(``RAI_LOCAL_INTENT_MAX_CHARS`` chars, default 1 200) so the classifier
evaluates accumulated intent rather than each message in isolation.

Configuration (environment variables)
--------------------------------------
RAI_LOCAL_INTENT_ENABLED     Set to "true" / "1" / "yes" to enable (default: disabled).
RAI_LOCAL_INTENT_MODEL       HuggingFace model id or local path
                             (default: MoritzLaurer/deberta-v3-xsmall-zeroshot-v1.1-all-labels).
RAI_LOCAL_INTENT_THRESHOLD   Minimum NLI entailment score to flag a violation (default: 0.60).
RAI_LOCAL_INTENT_MAX_CHARS   Max characters of concatenated context fed to the model (default: 1200).
RAI_LOCAL_INTENT_DEVICE      Inference device: "cpu", "cuda", "mps" — or leave blank to auto-detect.

Recommended models (accuracy vs. size trade-off)
-------------------------------------------------
~70 MB  (fastest)  MoritzLaurer/deberta-v3-xsmall-zeroshot-v1.1-all-labels
~180 MB (balanced) cross-encoder/nli-deberta-v3-small
~400 MB (best)     facebook/bart-large-mnli
"""

from __future__ import annotations

import logging
import os
import threading
from typing import Any

from raiguard.checks.base import BaseCheck, CheckResult, Severity

logger = logging.getLogger("raiguard.checks.local_intent")

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

_ENABLED: bool = os.getenv("RAI_LOCAL_INTENT_ENABLED", "false").lower() in ("true", "1", "yes")
_MODEL: str = os.getenv(
    "RAI_LOCAL_INTENT_MODEL",
    "MoritzLaurer/deberta-v3-xsmall-zeroshot-v1.1-all-labels",
)
_THRESHOLD: float = float(os.getenv("RAI_LOCAL_INTENT_THRESHOLD", "0.60"))
_MAX_CHARS: int = int(os.getenv("RAI_LOCAL_INTENT_MAX_CHARS", "1200"))
_DEVICE: str | None = os.getenv("RAI_LOCAL_INTENT_DEVICE") or None  # None → auto

# ---------------------------------------------------------------------------
# Candidate labels fed to the NLI classifier
# ---------------------------------------------------------------------------
# These are the *hypothesis* labels the model checks against.
# Phrased as natural-language descriptions — this is what makes zero-shot NLI
# powerful: you change the threat taxonomy without touching the model weights.

_CANDIDATE_LABELS: list[tuple[str, str, Severity]] = [
    # (label sent to model,  internal category name,  severity)
    ("attempt to override or ignore AI system instructions",        "prompt_injection",     Severity.CRITICAL),
    ("jailbreak attempt to remove AI safety constraints",           "jailbreak",            Severity.CRITICAL),
    ("false authority claim to gain elevated system access",        "privilege_escalation", Severity.CRITICAL),
    ("content that dehumanises or incites hatred against a group",  "hate_speech",          Severity.CRITICAL),
    ("instructions or encouragement for violence against people",   "violence",             Severity.CRITICAL),
    ("encouraging or requesting self-harm or suicide methods",      "self_harm",            Severity.CRITICAL),
    ("sexual content involving minors",                             "csam",                 Severity.CRITICAL),
    ("severely offensive, threatening, or harassing language",      "toxicity",             Severity.HIGH),
    ("attempting to extract private personal data or credentials",  "pii_exfiltration",     Severity.HIGH),
    ("targeted personal attack or doxing threat",                   "harassment",           Severity.HIGH),
    ("requesting fabrication of false medical or factual claims",   "misinformation",       Severity.HIGH),
    ("prompt that would produce executable injection payloads",     "insecure_output",      Severity.HIGH),
]

_LABELS_ONLY: list[str] = [label for label, _, _ in _CANDIDATE_LABELS]
_LABEL_TO_META: dict[str, tuple[str, Severity]] = {
    label: (cat, sev) for label, cat, sev in _CANDIDATE_LABELS
}

# ---------------------------------------------------------------------------
# Lazy pipeline loader — loads once, reused across all requests
# ---------------------------------------------------------------------------

_pipeline: Any = None          # transformers pipeline instance
_pipeline_lock = threading.Lock()
_pipeline_error: Exception | None = None  # cached load error so we don't retry infinitely


def _get_pipeline() -> Any:
    global _pipeline, _pipeline_error
    if _pipeline is not None:
        return _pipeline
    if _pipeline_error is not None:
        raise _pipeline_error

    with _pipeline_lock:
        if _pipeline is not None:
            return _pipeline
        try:
            from transformers import pipeline  # type: ignore

            logger.info("Loading local intent model '%s' …", _MODEL)
            kwargs: dict[str, Any] = {"model": _MODEL}
            if _DEVICE:
                kwargs["device"] = _DEVICE
            _pipeline = pipeline("zero-shot-classification", **kwargs)
            logger.info("Local intent model loaded.")
        except Exception as exc:
            _pipeline_error = exc
            raise

    return _pipeline


# ---------------------------------------------------------------------------
# Check implementation
# ---------------------------------------------------------------------------


class LocalIntentCheck(BaseCheck):
    """
    Offline zero-shot intent classifier backed by a local NLI model.

    Understands paraphrased, indirect, and multi-turn jailbreak attempts that
    regex patterns miss — with zero network dependency after the first model
    download (``~/.cache/huggingface/``).

    Enabled via ``RAI_LOCAL_INTENT_ENABLED=true``.  When disabled (default)
    the check returns *passed* immediately with zero latency.
    """

    name = "local_intent"
    description = "Local zero-shot NLI intent classification (no API calls)"
    owasp_refs = ["LLM01", "LLM02", "LLM06"]
    eu_ai_act_refs = ["Article 9", "Article 13"]

    def __init__(self, threshold: float = _THRESHOLD) -> None:
        self._enabled = _ENABLED
        self._threshold = threshold

    # ------------------------------------------------------------------
    # BaseCheck interface
    # ------------------------------------------------------------------

    def check_input(self, text: str, context: dict[str, Any] | None = None) -> CheckResult:
        if not self._enabled:
            return self._make_result(
                passed=True, score=0.0, severity=Severity.LOW,
                details={"status": "disabled"},
            )

        window = self._build_window(text, context)

        try:
            pipe = _get_pipeline()
        except Exception as exc:
            logger.warning("LocalIntentCheck: model unavailable (fail-open): %s", exc)
            return self._make_result(
                passed=True, score=0.0, severity=Severity.LOW,
                details={"status": "model_unavailable", "error": str(exc)},
            )

        try:
            output = pipe(window, _LABELS_ONLY, multi_label=True)
        except Exception as exc:
            logger.warning("LocalIntentCheck: inference error (fail-open): %s", exc)
            return self._make_result(
                passed=True, score=0.0, severity=Severity.LOW,
                details={"status": "inference_error", "error": str(exc)},
            )

        # output: {"labels": [...], "scores": [...]}
        label_scores: dict[str, float] = dict(zip(output["labels"], output["scores"]))

        violations: list[str] = []
        severity_list: list[Severity] = []
        top_score: float = 0.0

        for label, score in label_scores.items():
            if score >= self._threshold:
                category, severity = _LABEL_TO_META[label]
                violations.append(category)
                severity_list.append(severity)
                if score > top_score:
                    top_score = score

        if not violations:
            # Return the highest raw score as an informational signal even when passing
            best_score = max(label_scores.values(), default=0.0)
            return self._make_result(
                passed=True,
                score=round(best_score, 4),
                severity=Severity.LOW,
                details={"top_labels": self._top_n(label_scores, 3)},
            )

        severity = max(
            severity_list,
            key=lambda s: ["low", "medium", "high", "critical"].index(s.value),
        )

        return self._make_result(
            passed=False,
            score=round(top_score, 4),
            severity=severity,
            details={
                "violations": violations,
                "label_scores": self._top_n(label_scores, 5),
            },
            patterns=violations,
            remediation=(
                f"Local intent classifier detected: {', '.join(violations)} "
                f"(score={top_score:.2f}, threshold={self._threshold})"
            ),
        )

    def check_output(self, text: str, prompt: str = "", context: dict[str, Any] | None = None) -> CheckResult:
        return self.check_input(text, context=context)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _build_window(self, text: str, context: dict[str, Any] | None) -> str:
        """
        Concatenate conversation history + current message into a single
        string so the classifier evaluates accumulated intent.

        Format::
            [user] earlier message
            [assistant] earlier reply
            [user] <current text>
        """
        parts: list[str] = []
        if context:
            history: list[dict[str, str]] = context.get("history", [])
            for turn in history:
                role = turn.get("role", "user")
                content = turn.get("content", "")
                parts.append(f"[{role}] {content}")
        parts.append(f"[user] {text}")

        window = "\n".join(parts)
        # Truncate to keep inference fast; take the *tail* so the latest turns
        # are always included (most recent context matters most)
        if len(window) > _MAX_CHARS:
            window = window[-_MAX_CHARS:]
        return window

    @staticmethod
    def _top_n(scores: dict[str, float], n: int) -> dict[str, float]:
        """Return the top-n label→score pairs sorted descending."""
        return dict(sorted(scores.items(), key=lambda kv: kv[1], reverse=True)[:n])
