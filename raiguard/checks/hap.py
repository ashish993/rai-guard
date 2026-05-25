"""
IBM Granite Guardian HAP-38M toxicity check — OWASP LLM02.

Purpose-built 38M-parameter classifier from IBM Research for hate, abuse,
and profanity (HAP) detection. Compressed 4-layer RoBERTa architecture
achieves <10ms CPU latency while outperforming the full 125M-parameter
RoBERTa-base on HAP benchmarks.

When enabled this check augments (not replaces) the regex ToxicityCheck —
the regex pass catches obvious patterns before the model is invoked.

Model:   ibm-granite/granite-guardian-hap-38m
License: Apache 2.0
Size:    ~38 MB  (38.5M parameters)

Configuration (environment variables)
--------------------------------------
RAI_HAP_ENABLED     Enable check. "true" / "1" / "yes" (default: false — opt-in).
RAI_HAP_MODEL       HuggingFace model id or local path.
                    Default: ibm-granite/granite-guardian-hap-38m
RAI_HAP_THRESHOLD   Probability at/above which content is flagged. Default: 0.50.
RAI_HAP_DEVICE      Inference device: "cpu", "cuda", "mps". Default: auto-detect.
"""

from __future__ import annotations

import logging
import os
import threading
from typing import Any

from raiguard.checks.base import BaseCheck, CheckResult, Severity

logger = logging.getLogger("raiguard.checks.hap")

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

_ENABLED: bool = os.getenv("RAI_HAP_ENABLED", "false").lower() in ("true", "1", "yes")
_MODEL: str = os.getenv("RAI_HAP_MODEL", "ibm-granite/granite-guardian-hap-38m")
_THRESHOLD: float = float(os.getenv("RAI_HAP_THRESHOLD", "0.50"))
_DEVICE: str | None = os.getenv("RAI_HAP_DEVICE") or None  # None → auto

# ---------------------------------------------------------------------------
# Lazy pipeline singleton
# ---------------------------------------------------------------------------

_pipeline = None  # type: ignore[var-annotated]
_pipeline_lock = threading.Lock()
_pipeline_failed = False  # once loading fails, don't retry on every request


def _get_pipeline():
    """Load (or return cached) HuggingFace text-classification pipeline."""
    global _pipeline, _pipeline_failed
    if _pipeline is not None or _pipeline_failed:
        return _pipeline

    with _pipeline_lock:
        if _pipeline is not None or _pipeline_failed:
            return _pipeline
        try:
            import torch
            from transformers import (
                AutoModelForSequenceClassification,
                AutoTokenizer,
                pipeline,
            )

            device = _DEVICE
            if device is None:
                if torch.cuda.is_available():
                    device = "cuda"
                elif (
                    hasattr(torch.backends, "mps")
                    and torch.backends.mps.is_available()
                ):
                    device = "mps"
                else:
                    device = "cpu"

            tokenizer = AutoTokenizer.from_pretrained(_MODEL)
            model = AutoModelForSequenceClassification.from_pretrained(_MODEL)
            _pipeline = pipeline(
                "text-classification",
                model=model,
                tokenizer=tokenizer,
                device=device,
                truncation=True,
                max_length=512,
            )
            logger.info(
                "HAP-38M pipeline loaded on %s (model=%s, threshold=%.2f)",
                device,
                _MODEL,
                _THRESHOLD,
            )
        except Exception as exc:  # pragma: no cover
            logger.warning(
                "HAP-38M pipeline unavailable: %s — check will fail-open", exc
            )
            _pipeline_failed = True

    return _pipeline


# ---------------------------------------------------------------------------
# Check class
# ---------------------------------------------------------------------------


class GraniteHAPCheck(BaseCheck):
    """
    IBM Granite Guardian HAP-38M — hate, abuse, profanity binary classifier.

    <10ms CPU latency makes it suitable as an inline request/response guard.
    Fails open (pass=True) if transformers/torch are absent or the model
    download fails.

    The model outputs:
      LABEL_1 / score = P(text is HAP) — labelled as *unsafe*
      LABEL_0 / score = P(text is safe) — labelled as *safe*
    """

    name = "hap"
    description = "IBM Granite HAP-38M — hate, abuse, profanity classifier"
    owasp_refs = ["LLM02"]
    eu_ai_act_refs = ["Article 9", "Article 13"]

    def __init__(self) -> None:
        self._enabled = _ENABLED

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _run(self, text: str) -> CheckResult:
        if not self._enabled:
            return self._make_result(
                passed=True,
                score=0.0,
                severity=Severity.LOW,
                details={"reason": "disabled"},
            )

        if not text or not text.strip():
            return self._make_result(passed=True, score=0.0, severity=Severity.LOW)

        pipe = _get_pipeline()
        if pipe is None:
            return self._make_result(
                passed=True,
                score=0.0,
                severity=Severity.LOW,
                details={"reason": "model_unavailable"},
            )

        try:
            # Truncate very long inputs before sending to the pipeline
            output = pipe(text[:2048])
            label: str = output[0]["label"]       # "LABEL_0" | "LABEL_1"
            raw_score: float = output[0]["score"]  # P(label)

            # LABEL_1 → toxic;  LABEL_0 → safe
            is_toxic = label in ("LABEL_1", "1")

            # Normalise to a risk score: P(toxic)
            risk_score = raw_score if is_toxic else 1.0 - raw_score

            passed = not is_toxic or risk_score < _THRESHOLD
            severity = (
                Severity.CRITICAL
                if risk_score >= 0.80
                else (Severity.HIGH if risk_score >= 0.60 else Severity.MEDIUM)
            )

            return self._make_result(
                passed=passed,
                score=round(risk_score, 4),
                severity=severity if not passed else Severity.LOW,
                details={"label": label, "raw_score": raw_score, "model": _MODEL},
                remediation=(
                    "Content detected as hateful, abusive, or profane."
                    if not passed
                    else ""
                ),
            )
        except Exception as exc:  # pragma: no cover
            logger.warning("HAP check inference error: %s — fail open", exc)
            return self._make_result(
                passed=True,
                score=0.0,
                severity=Severity.LOW,
                details={"error": str(exc)},
            )

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def check_input(
        self, text: str, context: dict[str, Any] | None = None
    ) -> CheckResult:
        return self._run(text)

    def check_output(
        self, text: str, prompt: str = "", context: dict[str, Any] | None = None
    ) -> CheckResult:
        return self._run(text)
