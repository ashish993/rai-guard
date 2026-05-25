"""
ProtectAI DeBERTa-v3-base prompt injection ML check — OWASP LLM01.

Binary classifier fine-tuned on 20+ injection attack datasets by ProtectAI.
Recall=99.74% on a held-out test set means only ~0.26% of real injection
attempts pass through undetected.

ONNX Runtime is used automatically when ``optimum[onnxruntime]`` is installed
(~3ms CPU inference). Falls back to the standard PyTorch checkpoint (~25ms)
when optimum is absent.

This check is *additive* to the regex PromptInjectionCheck — the regex pass
catches keyword-obvious patterns before the ML model is invoked.

Model:   protectai/deberta-v3-base-prompt-injection-v2
License: Apache 2.0
Size:    ~183 MB (DeBERTa-v3-base, 184M parameters)

Configuration (environment variables)
--------------------------------------
RAI_INJECTION_ML_ENABLED     Enable check. "true" / "1" / "yes" (default: false).
RAI_INJECTION_ML_MODEL       HuggingFace model id or local path.
                             Default: protectai/deberta-v3-base-prompt-injection-v2
RAI_INJECTION_ML_THRESHOLD   Injection probability above which to flag (default: 0.70).
RAI_INJECTION_ML_DEVICE      Inference device: "cpu", "cuda", "mps". Default: auto.
RAI_INJECTION_ML_USE_ONNX    Set "false" to force PyTorch even when optimum is available.
"""

from __future__ import annotations

import logging
import os
import threading
from typing import Any

from raiguard.checks.base import BaseCheck, CheckResult, Severity

logger = logging.getLogger("raiguard.checks.injection_ml")

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

_ENABLED: bool = os.getenv("RAI_INJECTION_ML_ENABLED", "false").lower() in (
    "true",
    "1",
    "yes",
)
_MODEL: str = os.getenv(
    "RAI_INJECTION_ML_MODEL",
    "protectai/deberta-v3-base-prompt-injection-v2",
)
_THRESHOLD: float = float(os.getenv("RAI_INJECTION_ML_THRESHOLD", "0.70"))
_DEVICE: str | None = os.getenv("RAI_INJECTION_ML_DEVICE") or None
_USE_ONNX: bool = os.getenv("RAI_INJECTION_ML_USE_ONNX", "true").lower() not in (
    "false",
    "0",
    "no",
)

# ---------------------------------------------------------------------------
# Lazy pipeline singleton
# ---------------------------------------------------------------------------

_pipeline = None  # type: ignore[var-annotated]
_pipeline_lock = threading.Lock()
_pipeline_failed = False


def _get_pipeline():
    """Load (or return cached) text-classification pipeline — ONNX first."""
    global _pipeline, _pipeline_failed
    if _pipeline is not None or _pipeline_failed:
        return _pipeline

    with _pipeline_lock:
        if _pipeline is not None or _pipeline_failed:
            return _pipeline

        # ── 1. Try ONNX Runtime (fast path) ──────────────────────────────
        if _USE_ONNX:
            try:
                from optimum.onnxruntime import ORTModelForSequenceClassification  # noqa: F401
                from transformers import AutoTokenizer, pipeline

                tokenizer = AutoTokenizer.from_pretrained(_MODEL, subfolder="onnx")
                # The ONNX export uses only input_ids + attention_mask
                tokenizer.model_input_names = ["input_ids", "attention_mask"]

                from optimum.onnxruntime import ORTModelForSequenceClassification

                model = ORTModelForSequenceClassification.from_pretrained(
                    _MODEL,
                    export=False,
                    subfolder="onnx",
                )
                _pipeline = pipeline(
                    "text-classification",
                    model=model,
                    tokenizer=tokenizer,
                    truncation=True,
                    max_length=512,
                )
                logger.info(
                    "ProtectAI injection check loaded via ONNX Runtime (model=%s)", _MODEL
                )
                return _pipeline
            except ImportError:
                logger.info(
                    "optimum[onnxruntime] not installed — "
                    "falling back to PyTorch for injection ML check"
                )
            except Exception as exc:
                logger.info(
                    "ONNX load failed (%s) — falling back to PyTorch", exc
                )

        # ── 2. PyTorch fallback ───────────────────────────────────────────
        try:
            import torch
            from transformers import (
                AutoModelForSequenceClassification,
                AutoTokenizer,
                pipeline,
            )

            device = _DEVICE
            if device is None:
                device = "cuda" if torch.cuda.is_available() else "cpu"

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
                "ProtectAI injection check loaded via PyTorch (model=%s, device=%s)",
                _MODEL,
                device,
            )
        except Exception as exc:  # pragma: no cover
            logger.warning(
                "ProtectAI injection check unavailable: %s — check will fail-open", exc
            )
            _pipeline_failed = True

    return _pipeline


# ---------------------------------------------------------------------------
# Check class
# ---------------------------------------------------------------------------

# Labels emitted by this model
_INJECTION_LABELS = frozenset({"INJECTION", "LABEL_1", "1"})
_SAFE_LABELS = frozenset({"SAFE", "LEGIT", "LABEL_0", "0"})


class ProtectAIInjectionCheck(BaseCheck):
    """
    ProtectAI DeBERTa-v3-base prompt injection classifier.

    Fine-tuned specifically on injection attack data; Recall=99.74% means
    almost no real injection slips through.  Prefers ONNX Runtime at ~3ms
    CPU latency; PyTorch fallback at ~25ms.

    Fails open (pass=True) when the model cannot be loaded or inference
    raises an unexpected error.
    """

    name = "injection_ml"
    description = "ProtectAI DeBERTa-v3-base prompt injection ML detector"
    owasp_refs = ["LLM01"]
    eu_ai_act_refs = ["Article 9", "Article 15"]

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
            output = pipe(text[:2048])
            label: str = output[0]["label"].upper()
            raw_score: float = output[0]["score"]

            is_injection = label in _INJECTION_LABELS

            # Normalise to risk score: P(injection)
            risk_score = raw_score if is_injection else 1.0 - raw_score

            passed = not is_injection or risk_score < _THRESHOLD
            severity = Severity.CRITICAL if risk_score >= 0.80 else Severity.HIGH

            return self._make_result(
                passed=passed,
                score=round(risk_score, 4),
                severity=severity if not passed else Severity.LOW,
                details={
                    "label": label,
                    "raw_score": raw_score,
                    "model": _MODEL,
                    "backend": "onnx" if _USE_ONNX else "pytorch",
                },
                remediation=(
                    "Prompt injection attack detected by ML classifier."
                    if not passed
                    else ""
                ),
            )
        except Exception as exc:  # pragma: no cover
            logger.warning("ProtectAI injection check error: %s — fail open", exc)
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
        # Injection signals in LLM output can indicate prompt leakage or
        # indirect injection (the model was already compromised upstream).
        return self._run(text)
