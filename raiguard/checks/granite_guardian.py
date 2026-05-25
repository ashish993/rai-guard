"""
IBM Granite Guardian 3.1 2B check — OWASP LLM01 / LLM02 / LLM06 / LLM08.

A 2B-parameter generative safety model from IBM Research, fine-tuned on
human-annotated and red-team data across 13 harm dimensions. Unlike the
regex and lightweight classifier checks, Granite Guardian *understands
semantic context*, making it highly resistant to paraphrased jailbreaks.

Unique capabilities not covered by other checks in this library:
  • RAG hallucination / groundedness   (requires rag_context in context dict)
  • Answer relevance to user question  (output check)
  • Context relevance                  (RAG pipeline quality)
  • Social bias detection

The model generates a single "Yes" (unsafe) / "No" (safe) token. Probabilities
are extracted from the top-k logits of that first generated token rather than
full autoregressive decoding — this keeps latency manageable.

Typical latency
  - CPU BF32:  200–400 ms/request
  - CPU INT4:  80–150 ms/request  (with bitsandbytes)
  - GPU BF16:  15–30  ms/request

Because of the higher latency this check is **disabled by default**. Enable it
explicitly for deployments where semantic precision matters more than speed.

Model:   ibm-granite/granite-guardian-3.1-2b
License: Apache 2.0
Size:    ~4.3 GB BF16  /  ~1.2 GB with 4-bit quantisation

Configuration (environment variables)
--------------------------------------
RAI_GRANITE_GUARDIAN_ENABLED       Enable check. "true" / "1" / "yes" (default: false).
RAI_GRANITE_GUARDIAN_MODEL         HuggingFace model id or local path.
                                   Default: ibm-granite/granite-guardian-3.1-2b
RAI_GRANITE_GUARDIAN_THRESHOLD     Risk probability above which to flag. Default: 0.50.
RAI_GRANITE_GUARDIAN_DEVICE        "cpu" / "cuda" / "mps". Default: auto-detect.
RAI_GRANITE_GUARDIAN_LOAD_IN_4BIT  "true" to use INT4 quantisation via bitsandbytes.
RAI_GRANITE_GUARDIAN_RISKS         Comma-separated risk dimensions to evaluate per request.
                                   Default: "harm"
                                   All options:
                                     harm, jailbreaking, social_bias, violence,
                                     profanity, sexual_content, unethical_behavior,
                                     groundedness, answer_relevance, context_relevance

Risk configuration notes
------------------------
• groundedness and answer_relevance require extra context keys in the
  ``context`` dict passed to check_output():
    - groundedness:     context["rag_context"] = "...retrieved passages..."
    - answer_relevance: context["rag_query"]   = "original user question"
• Risks that require context but are not provided are silently skipped.
• The check returns the *highest* risk score across all evaluated dimensions.
"""

from __future__ import annotations

import logging
import os
import threading
from typing import Any

from raiguard.checks.base import BaseCheck, CheckResult, Severity

logger = logging.getLogger("raiguard.checks.granite_guardian")

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

_ENABLED: bool = os.getenv("RAI_GRANITE_GUARDIAN_ENABLED", "false").lower() in (
    "true",
    "1",
    "yes",
)
_MODEL: str = os.getenv(
    "RAI_GRANITE_GUARDIAN_MODEL", "ibm-granite/granite-guardian-3.1-2b"
)
_THRESHOLD: float = float(os.getenv("RAI_GRANITE_GUARDIAN_THRESHOLD", "0.50"))
_DEVICE: str | None = os.getenv("RAI_GRANITE_GUARDIAN_DEVICE") or None
_LOAD_IN_4BIT: bool = os.getenv("RAI_GRANITE_GUARDIAN_LOAD_IN_4BIT", "false").lower() in (
    "true",
    "1",
    "yes",
)

# Risks to evaluate — comma-separated env var
_DEFAULT_RISKS = ["harm"]
_RISK_ENV = os.getenv("RAI_GRANITE_GUARDIAN_RISKS", "harm")
_RISKS: list[str] = [r.strip() for r in _RISK_ENV.split(",") if r.strip()]

# Risks that require additional context keys to be meaningful
_RAG_RISKS = {"groundedness", "answer_relevance", "context_relevance"}

# Safe / unsafe token strings expected by Granite Guardian
_SAFE_TOKEN = "No"
_UNSAFE_TOKEN = "Yes"

# ---------------------------------------------------------------------------
# Lazy model singleton
# ---------------------------------------------------------------------------

_model_cache: dict[str, Any] = {}  # keys: "model", "tokenizer", "device"
_model_lock = threading.Lock()
_model_failed = False


def _load_model() -> bool:
    """Load the model and tokenizer. Returns True on success."""
    global _model_failed
    if _model_failed:
        return False
    if _model_cache:
        return True

    with _model_lock:
        if _model_cache or _model_failed:
            return bool(_model_cache)

        try:
            import torch
            from transformers import AutoModelForCausalLM, AutoTokenizer

            device = _DEVICE
            if device is None:
                if torch.cuda.is_available():
                    device = "cuda"
                elif hasattr(torch.backends, "mps") and torch.backends.mps.is_available():
                    device = "mps"
                else:
                    device = "cpu"

            tokenizer = AutoTokenizer.from_pretrained(_MODEL)

            load_kwargs: dict[str, Any] = {}
            if _LOAD_IN_4BIT:
                try:
                    from transformers import BitsAndBytesConfig

                    load_kwargs["quantization_config"] = BitsAndBytesConfig(
                        load_in_4bit=True,
                        bnb_4bit_compute_dtype=torch.float16,
                    )
                    load_kwargs["device_map"] = "auto"
                    logger.info("Loading Granite Guardian in INT4 mode")
                except ImportError:
                    logger.warning(
                        "bitsandbytes not installed — INT4 quantisation unavailable. "
                        "Falling back to standard precision."
                    )
            else:
                if device == "cpu":
                    load_kwargs["torch_dtype"] = torch.float32
                else:
                    load_kwargs["torch_dtype"] = torch.bfloat16
                load_kwargs["device_map"] = device

            model = AutoModelForCausalLM.from_pretrained(_MODEL, **load_kwargs)
            model.eval()

            _model_cache["model"] = model
            _model_cache["tokenizer"] = tokenizer
            _model_cache["device"] = device

            logger.info(
                "Granite Guardian 3.1-2B loaded on %s (risks=%s, threshold=%.2f)",
                device,
                _RISKS,
                _THRESHOLD,
            )
            return True

        except Exception as exc:  # pragma: no cover
            logger.warning(
                "Granite Guardian model unavailable: %s — check will fail-open", exc
            )
            _model_failed = True
            return False


# ---------------------------------------------------------------------------
# Inference helper
# ---------------------------------------------------------------------------

_MAX_INPUT_TOKENS = 1024  # truncate to keep latency predictable


def _score_risk(
    tokenizer: Any,
    model: Any,
    messages: list[dict[str, str]],
    guardian_config: dict[str, str],
) -> float:
    """
    Return P(unsafe) for the given messages and risk configuration.

    Uses the Granite Guardian 3.1 chat template which embeds the
    ``guardian_config`` dict to specify which risk to evaluate.
    """
    try:
        import torch

        input_ids = tokenizer.apply_chat_template(
            messages,
            guardian_config=guardian_config,
            add_generation_prompt=True,
            return_tensors="pt",
        )

        # Truncate to avoid OOM on very long inputs
        if input_ids.shape[-1] > _MAX_INPUT_TOKENS:
            input_ids = input_ids[:, -_MAX_INPUT_TOKENS:]

        device = next(model.parameters()).device
        input_ids = input_ids.to(device)

        with torch.no_grad():
            output = model.generate(
                input_ids,
                do_sample=False,
                max_new_tokens=1,
                return_dict_in_generate=True,
                output_scores=True,
            )

        # scores[0] is the logit distribution for the first generated token
        logits: Any = output.scores[0][0]  # shape: [vocab_size]

        safe_id = tokenizer.convert_tokens_to_ids(_SAFE_TOKEN)
        unsafe_id = tokenizer.convert_tokens_to_ids(_UNSAFE_TOKEN)

        import torch.nn.functional as F

        # Softmax over just the two relevant tokens for a calibrated probability
        relevant = torch.tensor(
            [logits[safe_id].item(), logits[unsafe_id].item()],
            dtype=torch.float32,
        )
        probs = F.softmax(relevant, dim=0)
        return float(probs[1])  # P(Yes / unsafe)

    except Exception as exc:  # pragma: no cover
        logger.debug("_score_risk error: %s", exc)
        return 0.0


# ---------------------------------------------------------------------------
# Check class
# ---------------------------------------------------------------------------


class GraniteGuardianCheck(BaseCheck):
    """
    IBM Granite Guardian 3.1 2B — semantic multi-risk safety classifier.

    Evaluates one or more risk dimensions using an LLM's internal
    yes/no token probability. Substantially more robust against paraphrased
    and multi-turn jailbreaks than regex or lightweight classifier checks.

    Fails open (pass=True) on model load failure or inference error.

    Usage tips
    ----------
    • Enable only the risks you need to minimise per-request latency.
    • For RAG pipelines, add context["rag_context"] and context["rag_query"]
      and include "groundedness" and "answer_relevance" in RAI_GRANITE_GUARDIAN_RISKS.
    • The check is thread-safe — the global model singleton is locked during
      first load and reused for all subsequent requests.
    """

    name = "granite_guardian"
    description = "IBM Granite Guardian 3.1-2B semantic multi-risk classifier"
    owasp_refs = ["LLM01", "LLM02", "LLM06", "LLM08"]
    eu_ai_act_refs = ["Article 9", "Article 13", "Article 15"]

    def __init__(self) -> None:
        self._enabled = _ENABLED

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _disabled_result(self) -> CheckResult:
        return self._make_result(
            passed=True,
            score=0.0,
            severity=Severity.LOW,
            details={"reason": "disabled"},
        )

    def _unavailable_result(self) -> CheckResult:
        return self._make_result(
            passed=True,
            score=0.0,
            severity=Severity.LOW,
            details={"reason": "model_unavailable"},
        )

    def _evaluate_risks(
        self,
        messages: list[dict[str, str]],
        risks: list[str],
    ) -> tuple[float, list[str]]:
        """
        Run each risk check and return (max_risk_score, [flagged_risk_names]).
        """
        if not _load_model():
            return 0.0, []

        tokenizer = _model_cache["tokenizer"]
        model = _model_cache["model"]

        max_score = 0.0
        flagged: list[str] = []

        for risk in risks:
            score = _score_risk(
                tokenizer,
                model,
                messages,
                guardian_config={"risk_name": risk},
            )
            if score > max_score:
                max_score = score
            if score >= _THRESHOLD:
                flagged.append(risk)

        return max_score, flagged

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def check_input(
        self, text: str, context: dict[str, Any] | None = None
    ) -> CheckResult:
        if not self._enabled:
            return self._disabled_result()

        if not text or not text.strip():
            return self._make_result(passed=True, score=0.0, severity=Severity.LOW)

        if not _load_model():
            return self._unavailable_result()

        # Build a user-only conversation for input checks
        messages = [{"role": "user", "content": text}]

        # For input checks exclude RAG-specific risks that need rag_context
        risks = [r for r in _RISKS if r not in _RAG_RISKS]
        if not risks:
            risks = ["harm"]

        try:
            score, flagged = self._evaluate_risks(messages, risks)
            passed = not flagged
            severity = (
                Severity.CRITICAL
                if score >= 0.80
                else (Severity.HIGH if score >= 0.60 else Severity.MEDIUM)
            )

            return self._make_result(
                passed=passed,
                score=round(score, 4),
                severity=severity if not passed else Severity.LOW,
                details={"flagged_risks": flagged, "model": _MODEL},
                remediation=(
                    f"Granite Guardian flagged risks: {', '.join(flagged)}."
                    if flagged
                    else ""
                ),
            )
        except Exception as exc:  # pragma: no cover
            logger.warning("Granite Guardian check_input error: %s — fail open", exc)
            return self._make_result(
                passed=True,
                score=0.0,
                severity=Severity.LOW,
                details={"error": str(exc)},
            )

    def check_output(
        self, text: str, prompt: str = "", context: dict[str, Any] | None = None
    ) -> CheckResult:
        if not self._enabled:
            return self._disabled_result()

        if not text or not text.strip():
            return self._make_result(passed=True, score=0.0, severity=Severity.LOW)

        if not _load_model():
            return self._unavailable_result()

        ctx = context or {}
        rag_context: str | None = ctx.get("rag_context")
        rag_query: str | None = ctx.get("rag_query")

        try:
            # Build conversation for output checks (user → assistant structure)
            user_msg = prompt or rag_query or "User request"
            messages = [
                {"role": "user", "content": user_msg},
                {"role": "assistant", "content": text},
            ]

            risks: list[str] = list(_RISKS)

            # Include groundedness only when retrieved context is available
            if "groundedness" in risks and not rag_context:
                risks.remove("groundedness")
            elif "groundedness" in risks and rag_context:
                # Inject RAG context as a system message for groundedness check
                messages = [
                    {"role": "context", "content": rag_context},
                    *messages,
                ]

            if "answer_relevance" in risks and not rag_query:
                risks.remove("answer_relevance")

            if not risks:
                risks = ["harm"]

            score, flagged = self._evaluate_risks(messages, risks)
            passed = not flagged
            severity = (
                Severity.CRITICAL
                if score >= 0.80
                else (Severity.HIGH if score >= 0.60 else Severity.MEDIUM)
            )

            return self._make_result(
                passed=passed,
                score=round(score, 4),
                severity=severity if not passed else Severity.LOW,
                details={"flagged_risks": flagged, "model": _MODEL},
                remediation=(
                    f"Granite Guardian flagged output risks: {', '.join(flagged)}."
                    if flagged
                    else ""
                ),
            )
        except Exception as exc:  # pragma: no cover
            logger.warning("Granite Guardian check_output error: %s — fail open", exc)
            return self._make_result(
                passed=True,
                score=0.0,
                severity=Severity.LOW,
                details={"error": str(exc)},
            )
