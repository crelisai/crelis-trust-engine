"""
Stage 1 — Normalizer.

Raw requests arrive messy: mixed casing, stray whitespace, missing fields.
This stage cleans everything into one predictable shape so every later stage
(scoring, policies, routing) can trust what it reads.

It also records WHAT was missing — that feeds the confidence score.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from app.models.request_models import TrustRequest
from app.services import detection_engine

# Task-type values that double as intent categories. When a structured request
# carries one of these, we treat it as a detected intent too, so detection-based
# policies fire for structured AND natural-language requests alike.
_INTENT_TASK_TYPES = {
    "refund_request", "billing_dispute", "legal_escalation", "data_export",
    "password_reset", "mfa_reset", "wire_transfer", "customer_complaint",
    "fraud_suspicion", "regulator_complaint", "vip_escalation",
    "security_access_request", "production_database_access",
}

# Amount at/above which the request carries large-financial-amount risk.
_LARGE_AMOUNT_THRESHOLD = 10000


def _clean(value: Any) -> Any:
    """Trim and lowercase strings; leave everything else untouched."""
    if isinstance(value, str):
        return value.strip().lower()
    return value


def extract_amounts(message: Optional[str]) -> List[float]:
    """Monetary values in the message (delegates to the detection engine)."""
    return detection_engine.extract_amounts(message)


def normalize_request(request: TrustRequest) -> Dict[str, Any]:
    """
    Convert a validated TrustRequest into the engine's internal working dict.

    Returns a dict with:
      * cleaned, lowercased copies of every text field,
      * the original (un-lowercased) user_message kept as `raw_user_message`
        so audit records stay faithful to what the user actually wrote,
      * `missing_fields`   — every optional field the caller didn't provide,
      * `missing_critical` — the subset that really hurts decision quality.
    """
    missing_fields: List[str] = []
    missing_critical: List[str] = []

    # Fields we check for presence. (request_id is mandatory — Pydantic already
    # rejected the request if it was absent.)
    optional_fields = [
        "source_system",
        "industry",
        "channel",
        "task_type",
        "user_message",
        "proposed_action",
        "amount",
        "customer_tier",
    ]
    critical_fields = {"task_type", "user_message"}

    # Run the natural-language detection pipeline over the raw message.
    detection = detection_engine.detect(request.user_message)

    # Effective amount: the structured field, the largest amount mentioned in
    # the message, or — if both exist — the LARGER of the two. Fail-safe: an
    # agent claiming amount=10 while the customer writes "refund 100,000" must
    # be judged on the bigger number, not the smaller one.
    extracted = detection["detected_amounts"]
    extracted_max = max(extracted) if extracted else None
    field_amount = request.amount
    amount_source: Optional[str] = None
    if field_amount is not None and extracted_max is not None:
        if extracted_max > field_amount:
            effective_amount, amount_source = extracted_max, "message_exceeds_field"
        else:
            effective_amount, amount_source = field_amount, "field"
    elif field_amount is not None:
        effective_amount, amount_source = field_amount, "field"
    elif extracted_max is not None:
        effective_amount, amount_source = extracted_max, "message"
    else:
        effective_amount = None

    for field in optional_fields:
        value = getattr(request, field)
        is_missing = value is None or (isinstance(value, str) and not value.strip())
        # An amount recovered from the message text counts as present.
        if field == "amount" and effective_amount is not None:
            is_missing = False
        if is_missing:
            missing_fields.append(field)
            if field in critical_fields:
                missing_critical.append(field)

    # Merge detected intents with the structured task_type (if it names an
    # intent) so policies can match either source through one operator.
    task_type = _clean(request.task_type)
    detected_intents = list(detection["detected_intents"])
    if task_type in _INTENT_TASK_TYPES and task_type not in detected_intents:
        detected_intents.append(task_type)

    # The authoritative risk-signal set: signals detected in the message, plus
    # large_financial_amount derived from the EFFECTIVE amount (which may come
    # from the structured field, not the text).
    detected_risk_signals = list(detection["detected_risk_signals"])
    if (
        effective_amount is not None
        and effective_amount >= _LARGE_AMOUNT_THRESHOLD
        and "large_financial_amount" not in detected_risk_signals
    ):
        detected_risk_signals.append("large_financial_amount")

    normalized: Dict[str, Any] = {
        "request_id": request.request_id.strip(),
        "source_system": _clean(request.source_system),
        "industry": _clean(request.industry),
        "channel": _clean(request.channel),
        "task_type": task_type,
        "user_message": _clean(request.user_message),
        "raw_user_message": request.user_message,
        "proposed_action": _clean(request.proposed_action),
        "amount": effective_amount,
        "amount_source": amount_source,
        "customer_tier": _clean(request.customer_tier),
        "metadata": dict(request.metadata or {}),
        "missing_fields": missing_fields,
        "missing_critical": missing_critical,
        # Detection results consumed by scoring, policies, and audit:
        "detection": detection,
        "detected_intents": detected_intents,
        "detected_risk_signals": detected_risk_signals,
        "detected_entities": list(detection["detected_entities"].keys()),
    }
    return normalized
