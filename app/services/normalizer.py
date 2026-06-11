"""
Stage 1 — Normalizer.

Raw requests arrive messy: mixed casing, stray whitespace, missing fields.
This stage cleans everything into one predictable shape so every later stage
(scoring, policies, routing) can trust what it reads.

It also records WHAT was missing — that feeds the confidence score.
"""

from __future__ import annotations

from typing import Any, Dict, List

from app.models.request_models import TrustRequest


def _clean(value: Any) -> Any:
    """Trim and lowercase strings; leave everything else untouched."""
    if isinstance(value, str):
        return value.strip().lower()
    return value


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

    for field in optional_fields:
        value = getattr(request, field)
        is_missing = value is None or (isinstance(value, str) and not value.strip())
        if is_missing:
            missing_fields.append(field)
            if field in critical_fields:
                missing_critical.append(field)

    normalized: Dict[str, Any] = {
        "request_id": request.request_id.strip(),
        "source_system": _clean(request.source_system),
        "industry": _clean(request.industry),
        "channel": _clean(request.channel),
        "task_type": _clean(request.task_type),
        "user_message": _clean(request.user_message),
        "raw_user_message": request.user_message,
        "proposed_action": _clean(request.proposed_action),
        "amount": request.amount,
        "customer_tier": _clean(request.customer_tier),
        "metadata": dict(request.metadata or {}),
        "missing_fields": missing_fields,
        "missing_critical": missing_critical,
    }
    return normalized
