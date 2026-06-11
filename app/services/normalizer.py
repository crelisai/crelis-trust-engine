"""
Stage 1 — Normalizer.

Raw requests arrive messy: mixed casing, stray whitespace, missing fields.
This stage cleans everything into one predictable shape so every later stage
(scoring, policies, routing) can trust what it reads.

It also records WHAT was missing — that feeds the confidence score.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

from app.models.request_models import TrustRequest


def _clean(value: Any) -> Any:
    """Trim and lowercase strings; leave everything else untouched."""
    if isinstance(value, str):
        return value.strip().lower()
    return value


# ---------------------------------------------------------------------------
# Amount extraction from free text
# ---------------------------------------------------------------------------
# Callers don't always fill in the structured `amount` field — the money is
# often only mentioned in the user's message ("I need a refund of 100,000").
# A governance engine that ignores that is blind to its biggest risk signal,
# so we parse monetary mentions out of the text. Handles:
#   100000   100,000   $100,000   USD 100,000   SGD 100,000   1,234.56

AMOUNT_PATTERN = re.compile(
    r"""
    (?:(?:USD|SGD|EUR|GBP|AUD|MYR|INR|US\$|S\$|\$|€|£)\s*)?   # optional currency
    \b(
        \d{1,3}(?:,\d{3})+(?:\.\d+)?    # comma-grouped: 100,000 / 1,234.56
        |
        \d+(?:\.\d+)?                   # plain: 100000 / 99.5
    )\b
    """,
    re.VERBOSE | re.IGNORECASE,
)


def extract_amounts(message: Optional[str]) -> List[float]:
    """Return every monetary-looking number found in the message."""
    if not message:
        return []
    amounts = []
    for match in AMOUNT_PATTERN.finditer(message):
        try:
            amounts.append(float(match.group(1).replace(",", "")))
        except ValueError:  # defensive — pattern should always parse
            continue
    return amounts


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

    # Effective amount: the structured field, the largest amount mentioned in
    # the message, or — if both exist — the LARGER of the two. Fail-safe: an
    # agent claiming amount=10 while the customer writes "refund 100,000" must
    # be judged on the bigger number, not the smaller one.
    extracted = extract_amounts(request.user_message)
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

    normalized: Dict[str, Any] = {
        "request_id": request.request_id.strip(),
        "source_system": _clean(request.source_system),
        "industry": _clean(request.industry),
        "channel": _clean(request.channel),
        "task_type": _clean(request.task_type),
        "user_message": _clean(request.user_message),
        "raw_user_message": request.user_message,
        "proposed_action": _clean(request.proposed_action),
        "amount": effective_amount,
        "amount_source": amount_source,
        "customer_tier": _clean(request.customer_tier),
        "metadata": dict(request.metadata or {}),
        "missing_fields": missing_fields,
        "missing_critical": missing_critical,
    }
    return normalized
