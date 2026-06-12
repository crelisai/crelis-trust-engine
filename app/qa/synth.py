"""
Synthesize a request that should satisfy a policy's condition.

Used by Reachability QA and the customer-policy validation gate to prove a
policy can actually fire. Resolves message phrases, detected intents/signals/
entities, structured fields and amounts from the engine's own vocabularies.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Tuple

from app.services.policy_engine import CONDITION_EVALUATORS

_LIB = Path(__file__).resolve().parent.parent / "data" / "native_libraries"
_INTENTS = json.loads((_LIB / "intents.json").read_text(encoding="utf-8"))["intents"]
_SIGNALS = json.loads((_LIB / "risk_signals.json").read_text(encoding="utf-8"))["risk_signals"]
_ENTITIES = json.loads((_LIB / "entities.json").read_text(encoding="utf-8"))["entities"]

_REGEX_ENTITY_SAMPLES = {
    "email": "jane@example.com",
    "phone_number": "+1 415 555 0172",
    "credit_card": "4111 1111 1111 1111",
    "nric": "s1234567a",
}

STRUCTURED_OPS = {
    "task_type_in", "proposed_action_in", "industry_in", "channel_in", "customer_tier_in",
}
UI_REACHABLE_OPS = STRUCTURED_OPS | {
    "message_contains_any", "detected_intent_in", "detected_risk_signal_in",
    "detected_entity_in", "amount_greater_than", "amount_less_than", "amount_at_least",
}


def _intent_phrase(intent: str):
    phrases = _INTENTS.get(intent)
    return phrases[0] if phrases else None


def _satisfy_entity(entity: str, msg_parts: List[str]) -> bool:
    spec = _ENTITIES.get(entity)
    if not spec:
        return False
    match = spec["match"]
    if match == "phrase":
        msg_parts.append(spec["phrases"][0])
        return True
    if match == "regex":
        sample = _REGEX_ENTITY_SAMPLES.get(entity)
        if sample:
            msg_parts.append(sample)
            return True
        return False
    if match in ("amount", "currency"):
        msg_parts.append("$25,000")
        return True
    return False


def _satisfy_signal(signal: str, msg_parts: List[str]) -> bool:
    spec = _SIGNALS.get(signal)
    if not spec:
        return False
    if "phrases" in spec:
        msg_parts.append(spec["phrases"][0])
        return True
    if "derived_from_intents" in spec:
        phrase = _intent_phrase(spec["derived_from_intents"][0])
        if phrase:
            msg_parts.append(phrase)
            return True
    if "derived_from_entities" in spec:
        return _satisfy_entity(spec["derived_from_entities"][0], msg_parts)
    if "derived_amount_threshold" in spec:
        msg_parts.append(f"${int(spec['derived_amount_threshold']) + 1}")
        return True
    if spec.get("derived_abusive_and_complaint"):
        msg_parts.append(_SIGNALS["abusive_language"]["phrases"][0])
        complaint = _intent_phrase("customer_complaint")
        if complaint:
            msg_parts.append(complaint)
        return True
    return False


def synthesize(conditions: Dict[str, Any]) -> Tuple[str, Dict[str, Any], List[str]]:
    """Return (message, structured_fields, unsatisfiable_reasons)."""
    msg_parts: List[str] = []
    fields: Dict[str, Any] = {}
    unsat: List[str] = []
    gt = atleast = lt = None

    for op, val in conditions.items():
        if op == "message_contains_any":
            msg_parts.append(val[0])
        elif op == "task_type_in":
            fields["task_type"] = val[0]
        elif op == "proposed_action_in":
            fields["proposed_action"] = val[0]
        elif op == "industry_in":
            fields["industry"] = val[0]
        elif op == "channel_in":
            fields["channel"] = val[0]
        elif op == "customer_tier_in":
            fields["customer_tier"] = val[0]
        elif op == "amount_greater_than":
            gt = val
        elif op == "amount_at_least":
            atleast = val
        elif op == "amount_less_than":
            lt = val
        elif op == "detected_intent_in":
            phrase = _intent_phrase(val[0])
            msg_parts.append(phrase) if phrase else unsat.append(f"intent:{val[0]}")
        elif op == "detected_risk_signal_in":
            if not _satisfy_signal(val[0], msg_parts):
                unsat.append(f"signal:{val[0]}")
        elif op == "detected_entity_in":
            if not _satisfy_entity(val[0], msg_parts):
                unsat.append(f"entity:{val[0]}")
        else:
            unsat.append(f"unsupported_op:{op}")

    lower = None
    if gt is not None:
        lower = gt + 1
    if atleast is not None:
        lower = max(lower or 0, atleast)
    amount = lower
    if lt is not None:
        if amount is None:
            amount = max(0, lt - 1)
        elif amount >= lt:
            unsat.append("amount_range_conflict")
    if amount is not None:
        fields["amount"] = amount

    message = " ".join(f"{p}." for p in msg_parts) if msg_parts else "Please process this routine request."
    return message, fields, unsat


def classify_reachability(conditions: Dict[str, Any]) -> Dict[str, bool]:
    ops = set(conditions)
    return {
        "requires_task_type": "task_type_in" in ops,
        "requires_structured": bool(ops & STRUCTURED_OPS),
        "free_text_only": not (ops & STRUCTURED_OPS),
        "ui_unreachable": bool(ops - UI_REACHABLE_OPS),
        "unknown_operator": bool(ops - set(CONDITION_EVALUATORS)),
    }
