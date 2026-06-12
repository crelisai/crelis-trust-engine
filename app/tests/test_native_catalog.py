"""
Validation suite for the expanded native policy catalog
(app/data/native_policies/catalog_*.json).

Enforces:
  * hard minimums      — >= 500 total native policies, >= 12 categories,
                         >= 35 policies per category, unique stable ids
  * schema correctness — required fields, enum values, condition operators
                         restricted to what the engine actually implements,
                         detection vocab restricted to the shipped libraries
  * calibration guards — mechanical rules that keep the catalog from
                         regressing the pinned behaviours in the core test
                         suite (e.g. wire transfers escalate, never block;
                         routine password resets stay allowed)
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from app.services import policy_loader
from app.services.detection_engine import keyword_in_message
from app.services.policy_engine import CONDITION_EVALUATORS

DATA_DIR = Path(policy_loader.NATIVE_DIR)
LIB_DIR = DATA_DIR.parent / "native_libraries"

REQUIRED_FIELDS = [
    "policy_id", "name", "category", "subcategory", "description", "severity",
    "decision", "route_to", "enabled", "critical", "allowed_by_native_policy",
    "applicable_industries", "applicable_regions", "regulatory_references",
    "condition", "risk_modifier", "version",
]

DECISIONS = {"allow", "human_approval_required", "human_agent_required", "block"}
SEVERITIES = {"low", "medium", "high", "critical"}
PRIORITY = {"allow": 1, "human_approval_required": 2, "human_agent_required": 3, "block": 4}

POLICY_ID_PATTERN = re.compile(r"^[a-z0-9][a-z0-9_]*_policy$")

# Protected messages from the core regression suite, with the highest decision
# a catalog policy may carry if any of its message phrases matches the text.
# Level 0 = no catalog phrase may match the text at all (the baseline request
# must keep triggering ZERO policies).
PROTECTED_MESSAGES = [
    ("i would like a refund please.", 0),
    ("i forgot my password and cannot login", 1),
    ("i forgot my password.", 1),
    ("please unlock my account", 1),
    ("my invoice has a wrong charge", 2),
    ("i want my money back", 2),
    ("i need a manager immediately", 2),
    ("your service is a scam", 2),
    ("this is a scam and your support is useless.", 2),
    ("please refund $750 for a duplicate charge", 2),
    ("i need mfa reset for my admin account", 2),
    ("my email is jane@example.com, refund me.", 2),
    ("i will pursue a refund through the app.", 3),
    ("i will pursue a refund and assume the total sum is correct.", 3),
    ("i need a refund of 100,000 because your service is bullshit", 3),
    ("approve wire transfer of usd 250,000 to a new beneficiary", 3),
    ("release funds now, this is urgent", 3),
    ("i will sue your company", 3),
    ("i am reporting this to mas", 3),
    ("change beneficiary and transfer funds", 3),
    ("this is my final warning before legal notice", 3),
    ("i want a refund and may pursue legal action.", 3),
    ("reset it now or my lawyer gets involved.", 3),
    ("i need a refund of 80,000 now", 3),
    ("process my request.", 3),
    ("please update my mailing address.", 3),
]

LIST_OPERATORS = {
    "message_contains_any", "task_type_in", "proposed_action_in", "industry_in",
    "channel_in", "customer_tier_in", "detected_intent_in",
    "detected_risk_signal_in", "detected_entity_in",
}
AMOUNT_OPERATORS = {"amount_greater_than", "amount_less_than", "amount_at_least"}


def _load_vocab():
    intents = json.loads((LIB_DIR / "intents.json").read_text(encoding="utf-8"))["intents"]
    signals = json.loads((LIB_DIR / "risk_signals.json").read_text(encoding="utf-8"))["risk_signals"]
    entities = json.loads((LIB_DIR / "entities.json").read_text(encoding="utf-8"))["entities"]
    entity_keys = set(entities.keys()) | {"amount", "currency"}
    return set(intents.keys()), set(signals.keys()), entity_keys


def _catalog_policies_raw():
    policies = []
    for path in policy_loader.list_catalog_files():
        data = json.loads(path.read_text(encoding="utf-8"))
        for p in data.get("policies", []):
            policies.append((path.name, p))
    return policies


# ---------------------------------------------------------------------------
# Hard minimums
# ---------------------------------------------------------------------------

def test_catalog_minimums():
    raw = _catalog_policies_raw()
    library = policy_loader.load_native_library()
    total = len(library["policies"])
    assert total >= 500, f"native library has {total} policies; need >= 500"

    categories: dict[str, int] = {}
    for _, p in raw:
        categories[p["category"]] = categories.get(p["category"], 0) + 1
    assert len(categories) >= 12, f"only {len(categories)} categories; need >= 12"
    thin = {c: n for c, n in categories.items() if n < 35}
    assert not thin, f"categories below 35 policies: {thin}"


def test_policy_ids_unique_and_stable():
    library = policy_loader.load_native_library()
    ids = [p["id"] for p in library["policies"]]
    dupes = {i for i in ids if ids.count(i) > 1}
    assert not dupes, f"duplicate policy ids: {sorted(dupes)[:10]}"
    for _, p in _catalog_policies_raw():
        assert POLICY_ID_PATTERN.match(p["policy_id"]), p["policy_id"]


# ---------------------------------------------------------------------------
# Schema correctness
# ---------------------------------------------------------------------------

def test_catalog_schema_and_enums():
    for fname, p in _catalog_policies_raw():
        pid = p.get("policy_id", "<missing id>")
        for field in REQUIRED_FIELDS:
            assert field in p, f"{fname}:{pid} missing field '{field}'"
        assert p["decision"] in DECISIONS, f"{fname}:{pid} bad decision {p['decision']}"
        assert p["severity"] in SEVERITIES, f"{fname}:{pid} bad severity {p['severity']}"
        assert isinstance(p["enabled"], bool), f"{fname}:{pid} enabled must be bool"
        assert isinstance(p["critical"], bool), f"{fname}:{pid} critical must be bool"
        assert isinstance(p["applicable_industries"], list) and p["applicable_industries"], f"{fname}:{pid}"
        assert isinstance(p["applicable_regions"], list) and p["applicable_regions"], f"{fname}:{pid}"
        assert isinstance(p["regulatory_references"], list), f"{fname}:{pid}"
        assert isinstance(p["risk_modifier"], (int, float)), f"{fname}:{pid}"
        assert -20 <= p["risk_modifier"] <= 30, f"{fname}:{pid} risk_modifier out of range"
        if p["critical"]:
            assert p["allowed_by_native_policy"] is False, (
                f"{fname}:{pid} critical policies must not be customer-tunable"
            )
        # The engine has no risk_floor/risk_ceiling in the catalog schema.
        assert "risk_floor" not in p and "risk_ceiling" not in p, f"{fname}:{pid}"


def test_catalog_conditions_use_supported_operators_only():
    intents, signals, entities = _load_vocab()
    for fname, p in _catalog_policies_raw():
        pid = p["policy_id"]
        condition = p["condition"]
        assert isinstance(condition, dict) and condition, f"{fname}:{pid} empty condition"
        for op, value in condition.items():
            assert op in CONDITION_EVALUATORS, f"{fname}:{pid} unsupported operator '{op}'"
            if op in LIST_OPERATORS:
                assert isinstance(value, list) and value, f"{fname}:{pid} {op} needs a non-empty list"
                assert all(isinstance(v, str) and v for v in value), f"{fname}:{pid} {op}"
            if op in AMOUNT_OPERATORS:
                assert isinstance(value, (int, float)) and value >= 0, f"{fname}:{pid} {op}"
        # Detection-based operators may only reference vocabulary the
        # detection engine can actually produce — anything else can never fire.
        for v in condition.get("detected_intent_in", []):
            assert v in intents, f"{fname}:{pid} unknown intent '{v}'"
        for v in condition.get("detected_risk_signal_in", []):
            assert v in signals, f"{fname}:{pid} unknown risk signal '{v}'"
        for v in condition.get("detected_entity_in", []):
            assert v in entities, f"{fname}:{pid} unknown entity '{v}'"


# ---------------------------------------------------------------------------
# Calibration guards (mirror the pinned behaviours in the core suite)
# ---------------------------------------------------------------------------

def test_catalog_phrases_respect_protected_messages():
    for fname, p in _catalog_policies_raw():
        pid = p["policy_id"]
        phrases = p["condition"].get("message_contains_any", [])
        if not phrases:
            continue
        level = PRIORITY[p["decision"]]
        for message, max_level in PROTECTED_MESSAGES:
            hits = [kw for kw in phrases if keyword_in_message(kw, message)]
            if not hits:
                continue
            if max_level == 0:
                raise AssertionError(
                    f"{fname}:{pid} phrase(s) {hits} match the protected baseline "
                    f"message '{message}' — the baseline must trigger no policies"
                )
            assert level <= max_level, (
                f"{fname}:{pid} (decision={p['decision']}) phrase(s) {hits} match "
                f"protected message '{message}' whose max decision level is {max_level}"
            )


def test_catalog_decision_calibration_guards():
    for fname, p in _catalog_policies_raw():
        pid = p["policy_id"]
        c = p["condition"]
        decision = p["decision"]
        ops = set(c.keys())
        intents = set(c.get("detected_intent_in", []))
        signals = set(c.get("detected_risk_signal_in", []))
        entities = set(c.get("detected_entity_in", []))
        has_phrases = bool(c.get("message_contains_any"))
        amount_ops = ops & AMOUNT_OPERATORS
        escalating_amounts = {
            c[o] for o in amount_ops if o in {"amount_greater_than", "amount_at_least"}
        }

        # G2/G3 — broad contextual attributes can never stand alone.
        if ops == {"industry_in"} or ops == {"channel_in"}:
            raise AssertionError(f"{fname}:{pid} single industry/channel condition is too broad")
        if ops == {"customer_tier_in"}:
            assert PRIORITY[decision] <= 2, f"{fname}:{pid} tier-only policies cap at approval"

        # G4 — routine credential resets must stay allowed.
        if "password_reset" in intents or "credential_reset" in signals:
            assert decision == "allow", (
                f"{fname}:{pid} references routine password/credential reset — must be allow"
            )

        # G5 — money movement escalates to humans; it is never hard-blocked.
        money = (
            "wire_transfer" in intents
            or signals & {"external_transfer", "large_financial_amount"}
            or "beneficiary" in entities
            or amount_ops
        )
        if money:
            assert decision != "block", f"{fname}:{pid} money-movement policies never block"

        # G6 — legal/regulator contact is a human-takeover, never a block.
        if intents & {"legal_escalation", "regulator_complaint"} or signals & {
            "legal_threat", "regulator_mention"
        }:
            assert decision != "block", f"{fname}:{pid} legal/regulator policies never block"

        # G7 — pure amount thresholds may only reach human_agent at >= 10000.
        if decision == "human_agent_required" and amount_ops and not has_phrases:
            assert escalating_amounts and min(escalating_amounts) >= 10000, (
                f"{fname}:{pid} human_agent on amounts needs a threshold >= 10000"
            )

        # G8 — refund-intent policies need an amount gate or specific phrases,
        # or the neutral baseline request would trigger them.
        if "refund_request" in intents and not has_phrases and not amount_ops:
            extra = ops - {"detected_intent_in", "industry_in", "channel_in", "customer_tier_in"}
            assert extra, (
                f"{fname}:{pid} refund_request-intent policy would fire on the "
                f"neutral baseline request — add an amount gate or phrases"
            )

        # G9 — MFA/admin alone caps at approval (matches core mfa policy).
        if ops == {"detected_intent_in"} and intents == {"mfa_reset"}:
            assert PRIORITY[decision] <= 2, f"{fname}:{pid}"
        if ops == {"detected_risk_signal_in"} and signals == {"admin_access"}:
            assert PRIORITY[decision] <= 2, f"{fname}:{pid}"

        # G10 — complaint/abuse/urgency tone signals cap at approval unless a
        # large amount or specific phrases are also required.
        tone_only = (
            (signals and signals <= {"abusive_language", "urgent_pressure", "reputational_risk"})
            or (intents and intents <= {"customer_complaint", "billing_dispute"})
        )
        other_gates = has_phrases or (escalating_amounts and min(escalating_amounts) >= 10000)
        if tone_only and not other_gates and not (intents and signals):
            assert PRIORITY[decision] <= 2, (
                f"{fname}:{pid} tone/complaint-only policies cap at human approval"
            )


# ---------------------------------------------------------------------------
# Loader integration
# ---------------------------------------------------------------------------

def test_loader_merges_catalog_after_core():
    library = policy_loader.load_native_library()
    ids = [p["id"] for p in library["policies"]]
    # Core policies keep their positions at the head of the list so that on
    # decision ties the core policy stays the routing winner.
    assert ids[0] == "legal_escalation_policy"
    assert "low_risk_support_policy" in ids[:16]
    # Every merged policy still carries the governance metadata the
    # resolver/validator need (mirrors test_native_policies_load_correctly).
    for p in library["policies"]:
        assert "critical" in p, p["id"]
        assert p["severity"] in SEVERITIES, p["id"]
        assert "allowed_by_native_policy" in p, p["id"]
