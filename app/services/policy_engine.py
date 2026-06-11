"""
Stage 3 — Policy Engine (declarative, JSON-driven).

This is the advanced heart of Crelis: policies live in
`app/data/policy_rules.json`, NOT in Python code. A compliance officer can add,
edit, disable, or re-route a policy by editing JSON — no deploy, no developer.

How a policy matches:
  * every entry in its `conditions` object must be true (logical AND),
  * supported operators are listed in CONDITION_EVALUATORS below,
  * a fired policy contributes its `decision`, optional `risk_floor` /
    `risk_ceiling`, optional `route_to` override, and its `reasoning`.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Callable, Dict, List, Tuple

from app.models.response_models import TriggeredPolicy
from app.services.risk_scoring import keyword_in_message

POLICY_FILE = Path(__file__).resolve().parent.parent / "data" / "policy_rules.json"


# ---------------------------------------------------------------------------
# Condition operators
# ---------------------------------------------------------------------------
# Each operator is a tiny function: (normalized_request, operator_value) -> bool.
# Adding a new operator = adding one entry here. Nothing else changes.

def _msg_contains_any(req: Dict[str, Any], keywords: List[str]) -> bool:
    # Whole-word matching ('sue' must not fire inside 'pursue').
    message = req.get("user_message") or ""
    return any(keyword_in_message(kw, message) for kw in keywords)


def _task_type_in(req: Dict[str, Any], values: List[str]) -> bool:
    return (req.get("task_type") or "") in [v.lower() for v in values]


def _proposed_action_in(req: Dict[str, Any], values: List[str]) -> bool:
    return (req.get("proposed_action") or "") in [v.lower() for v in values]


def _industry_in(req: Dict[str, Any], values: List[str]) -> bool:
    return (req.get("industry") or "") in [v.lower() for v in values]


def _channel_in(req: Dict[str, Any], values: List[str]) -> bool:
    return (req.get("channel") or "") in [v.lower() for v in values]


def _amount_greater_than(req: Dict[str, Any], threshold: float) -> bool:
    amount = req.get("amount")
    return amount is not None and amount > threshold


def _amount_less_than(req: Dict[str, Any], threshold: float) -> bool:
    amount = req.get("amount")
    return amount is not None and amount < threshold


def _amount_at_least(req: Dict[str, Any], threshold: float) -> bool:
    amount = req.get("amount")
    return amount is not None and amount >= threshold


CONDITION_EVALUATORS: Dict[str, Callable[[Dict[str, Any], Any], bool]] = {
    "message_contains_any": _msg_contains_any,
    "task_type_in": _task_type_in,
    "proposed_action_in": _proposed_action_in,
    "industry_in": _industry_in,
    "channel_in": _channel_in,
    "amount_greater_than": _amount_greater_than,
    "amount_less_than": _amount_less_than,
    "amount_at_least": _amount_at_least,
}


# ---------------------------------------------------------------------------
# Policy loading
# ---------------------------------------------------------------------------

class PolicyEngine:
    """Loads the policy pack and evaluates requests against it."""

    def __init__(self, policy_file: Path = POLICY_FILE):
        self.policy_file = policy_file
        self.policies: List[Dict[str, Any]] = []
        self.pack_version: str = "unknown"
        self.load()

    def load(self) -> int:
        """(Re)load policies from disk. Returns how many are active."""
        with open(self.policy_file, "r", encoding="utf-8") as f:
            data = json.load(f)
        self.pack_version = data.get("version", "unknown")
        self.policies = [p for p in data.get("policies", []) if p.get("enabled", True)]
        return len(self.policies)

    # -- evaluation ----------------------------------------------------------

    def _policy_matches(self, policy: Dict[str, Any], req: Dict[str, Any]) -> str | None:
        """
        Check all conditions of one policy (AND semantics).

        Returns a short human-readable string describing the match, or None if
        any condition fails / is unknown.
        """
        conditions = policy.get("conditions", {})
        if not conditions:
            return None  # a policy with no conditions never fires — safety first

        matched_parts: List[str] = []
        for op_name, op_value in conditions.items():
            evaluator = CONDITION_EVALUATORS.get(op_name)
            if evaluator is None:
                # Unknown operator: fail CLOSED for this policy and make it
                # visible, rather than silently pretending it matched.
                return None
            if not evaluator(req, op_value):
                return None
            matched_parts.append(f"{op_name}={op_value!r}")
        return " AND ".join(matched_parts)

    def evaluate(
        self, normalized: Dict[str, Any]
    ) -> Tuple[List[TriggeredPolicy], float | None, float | None]:
        """
        Run the request through every active policy.

        Returns:
          * triggered — every policy that fired (full detail),
          * risk_floor — highest `risk_floor` among fired policies (or None),
          * risk_ceiling — lowest `risk_ceiling` among fired policies (or None).
        """
        triggered: List[TriggeredPolicy] = []
        risk_floor: float | None = None
        risk_ceiling: float | None = None

        for policy in self.policies:
            matched_on = self._policy_matches(policy, normalized)
            if matched_on is None:
                continue

            triggered.append(
                TriggeredPolicy(
                    id=policy["id"],
                    description=policy.get("description", ""),
                    decision=policy["decision"],
                    route_to=policy.get("route_to"),
                    matched_on=matched_on,
                )
            )

            floor = policy.get("risk_floor")
            if floor is not None:
                risk_floor = floor if risk_floor is None else max(risk_floor, floor)

            ceiling = policy.get("risk_ceiling")
            if ceiling is not None:
                risk_ceiling = (
                    ceiling if risk_ceiling is None else min(risk_ceiling, ceiling)
                )

        return triggered, risk_floor, risk_ceiling

    def reasoning_for(self, policy_id: str) -> str:
        """Fetch the human-readable reasoning text for a policy id."""
        for policy in self.policies:
            if policy["id"] == policy_id:
                return policy.get("reasoning", "")
        return ""


# One shared engine instance for the whole app (loaded once at startup,
# reloadable via POST /policies/reload).
policy_engine = PolicyEngine()
