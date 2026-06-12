"""
Stage 3 — Policy Engine (declarative, JSON-driven).

The engine evaluates a RESOLVED policy set against a normalized request. It no
longer reads files itself — policy_loader.py loads libraries from disk and
policy_resolver.py merges native + customer libraries into the final set that
gets handed to this engine.

How a policy matches:
  * every entry in its `conditions` object must be true (logical AND),
  * supported operators are listed in CONDITION_EVALUATORS below,
  * a fired policy contributes its `decision`, optional `risk_floor` /
    `risk_ceiling` / `risk_modifier`, optional `route_to` override, and its
    `reasoning`.
"""

from __future__ import annotations

from typing import Any, Callable, Dict, List, Tuple

from app.models.response_models import TriggeredPolicy
from app.services.risk_scoring import keyword_in_message


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


def _customer_tier_in(req: Dict[str, Any], values: List[str]) -> bool:
    return (req.get("customer_tier") or "") in [v.lower() for v in values]


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
    "customer_tier_in": _customer_tier_in,
    "amount_greater_than": _amount_greater_than,
    "amount_less_than": _amount_less_than,
    "amount_at_least": _amount_at_least,
}


# ---------------------------------------------------------------------------
# Evaluation
# ---------------------------------------------------------------------------

class PolicyEngine:
    """Evaluates requests against one resolved policy set."""

    def __init__(self, policies: List[Dict[str, Any]], version: str = "unknown"):
        self.pack_version = version
        # Disabled policies are dropped here so evaluation never sees them.
        self.policies = [p for p in policies if p.get("enabled", True)]

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
    ) -> Tuple[List[TriggeredPolicy], float | None, float | None, float]:
        """
        Run the request through every active policy.

        Returns:
          * triggered — every policy that fired (full detail),
          * risk_floor — highest `risk_floor` among fired policies (or None),
          * risk_ceiling — lowest `risk_ceiling` among fired policies (or None),
          * risk_modifier — sum of `risk_modifier` points from fired policies
            (customer custom policies use this to nudge the risk score).
        """
        triggered: List[TriggeredPolicy] = []
        risk_floor: float | None = None
        risk_ceiling: float | None = None
        risk_modifier = 0.0

        for policy in self.policies:
            matched_on = self._policy_matches(policy, normalized)
            if matched_on is None:
                continue

            triggered.append(
                TriggeredPolicy(
                    id=policy["id"],
                    description=policy.get("description", policy.get("name", "")),
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

            modifier = policy.get("risk_modifier")
            if modifier:
                risk_modifier += modifier

        return triggered, risk_floor, risk_ceiling, risk_modifier

    def reasoning_for(self, policy_id: str) -> str:
        """Fetch the human-readable reasoning text for a policy id."""
        for policy in self.policies:
            if policy["id"] == policy_id:
                return policy.get("reasoning", policy.get("name", ""))
        return ""
