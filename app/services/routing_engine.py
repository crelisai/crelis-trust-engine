"""
Stage 4 — Routing Engine.

Takes everything the earlier stages produced (triggered policies, risk floors/
ceilings, base risk score) and makes the FINAL call:

  1. Which decision wins?   → most severe decision among fired policies
                              (block > human_agent_required >
                               human_approval_required > allow)
  2. What's the final risk? → base risk, raised to any policy risk_floor;
                              capped by a risk_ceiling only when the winning
                              decision is `allow` (a "low-risk" cap must never
                              hide the risk of an escalated request)
  3. Where does it go?      → the winning policy's route_to override if it has
                              one, else the default route for the decision
  4. Why?                   → reasoning sentences stitched from each policy
"""

from __future__ import annotations

from typing import Any, Dict, List, Tuple

from app import config
from app.models.response_models import TriggeredPolicy
from app.services.policy_engine import PolicyEngine


def decide(
    normalized: Dict[str, Any],
    triggered: List[TriggeredPolicy],
    base_risk: float,
    risk_floor: float | None,
    risk_ceiling: float | None,
    engine: PolicyEngine,
) -> Tuple[str, str, float, str]:
    """
    Produce (decision, route_to, final_risk, reasoning).
    """
    # ------------------------------------------------------------------ 1.
    # Pick the most severe decision. If nothing fired, default to `allow` —
    # the request broke no rules.
    if triggered:
        winner = max(triggered, key=lambda p: config.DECISION_PRIORITY[p.decision])
        decision = winner.decision
    else:
        winner = None
        decision = config.DECISION_ALLOW

    # ------------------------------------------------------------------ 2.
    # Apply risk floor/ceiling.
    final_risk = base_risk
    if risk_floor is not None:
        final_risk = max(final_risk, risk_floor)
    # A ceiling (e.g. "password resets are <20 risk") only applies when the
    # request actually ends up allowed — escalations keep their real risk.
    if risk_ceiling is not None and decision == config.DECISION_ALLOW:
        final_risk = min(final_risk, risk_ceiling)
    final_risk = round(final_risk, 1)

    # ------------------------------------------------------------------ 3.
    # Route: winning policy's override beats the default for that decision.
    route_to = config.DEFAULT_ROUTES[decision]
    if winner is not None and winner.route_to:
        route_to = winner.route_to

    # ------------------------------------------------------------------ 4.
    # Reasoning: the winning policy's explanation first, then the others.
    if triggered:
        ordered = sorted(
            triggered,
            key=lambda p: config.DECISION_PRIORITY[p.decision],
            reverse=True,
        )
        sentences = []
        for pol in ordered:
            text = engine.reasoning_for(pol.id)
            if text:
                sentences.append(text.rstrip("."))
        reasoning = ". ".join(sentences) + "." if sentences else "Policy match."
    else:
        reasoning = (
            "No governance policies were triggered; the action falls within "
            "normal autonomous operating limits."
        )

    return decision, route_to, final_risk, reasoning
