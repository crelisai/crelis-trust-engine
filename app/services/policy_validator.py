"""
Policy Validator — enforces the governance rules of the policy-library system.

The rules a customer library must obey:

  1. Overrides may only target policies that exist in the native library.
  2. CRITICAL native policies can never be disabled.
  3. For critical native policies, decision/severity may only be RAISED
     (e.g. human_agent_required → block), never lowered.
  4. Conditions/thresholds may only be overridden where the native policy
     declares `allowed_by_native_policy: true`.
  5. `route_to` may always be overridden (routing preferences are safe).
  6. Custom policies must carry every required field, use known condition
     operators, and must not collide with native policy ids.

The validator is intentionally split into small per-item functions so the
resolver can re-use them to apply ONLY the valid parts of a customer library
(fail-safe: an invalid override is skipped, never half-applied).
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from app import config
from app.services.policy_engine import CONDITION_EVALUATORS

# Every field a customer custom policy must include.
REQUIRED_CUSTOM_FIELDS = [
    "policy_id",
    "name",
    "condition",
    "decision",
    "risk_modifier",
    "severity",
    "route_to",
    "enabled",
]

VALID_DECISIONS = set(config.DECISION_PRIORITY)
VALID_SEVERITIES = set(config.SEVERITY_ORDER)

# Keys an override block is allowed to contain at all.
KNOWN_OVERRIDE_KEYS = {
    "enabled",
    "decision",
    "severity",
    "conditions",
    "route_to",
    "risk_floor",
}


def _unknown_operators(conditions: Any) -> List[str]:
    if not isinstance(conditions, dict) or not conditions:
        return ["<conditions must be a non-empty object>"]
    return [op for op in conditions if op not in CONDITION_EVALUATORS]


# ---------------------------------------------------------------------------
# Per-item validators (re-used by the resolver)
# ---------------------------------------------------------------------------

def validate_override(
    policy_id: str,
    override: Dict[str, Any],
    native_policy: Optional[Dict[str, Any]],
) -> List[str]:
    """Validate ONE override block against its native policy. Returns errors."""
    errors: List[str] = []

    if native_policy is None:
        return [f"override '{policy_id}': no such policy in the native library"]
    if not isinstance(override, dict):
        return [f"override '{policy_id}': must be an object"]

    critical = bool(native_policy.get("critical", False))

    for key in override:
        if key not in KNOWN_OVERRIDE_KEYS:
            errors.append(f"override '{policy_id}': unknown key '{key}'")

    # Rule 2 — critical natives can never be disabled.
    if override.get("enabled") is False and critical:
        errors.append(
            f"override '{policy_id}': critical native policies cannot be disabled"
        )

    # Rule 3 — decision severity may only be raised on critical natives.
    if "decision" in override:
        new_decision = override["decision"]
        if new_decision not in VALID_DECISIONS:
            errors.append(f"override '{policy_id}': unknown decision '{new_decision}'")
        elif critical and (
            config.DECISION_PRIORITY[new_decision]
            < config.DECISION_PRIORITY[native_policy["decision"]]
        ):
            errors.append(
                f"override '{policy_id}': cannot lower the decision of a critical "
                f"native policy ({native_policy['decision']} → {new_decision})"
            )

    if "severity" in override:
        new_severity = override["severity"]
        native_severity = native_policy.get("severity", "low")
        if new_severity not in VALID_SEVERITIES:
            errors.append(f"override '{policy_id}': unknown severity '{new_severity}'")
        elif critical and (
            config.SEVERITY_ORDER[new_severity]
            < config.SEVERITY_ORDER.get(native_severity, 1)
        ):
            errors.append(
                f"override '{policy_id}': cannot lower the severity of a critical "
                f"native policy ({native_severity} → {new_severity})"
            )

    # Rule 4 — thresholds only where the native policy allows it.
    if "conditions" in override:
        if not native_policy.get("allowed_by_native_policy", False):
            errors.append(
                f"override '{policy_id}': this native policy does not allow "
                "condition/threshold overrides (allowed_by_native_policy=false)"
            )
        else:
            for op in _unknown_operators(override["conditions"]):
                errors.append(f"override '{policy_id}': unknown condition operator '{op}'")

    # risk_floor on a critical native may only be raised.
    if "risk_floor" in override:
        native_floor = native_policy.get("risk_floor")
        if not isinstance(override["risk_floor"], (int, float)):
            errors.append(f"override '{policy_id}': risk_floor must be a number")
        elif critical and native_floor is not None and override["risk_floor"] < native_floor:
            errors.append(
                f"override '{policy_id}': cannot lower the risk_floor of a critical "
                f"native policy ({native_floor} → {override['risk_floor']})"
            )

    return errors


def validate_custom_policy(
    custom: Dict[str, Any],
    native_ids: set,
    seen_ids: set,
) -> List[str]:
    """Validate ONE customer custom policy. Returns errors."""
    if not isinstance(custom, dict):
        return ["custom policy: must be an object"]

    label = custom.get("policy_id", "<missing policy_id>")
    errors: List[str] = []

    for field in REQUIRED_CUSTOM_FIELDS:
        if field not in custom:
            errors.append(f"custom policy '{label}': missing required field '{field}'")
    if errors:
        return errors  # can't sensibly check further with fields missing

    if custom["policy_id"] in native_ids:
        errors.append(
            f"custom policy '{label}': policy_id collides with a native policy"
        )
    if custom["policy_id"] in seen_ids:
        errors.append(f"custom policy '{label}': duplicate policy_id")
    if custom["decision"] not in VALID_DECISIONS:
        errors.append(f"custom policy '{label}': unknown decision '{custom['decision']}'")
    if custom["severity"] not in VALID_SEVERITIES:
        errors.append(f"custom policy '{label}': unknown severity '{custom['severity']}'")
    if not isinstance(custom["risk_modifier"], (int, float)):
        errors.append(f"custom policy '{label}': risk_modifier must be a number")
    if not isinstance(custom["enabled"], bool):
        errors.append(f"custom policy '{label}': enabled must be true or false")
    for op in _unknown_operators(custom["condition"]):
        errors.append(f"custom policy '{label}': unknown condition operator '{op}'")

    return errors


# ---------------------------------------------------------------------------
# Whole-library validation (used by the /validate endpoint)
# ---------------------------------------------------------------------------

def validate_customer_library(
    customer: Dict[str, Any],
    native_library: Dict[str, Any],
) -> Dict[str, Any]:
    """
    Validate a full customer library against the native one.

    Returns {"valid": bool, "errors": [...], "warnings": [...]} — errors are
    rule violations; warnings are non-fatal oddities worth surfacing.
    """
    errors: List[str] = []
    warnings: List[str] = []

    if not isinstance(customer, dict):
        return {"valid": False, "errors": ["customer library must be an object"], "warnings": []}

    if not customer.get("tenant_id"):
        errors.append("customer library: missing tenant_id")

    native_by_id = {p["id"]: p for p in native_library.get("policies", [])}

    overrides = customer.get("overrides", {})
    if not isinstance(overrides, dict):
        errors.append("customer library: 'overrides' must be an object keyed by policy id")
        overrides = {}
    for policy_id, override in overrides.items():
        errors.extend(validate_override(policy_id, override, native_by_id.get(policy_id)))

    custom_policies = customer.get("custom_policies", [])
    if not isinstance(custom_policies, list):
        errors.append("customer library: 'custom_policies' must be a list")
        custom_policies = []
    seen_ids: set = set()
    for custom in custom_policies:
        errors.extend(validate_custom_policy(custom, set(native_by_id), seen_ids))
        if isinstance(custom, dict) and "policy_id" in custom:
            seen_ids.add(custom["policy_id"])

    if not overrides and not custom_policies:
        warnings.append("customer library defines no overrides and no custom policies")

    return {"valid": not errors, "errors": errors, "warnings": warnings}
