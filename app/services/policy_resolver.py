"""
Policy Resolver — merges the native Crelis library with a tenant's customer
library into the final policy set the engine evaluates.

Resolution pipeline (the order matters):

  1. Load native Crelis policies            (policy_loader)
  2. Load the tenant's customer policies    (policy_loader)
  3. Apply customer overrides               (validated per-item; invalid
                                             overrides are SKIPPED, fail-safe)
  4. Append customer custom policies        (validated per-item, same rule)
  5. Validate / annotate the final set
  6. Hand the resolved set to PolicyEngine

If a tenant has no customer library — or no tenant_id is given — the resolved
set is simply the native default library. Resolved sets are cached per tenant;
POST /policies/reload clears the cache.
"""

from __future__ import annotations

import copy
from typing import Any, Dict, List, Optional, Tuple

from app.services import policy_loader, policy_validator
from app.services.policy_engine import PolicyEngine

# Cache of resolved sets: {cache_key: (engine, resolved_dict)}
_NATIVE_KEY = "__native__"
_cache: Dict[str, Tuple[PolicyEngine, Dict[str, Any]]] = {}


def clear_cache() -> None:
    """Forget every resolved policy set (used by POST /policies/reload)."""
    _cache.clear()


# ---------------------------------------------------------------------------
# Merge logic
# ---------------------------------------------------------------------------

def _custom_to_internal(custom: Dict[str, Any]) -> Dict[str, Any]:
    """Convert a customer custom policy (external schema) to engine format."""
    return {
        "id": custom["policy_id"],
        "name": custom["name"],
        "description": custom["name"],
        "enabled": custom["enabled"],
        "decision": custom["decision"],
        "severity": custom["severity"],
        "conditions": custom["condition"],
        "risk_modifier": custom["risk_modifier"],
        "route_to": custom["route_to"],
        "reasoning": custom.get("reasoning", custom["name"]),
        "critical": False,
        "library": "customer",
    }


def apply_customer_library(
    native_library: Dict[str, Any],
    customer: Optional[Dict[str, Any]],
) -> Tuple[List[Dict[str, Any]], List[str]]:
    """
    Merge one customer library onto the native policies.

    Every override and custom policy is validated individually; invalid items
    are skipped with a warning rather than applied half-way (fail-safe: the
    native rule keeps running untouched).

    Returns (resolved_policies, warnings).
    """
    policies = copy.deepcopy(native_library.get("policies", []))
    for policy in policies:
        policy.setdefault("library", "native")
    warnings: List[str] = []

    if not customer:
        return policies, warnings

    by_id = {p["id"]: p for p in policies}

    # Step 3 — apply overrides.
    overrides = customer.get("overrides", {})
    if isinstance(overrides, dict):
        for policy_id, override in overrides.items():
            errors = policy_validator.validate_override(
                policy_id, override, by_id.get(policy_id)
            )
            if errors:
                warnings.extend(f"skipped: {e}" for e in errors)
                continue
            target = by_id[policy_id]
            for key in policy_validator.KNOWN_OVERRIDE_KEYS:
                if key in override:
                    target[key] = override[key]
            target["overridden_by_customer"] = True
    else:
        warnings.append("skipped: 'overrides' must be an object keyed by policy id")

    # Step 4 — append custom policies.
    custom_policies = customer.get("custom_policies", [])
    if isinstance(custom_policies, list):
        seen: set = set()
        for custom in custom_policies:
            errors = policy_validator.validate_custom_policy(custom, set(by_id), seen)
            if errors:
                warnings.extend(f"skipped: {e}" for e in errors)
                continue
            seen.add(custom["policy_id"])
            policies.append(_custom_to_internal(custom))
    else:
        warnings.append("skipped: 'custom_policies' must be a list")

    return policies, warnings


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def resolve(tenant_id: Optional[str] = None) -> Dict[str, Any]:
    """
    Produce the resolved policy set for a tenant (or the native default).

    Unknown tenants fall back to the native library with
    `customer_library_missing: true` — for a governance engine the native
    defaults are the safe baseline, so evaluation never hard-fails on a
    missing tenant file.
    """
    native = policy_loader.load_native_library()
    cleaned = policy_loader.clean_tenant_id(tenant_id)

    customer = policy_loader.load_customer_library(cleaned) if cleaned else None
    policies, warnings = apply_customer_library(native, customer)

    return {
        "tenant_id": cleaned,
        "native_version": native.get("version", "unknown"),
        "customer_library": customer.get("name") if customer else None,
        "customer_library_missing": bool(cleaned) and customer is None,
        "policy_count": len(policies),
        "warnings": warnings,
        "policies": policies,
    }


def engine_for(tenant_id: Optional[str] = None) -> Tuple[PolicyEngine, Dict[str, Any]]:
    """Cached (engine, resolved_set) pair for a tenant / the native default."""
    key = policy_loader.clean_tenant_id(tenant_id) or _NATIVE_KEY
    if key not in _cache:
        resolved = resolve(None if key == _NATIVE_KEY else key)
        version = resolved["native_version"]
        if resolved["tenant_id"] and not resolved["customer_library_missing"]:
            version = f"{version}+{resolved['tenant_id']}"
        _cache[key] = (PolicyEngine(resolved["policies"], version=version), resolved)
    return _cache[key]
