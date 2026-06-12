"""
Policy Loader — reads policy libraries from disk.

Two kinds of library live under app/data/:

  native_policies/crelis_default_v<N>.json
      The Crelis-maintained library shipped with the engine. Versioned by
      filename; the loader picks the highest version unless one is requested.

  customer_policies/<tenant_id>.json
      One file per tenant with that customer's overrides + custom policies.

This module ONLY does file IO. Merging the two libraries together happens in
policy_resolver.py, and rule enforcement lives in policy_validator.py.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Dict, List, Optional

DATA_DIR = Path(__file__).resolve().parent.parent / "data"
NATIVE_DIR = DATA_DIR / "native_policies"
CUSTOMER_DIR = DATA_DIR / "customer_policies"

NATIVE_FILE_PATTERN = re.compile(r"^crelis_default_v(\d+)\.json$")

# Catalog extension files: one per category, merged into the native library
# AFTER the core default policies (order matters — on decision ties the engine
# keeps the first-listed policy as winner, so core routing stays stable).
CATALOG_FILE_PATTERN = re.compile(r"^catalog_[a-z0-9_]+\.json$")

# Tenant ids become filenames, so they must be strictly sanitised — this also
# blocks path-traversal tricks like "../../etc/passwd".
TENANT_ID_PATTERN = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")


def _read_json(path: Path) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


# ---------------------------------------------------------------------------
# Native library
# ---------------------------------------------------------------------------

def list_native_versions() -> List[str]:
    """All shipped native library versions, oldest → newest, e.g. ['v1','v2']."""
    versions = []
    for path in NATIVE_DIR.glob("crelis_default_v*.json"):
        match = NATIVE_FILE_PATTERN.match(path.name)
        if match:
            versions.append(int(match.group(1)))
    return [f"v{n}" for n in sorted(versions)]


def list_catalog_files() -> List[Path]:
    """Every catalog extension file shipped with the engine, sorted by name."""
    return sorted(
        p for p in NATIVE_DIR.glob("catalog_*.json") if CATALOG_FILE_PATTERN.match(p.name)
    )


def _catalog_policy_to_internal(policy: Dict[str, Any]) -> Dict[str, Any]:
    """
    Convert a catalog policy (authoring schema: policy_id/condition/...) to the
    engine-internal shape (id/conditions/...). Catalog metadata that the engine
    does not evaluate (category, regulatory_references, ...) is passed through
    so /policies exposes it to consumers.
    """
    internal: Dict[str, Any] = {
        "id": policy["policy_id"],
        "name": policy.get("name", policy["policy_id"]),
        "description": policy.get("description", ""),
        "enabled": policy.get("enabled", True),
        "critical": policy.get("critical", False),
        "severity": policy.get("severity", "medium"),
        "allowed_by_native_policy": policy.get("allowed_by_native_policy", False),
        "decision": policy["decision"],
        "conditions": policy.get("condition", {}),
        "reasoning": policy.get("description") or policy.get("name", ""),
    }
    if policy.get("route_to"):
        internal["route_to"] = policy["route_to"]
    if policy.get("risk_modifier"):
        internal["risk_modifier"] = policy["risk_modifier"]
    for key in (
        "category",
        "subcategory",
        "applicable_industries",
        "applicable_regions",
        "regulatory_references",
        "version",
    ):
        if key in policy:
            internal[key] = policy[key]
    return internal


def load_catalog_policies() -> List[Dict[str, Any]]:
    """All catalog policies from every catalog file, in engine-internal shape."""
    policies: List[Dict[str, Any]] = []
    for path in list_catalog_files():
        data = _read_json(path)
        for policy in data.get("policies", []):
            policies.append(_catalog_policy_to_internal(policy))
    return policies


def load_native_library(version: Optional[str] = None) -> Dict[str, Any]:
    """
    Load the native Crelis policy library.

    With no argument, loads the NEWEST shipped version. Raises FileNotFoundError
    if the requested (or any) version is missing — the engine cannot run
    without its native library.

    Catalog extension files (catalog_*.json) are merged in AFTER the core
    default policies; on duplicate ids the core policy wins and the catalog
    copy is dropped.
    """
    if version is None:
        available = list_native_versions()
        if not available:
            raise FileNotFoundError(f"No native policy library found in {NATIVE_DIR}")
        version = available[-1]

    path = NATIVE_DIR / f"crelis_default_{version}.json"
    if not path.exists():
        raise FileNotFoundError(f"Native policy library version '{version}' not found")
    library = _read_json(path)

    merged: List[Dict[str, Any]] = list(library.get("policies", []))
    seen = {p["id"] for p in merged}
    for policy in load_catalog_policies():
        if policy["id"] in seen:
            continue
        seen.add(policy["id"])
        merged.append(policy)
    library["policies"] = merged
    return library


# ---------------------------------------------------------------------------
# Customer libraries
# ---------------------------------------------------------------------------

def clean_tenant_id(tenant_id: Optional[str]) -> Optional[str]:
    """Normalise a tenant id; returns None if absent or unsafe as a filename."""
    if not tenant_id:
        return None
    cleaned = tenant_id.strip().lower()
    if not TENANT_ID_PATTERN.match(cleaned):
        return None
    return cleaned


def load_customer_library(tenant_id: str) -> Optional[Dict[str, Any]]:
    """Load one tenant's policy library, or None if the tenant has none."""
    cleaned = clean_tenant_id(tenant_id)
    if cleaned is None:
        return None
    path = CUSTOMER_DIR / f"{cleaned}.json"
    if not path.exists():
        return None
    return _read_json(path)


def list_customer_tenants() -> List[str]:
    """Every tenant id that has a customer policy library on disk."""
    return sorted(p.stem for p in CUSTOMER_DIR.glob("*.json"))
