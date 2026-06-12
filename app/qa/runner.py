"""
QA run orchestrator: runs the selected lifecycle checks, computes the health
score and headline metrics, stores the run, and returns it.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import List, Optional

from app import config
from app.qa import checks, store
from app.qa.models import QARun, QARunSummary, QAResult
from app.services import policy_resolver

# Severity weights for the health score.
_WEIGHT = {"low": 1, "medium": 2, "high": 4, "critical": 8}

ALL_CATEGORIES = ["schema", "reachability", "detection", "decision", "audit", "tenant", "regression"]


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _summarize(run_id: str, ts: str, results: List[QAResult]) -> QARunSummary:
    total = len(results)
    passed = sum(1 for r in results if r.status == "pass")
    failed = sum(1 for r in results if r.status == "fail")
    warnings = sum(1 for r in results if r.status == "warning")

    total_weight = sum(_WEIGHT[r.severity] for r in results) or 1
    lost = sum(_WEIGHT[r.severity] for r in results if r.status == "fail")
    lost += 0.5 * sum(_WEIGHT[r.severity] for r in results if r.status == "warning")
    health = max(0.0, min(100.0, round(100 * (1 - lost / total_weight), 1)))

    failed_policies = len({r.policy_id for r in results if r.status == "fail" and r.policy_id})
    critical_failures = sum(1 for r in results if r.status == "fail" and r.severity == "critical")
    unreachable = sum(1 for r in results
                      if r.category == "Reachability QA" and r.check_type == "policy_triggers" and r.status == "fail")
    structured_only = sum(1 for r in results
                          if r.category == "Reachability QA" and r.status == "warning" and "structured" in r.actual)
    false_allows = sum(1 for r in results if r.check_type == "false_allow" and r.status == "fail")

    audit_results = [r for r in results if r.category == "Audit QA" and r.check_type == "hash_chain_intact"]
    audit_intact = bool(audit_results) and all(r.status == "pass" for r in audit_results)

    tenant_results = [r for r in results if r.category == "Tenant QA"]
    if not tenant_results:
        tenant_health = "unknown"
    elif all(r.status == "pass" for r in tenant_results):
        tenant_health = "healthy"
    else:
        tenant_health = "degraded"

    by_layer: dict = {}
    for r in results:
        if r.status != "pass":
            by_layer[r.impacted_layer] = by_layer.get(r.impacted_layer, 0) + 1
    by_category: dict = {}
    for r in results:
        c = by_category.setdefault(r.category, {"pass": 0, "fail": 0, "warning": 0})
        c[r.status] += 1

    scope = sorted({(r.tenant_id or "native") for r in results})

    return QARunSummary(
        run_id=run_id, timestamp=ts, tenant_scope=scope,
        total_checks=total, passed=passed, failed=failed, warnings=warnings,
        health_score=health, pass_rate=round(100 * passed / total, 1) if total else 100.0,
        failed_policies=failed_policies, critical_failures=critical_failures,
        unreachable_policies=unreachable, structured_only_policies=structured_only,
        false_allows=false_allows, audit_chain_intact=audit_intact,
        tenant_override_health=tenant_health, by_layer=by_layer, by_category=by_category,
    )


def run_qa(tenant_id: Optional[str] = None, categories: Optional[List[str]] = None) -> QARun:
    run_id = store.next_run_id()
    ts = _utc_now_iso()
    selected = set(categories) if categories else set(ALL_CATEGORIES)

    # Native scope policy set (and, if a tenant is named, that tenant's resolved set).
    native_policies = policy_resolver.resolve(None)["policies"]
    results: List[QAResult] = []

    if "schema" in selected:
        results += checks.schema_qa(run_id, ts, native_policies, None)
    if "reachability" in selected:
        results += checks.reachability_qa(run_id, ts, native_policies, None)
    if tenant_id:
        tenant_policies = policy_resolver.resolve(tenant_id)["policies"]
        if "schema" in selected:
            results += checks.schema_qa(run_id, ts, tenant_policies, tenant_id)
        if "reachability" in selected:
            results += checks.reachability_qa(run_id, ts, tenant_policies, tenant_id)
    if "detection" in selected:
        results += checks.detection_qa(run_id, ts, native_policies)
    if "decision" in selected:
        results += checks.decision_qa(run_id, ts)
    if "audit" in selected:
        results += checks.audit_qa(run_id, ts)
    if "tenant" in selected:
        results += checks.tenant_qa(run_id, ts)
    if "regression" in selected:
        results += checks.regression_qa(run_id, ts)

    run = QARun(summary=_summarize(run_id, ts, results), results=results)
    store.save_run(run)
    return run
