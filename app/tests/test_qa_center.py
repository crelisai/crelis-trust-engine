"""
Tests for the Trust Engine QA Center.

Exercises the seven lifecycle check categories, the API endpoints, and the
customer-policy validation gate (accept good, reject bad).
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.qa import store

client = TestClient(app)


@pytest.fixture(autouse=True)
def _clean_store():
    store.clear()
    yield
    store.clear()


# ---------------------------------------------------------------------------
# Run + summary
# ---------------------------------------------------------------------------

def test_qa_run_produces_healthy_summary():
    r = client.post("/qa/run")
    assert r.status_code == 200, r.text
    s = r.json()
    assert s["run_id"].startswith("QA-")
    assert s["total_checks"] > 500          # ~534 reachability + schema + curated
    assert s["passed"] > 0
    assert 0 <= s["health_score"] <= 100
    # On a healthy engine: no unreachable policies, no false allows, chain intact.
    assert s["unreachable_policies"] == 0
    assert s["false_allows"] == 0
    assert s["audit_chain_intact"] is True
    assert s["tenant_override_health"] == "healthy"


def test_qa_categories_all_present():
    client.post("/qa/run")
    run = client.get("/qa/runs").json()[0]
    full = client.get(f"/qa/runs/{run['run_id']}").json()
    categories = {res["category"] for res in full["results"]}
    assert {
        "Policy Schema QA", "Reachability QA", "Detection QA",
        "Decision QA", "Audit QA", "Tenant QA", "Regression QA",
    } <= categories


def test_qa_result_shape():
    client.post("/qa/run")
    full = client.get(f"/qa/runs/{store.latest_run().summary.run_id}").json()
    res = full["results"][0]
    for field in ("run_id", "timestamp", "category", "check_type", "status",
                  "severity", "expected", "actual", "suspected_root_cause",
                  "suggested_fix", "impacted_layer"):
        assert field in res
    assert res["impacted_layer"] in {"detection", "policy", "scoring", "routing", "audit", "tenant"}


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

def test_qa_runs_listing_and_summary():
    client.post("/qa/run")
    client.post("/qa/run")
    runs = client.get("/qa/runs").json()
    assert len(runs) == 2
    summary = client.get("/qa/summary").json()
    assert summary["has_run"] is True
    assert summary["summary"]["run_id"] == runs[0]["run_id"]  # newest first


def test_qa_summary_no_runs():
    body = client.get("/qa/summary").json()
    assert body["has_run"] is False
    assert body["summary"] is None


def test_qa_failures_endpoint_clean_on_healthy_engine():
    client.post("/qa/run")
    failures = client.get("/qa/failures").json()
    # A healthy engine has no hard failures.
    assert failures == []
    # Warnings exist (structured-only reachability) when included.
    with_warn = client.get("/qa/failures?include_warnings=true").json()
    assert all(f["status"] in {"fail", "warning"} for f in with_warn)


def test_qa_policy_endpoint():
    client.post("/qa/run")
    results = client.get("/qa/policy/legal_escalation_policy").json()
    assert results, "expected QA results for a known native policy"
    assert all(r["policy_id"] == "legal_escalation_policy" for r in results)


def test_qa_failures_requires_a_run():
    assert client.get("/qa/failures").status_code == 404


# ---------------------------------------------------------------------------
# Customer-policy validation gate
# ---------------------------------------------------------------------------

GOOD_POLICY = {
    "policy_id": "cust_weekend_wire_review_policy",
    "name": "Weekend wire review",
    "condition": {"message_contains_any": ["weekend wire", "after hours transfer"]},
    "decision": "human_approval_required",
    "risk_modifier": 10,
    "severity": "medium",
    "route_to": "ops_review",
    "enabled": True,
}

# Collides with a native id AND references an unknown operator.
BAD_POLICY = {
    "policy_id": "legal_escalation_policy",
    "name": "Sneaky override",
    "condition": {"sender_is_vip": ["yes"]},
    "decision": "allow",
    "risk_modifier": 0,
    "severity": "low",
    "route_to": "nowhere",
    "enabled": True,
}

# Schema-valid but unreachable (operator unknown means it can never fire).
UNREACHABLE_POLICY = {
    "policy_id": "cust_unreachable_policy",
    "name": "Impossible",
    "condition": {"amount_greater_than": 100, "amount_less_than": 50},
    "decision": "block",
    "risk_modifier": 0,
    "severity": "high",
    "route_to": "void",
    "enabled": True,
}


def test_validate_good_policy_passes():
    r = client.post("/qa/validate-policy", json={"tenant_id": "demo_customer", "policy": GOOD_POLICY})
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "validated"
    assert body["activate_allowed"] is True
    assert body["errors"] == []


def test_validate_bad_policy_is_draft_failed():
    r = client.post("/qa/validate-policy", json={"policy": BAD_POLICY})
    body = r.json()
    assert body["status"] == "draft_failed_validation"
    assert body["activate_allowed"] is False
    assert body["errors"]  # schema/governance errors reported


def test_validate_unreachable_policy_is_draft_failed():
    r = client.post("/qa/validate-policy", json={"policy": UNREACHABLE_POLICY})
    body = r.json()
    assert body["status"] == "draft_failed_validation"
    assert body["activate_allowed"] is False


# ---------------------------------------------------------------------------
# QA must not pollute the real audit chain (reachability uses dry-runs)
# ---------------------------------------------------------------------------

def test_qa_run_does_not_flood_audit_chain():
    before = client.get("/metrics").json()["audit_chain_length"]
    client.post("/qa/run")
    after = client.get("/metrics").json()["audit_chain_length"]
    # Only the single Audit QA probe records an event; the ~534 reachability
    # evaluations are dry-runs.
    assert after - before <= 2
    assert client.get("/metrics").json()["audit_chain_intact"] is True
