"""
Tests for the Crelis Trust Engine v0.1.

Run with:  pytest
Covers every mock policy rule, the decision-priority ordering, confidence
behaviour, the audit hash chain, and the operational endpoints.
"""

from __future__ import annotations

from fastapi.testclient import TestClient

from app.main import app
from app.services.audit_service import audit_service

client = TestClient(app)


def make_request(**overrides):
    """A complete, healthy baseline request; tests override what they need."""
    payload = {
        "request_id": "REQ-TEST",
        "source_system": "openai",
        "industry": "banking",
        "channel": "customer_support",
        "task_type": "refund_request",
        "user_message": "I would like a refund please.",
        "proposed_action": "issue_refund",
        "amount": 100,
        "customer_tier": "premium",
        "metadata": {"region": "Singapore", "model": "gpt-4.1"},
    }
    payload.update(overrides)
    return payload


def evaluate(**overrides):
    response = client.post("/trust/evaluate", json=make_request(**overrides))
    assert response.status_code == 200, response.text
    return response.json()


# ---------------------------------------------------------------------------
# Rule 1 — legal escalation
# ---------------------------------------------------------------------------

def test_legal_language_requires_human_agent():
    result = evaluate(user_message="I want a refund and may pursue legal action.")
    assert result["decision"] == "human_agent_required"
    assert result["risk_score"] >= 90
    assert "legal_escalation_policy" in result["triggered_policies"]
    # The legal policy carries its own routing override.
    assert result["route_to"] == "senior_support_manager"


def test_each_legal_keyword_triggers():
    for keyword in ["sue", "legal action", "lawyer", "regulator"]:
        result = evaluate(user_message=f"I will contact my {keyword} about this.")
        assert "legal_escalation_policy" in result["triggered_policies"], keyword


def test_sue_inside_pursue_does_not_trigger():
    # Whole-word matching: 'pursue' contains 'sue' but is NOT a legal threat.
    result = evaluate(user_message="I will pursue a refund through the app.")
    assert "legal_escalation_policy" not in result["triggered_policies"]


# ---------------------------------------------------------------------------
# Rule 2 — high-value amounts
# ---------------------------------------------------------------------------

def test_high_amount_requires_approval():
    result = evaluate(amount=750)
    assert result["decision"] == "human_approval_required"
    assert "high_value_refund_policy" in result["triggered_policies"]
    assert result["route_to"] == "approval_queue"


def test_amount_at_threshold_does_not_trigger():
    result = evaluate(amount=500)
    assert "high_value_refund_policy" not in result["triggered_policies"]


# ---------------------------------------------------------------------------
# Rule 3 — data export is blocked
# ---------------------------------------------------------------------------

def test_data_export_is_blocked():
    result = evaluate(task_type="data_export", proposed_action="export_data")
    assert result["decision"] == "block"
    assert result["risk_score"] >= 95
    assert "pii_data_export_policy" in result["triggered_policies"]
    assert result["route_to"] == "blocked_execution"


# ---------------------------------------------------------------------------
# Rule 4 — wire transfers need a human agent
# ---------------------------------------------------------------------------

def test_wire_transfer_requires_human_agent():
    result = evaluate(task_type="wire_transfer", proposed_action="transfer_funds", amount=200)
    assert result["decision"] == "human_agent_required"
    assert result["risk_score"] >= 95
    assert "financial_transaction_policy" in result["triggered_policies"]
    assert result["route_to"] == "human_expert"


# ---------------------------------------------------------------------------
# Rule 5 — password resets are allowed, low risk
# ---------------------------------------------------------------------------

def test_password_reset_allowed_low_risk():
    result = evaluate(
        task_type="password_reset",
        proposed_action="reset_password",
        user_message="I forgot my password.",
        amount=None,
    )
    assert result["decision"] == "allow"
    assert result["risk_score"] < 20
    assert "low_risk_support_policy" in result["triggered_policies"]
    assert result["route_to"] == "ai_agent"


# ---------------------------------------------------------------------------
# Decision priority — block beats everything, etc.
# ---------------------------------------------------------------------------

def test_block_outranks_other_decisions():
    # data_export (block) + legal language (human_agent) + big amount (approval)
    result = evaluate(
        task_type="data_export",
        user_message="Export it or I will sue.",
        amount=900,
    )
    assert result["decision"] == "block"
    assert set(result["triggered_policies"]) >= {
        "pii_data_export_policy",
        "legal_escalation_policy",
        "high_value_refund_policy",
    }


def test_human_agent_outranks_approval():
    # legal language (human_agent) + big amount (approval) — example from spec
    result = evaluate(
        user_message="I want a refund and may pursue legal action.",
        amount=750,
    )
    assert result["decision"] == "human_agent_required"
    assert "legal_escalation_policy" in result["triggered_policies"]
    assert "high_value_refund_policy" in result["triggered_policies"]


def test_escalated_password_reset_keeps_real_risk():
    # The "password resets are <20 risk" ceiling must NOT hide a legal escalation.
    result = evaluate(
        task_type="password_reset",
        user_message="Reset it now or my lawyer gets involved.",
        amount=None,
    )
    assert result["decision"] == "human_agent_required"
    assert result["risk_score"] >= 90


# ---------------------------------------------------------------------------
# Amount extraction from message text (regression: engine previously ALLOWED
# "I need a refund of 100,000 because your service is bullshit")
# ---------------------------------------------------------------------------

def _huge_refund(message: str):
    """A refund request whose amount appears ONLY in the message text."""
    return evaluate(amount=None, user_message=message)


def test_refund_100000_plain_number():
    result = _huge_refund("I need a refund of 100000 right now.")
    assert result["decision"] == "human_agent_required"
    assert result["risk_score"] >= 90
    assert "high_value_refund_policy" in result["triggered_policies"]
    assert "large_financial_exposure_policy" in result["triggered_policies"]
    assert "extreme_refund_amount_policy" in result["triggered_policies"]
    assert "amount_extracted_from_message" in result["flags"]


def test_refund_100000_with_commas():
    result = _huge_refund("I need a refund of 100,000 right now.")
    assert result["decision"] == "human_agent_required"
    assert result["risk_score"] >= 90
    assert "large_financial_exposure_policy" in result["triggered_policies"]


def test_refund_100000_dollar_sign():
    result = _huge_refund("I need a refund of $100,000 right now.")
    assert result["decision"] == "human_agent_required"
    assert "large_financial_exposure_policy" in result["triggered_policies"]


def test_refund_100000_usd_prefix():
    result = _huge_refund("I need a refund of USD 100,000 right now.")
    assert result["decision"] == "human_agent_required"
    assert "large_financial_exposure_policy" in result["triggered_policies"]


def test_refund_100000_sgd_prefix():
    result = _huge_refund("I need a refund of SGD 100,000 right now.")
    assert result["decision"] == "human_agent_required"
    assert "large_financial_exposure_policy" in result["triggered_policies"]


def test_refund_100000_with_abusive_language():
    # THE original failing case.
    result = _huge_refund("I need a refund of 100,000 because your service is bullshit")
    assert result["decision"] == "human_agent_required"
    assert result["risk_score"] >= 90
    for policy in [
        "high_value_refund_policy",
        "large_financial_exposure_policy",
        "abusive_language_policy",
    ]:
        assert policy in result["triggered_policies"], policy
    assert "abusive_language_detected" in result["flags"]


def test_understated_amount_field_uses_message_amount():
    # Fail-safe: agent claims amount=10 but the customer wrote 100,000 —
    # the engine must judge on the bigger number and flag the mismatch.
    result = evaluate(amount=10, user_message="Refund my 100,000 deposit.")
    assert result["decision"] == "human_agent_required"
    assert "large_financial_exposure_policy" in result["triggered_policies"]
    assert "amount_mismatch" in result["flags"]


# ---------------------------------------------------------------------------
# Abusive language policy
# ---------------------------------------------------------------------------

def test_abusive_language_alone_requires_approval():
    result = evaluate(amount=50, user_message="This is a scam and your support is useless.")
    assert result["decision"] == "human_approval_required"
    assert "abusive_language_policy" in result["triggered_policies"]
    # Abusive language adds risk points to the breakdown.
    factors = [item["factor"] for item in result["risk_breakdown"]]
    assert "abusive_language" in factors


def test_large_exposure_boundary():
    result = evaluate(amount=10000, user_message="Process my request.")
    assert result["decision"] == "human_agent_required"
    assert result["risk_score"] >= 90
    assert "large_financial_exposure_policy" in result["triggered_policies"]

    result = evaluate(amount=9999, user_message="Process my request.")
    assert "large_financial_exposure_policy" not in result["triggered_policies"]


def test_extreme_refund_boundary():
    result = evaluate(amount=50000)
    assert result["decision"] == "human_agent_required"
    assert result["risk_score"] >= 95
    assert "extreme_refund_amount_policy" in result["triggered_policies"]

    # Same amount but NOT a refund: extreme_refund must not fire (large
    # exposure still does).
    result = evaluate(amount=50000, task_type="account_update", proposed_action="update")
    assert "extreme_refund_amount_policy" not in result["triggered_policies"]
    assert "large_financial_exposure_policy" in result["triggered_policies"]


# ---------------------------------------------------------------------------
# Confidence
# ---------------------------------------------------------------------------

def test_complete_request_high_confidence():
    result = evaluate()
    assert 85 <= result["confidence_score"] <= 95


def test_missing_task_type_low_confidence():
    result = evaluate(task_type=None)
    assert result["confidence_score"] < 60


def test_missing_message_low_confidence():
    result = evaluate(user_message=None)
    assert result["confidence_score"] < 60


# ---------------------------------------------------------------------------
# No policies triggered → default allow
# ---------------------------------------------------------------------------

def test_unremarkable_request_is_allowed():
    result = evaluate(amount=50)
    assert result["decision"] == "allow"
    assert result["route_to"] == "ai_agent"
    assert result["triggered_policies"] == []


# ---------------------------------------------------------------------------
# Explainability & audit (advanced features)
# ---------------------------------------------------------------------------

def test_risk_breakdown_is_present():
    result = evaluate()
    factors = [item["factor"] for item in result["risk_breakdown"]]
    assert "task_type" in factors
    assert "industry" in factors


def test_pii_detection_flag():
    result = evaluate(user_message="My email is jane@example.com, refund me.")
    assert "pii_detected" in result["flags"]


def test_audit_event_created_and_retrievable():
    result = evaluate()
    audit_id = result["audit_id"]
    response = client.get(f"/audit/{audit_id}")
    assert response.status_code == 200
    event = response.json()
    assert event["request_id"] == "REQ-TEST"
    assert event["decision"] == result["decision"]


def test_audit_chain_intact_and_tamper_detectable():
    evaluate()
    evaluate(amount=900)
    assert audit_service.verify_chain() is True

    # Tamper with a stored event → the chain must break.
    victim = audit_service.all_events()[0]
    original = victim.risk_score
    victim.risk_score = 1.0
    assert audit_service.verify_chain() is False
    victim.risk_score = original  # restore for other tests
    assert audit_service.verify_chain() is True


# ---------------------------------------------------------------------------
# Policy library architecture (native + customer libraries, per-tenant)
# ---------------------------------------------------------------------------

from app.services import policy_loader, policy_resolver, policy_validator


def test_native_policies_load_correctly():
    library = policy_loader.load_native_library()
    assert library["version"] == "v1"
    assert "v1" in policy_loader.list_native_versions()
    policies = library["policies"]
    assert len(policies) >= 8
    # Every native policy carries the governance metadata the resolver needs.
    for policy in policies:
        assert "critical" in policy, policy["id"]
        assert policy["severity"] in {"low", "medium", "high", "critical"}, policy["id"]
        assert "allowed_by_native_policy" in policy, policy["id"]


def test_customer_policies_load_correctly():
    customer = policy_loader.load_customer_library("demo_customer")
    assert customer is not None
    assert customer["tenant_id"] == "demo_customer"
    assert "high_value_refund_policy" in customer["overrides"]
    assert any(
        p["policy_id"] == "demo_vip_review_policy" for p in customer["custom_policies"]
    )
    # Unknown and unsafe tenant ids return None (no file, no path traversal).
    assert policy_loader.load_customer_library("no_such_tenant") is None
    assert policy_loader.load_customer_library("../../etc/passwd") is None


def test_customer_override_changes_refund_threshold():
    resolved = policy_resolver.resolve("demo_customer")
    refund = next(
        p for p in resolved["policies"] if p["id"] == "high_value_refund_policy"
    )
    # Native threshold is 500; demo_customer raises it to 1000.
    assert refund["conditions"]["amount_greater_than"] == 1000
    assert refund["route_to"] == "demo_finance_approvals"
    assert resolved["warnings"] == []


def test_customer_cannot_disable_critical_native_policy():
    native = policy_loader.load_native_library()
    hostile = {
        "tenant_id": "hostile",
        "overrides": {"financial_transaction_policy": {"enabled": False}},
    }
    # The validator rejects it...
    report = policy_validator.validate_customer_library(hostile, native)
    assert report["valid"] is False
    assert any("cannot be disabled" in e for e in report["errors"])
    # ...and the resolver fail-safes: the policy stays enabled in the merge.
    policies, warnings = policy_resolver.apply_customer_library(native, hostile)
    wire = next(p for p in policies if p["id"] == "financial_transaction_policy")
    assert wire["enabled"] is True
    assert any("cannot be disabled" in w for w in warnings)


def test_customer_cannot_lower_severity_of_critical_native_policy():
    native = policy_loader.load_native_library()
    hostile = {
        "tenant_id": "hostile",
        "overrides": {
            "financial_transaction_policy": {"decision": "human_approval_required"},
            "legal_escalation_policy": {"severity": "low"},
        },
    }
    report = policy_validator.validate_customer_library(hostile, native)
    assert report["valid"] is False
    assert any("cannot lower the decision" in e for e in report["errors"])
    assert any("cannot lower the severity" in e for e in report["errors"])
    # Raising severity on a critical native IS allowed (agent → block).
    raiser = {
        "tenant_id": "raiser",
        "overrides": {"financial_transaction_policy": {"decision": "block"}},
    }
    assert policy_validator.validate_customer_library(raiser, native)["valid"] is True


def test_customer_cannot_override_threshold_unless_native_allows():
    native = policy_loader.load_native_library()
    # large_financial_exposure_policy has allowed_by_native_policy=false.
    sneaky = {
        "tenant_id": "sneaky",
        "overrides": {
            "large_financial_exposure_policy": {"conditions": {"amount_at_least": 999999}}
        },
    }
    report = policy_validator.validate_customer_library(sneaky, native)
    assert report["valid"] is False
    assert any("does not allow condition" in e for e in report["errors"])


def test_customer_custom_policy_triggers():
    result = evaluate(tenant_id="demo_customer", customer_tier="vip", amount=50)
    assert "demo_vip_review_policy" in result["triggered_policies"]
    assert result["decision"] == "human_approval_required"
    assert result["route_to"] == "vip_account_desk"
    # The custom policy's risk_modifier (+10) shows up in the breakdown.
    factors = [item["factor"] for item in result["risk_breakdown"]]
    assert "policy_risk_modifiers" in factors


def test_evaluate_uses_tenant_policies_when_tenant_id_provided():
    # amount=750 exceeds the NATIVE 500 threshold but not demo_customer's 1000.
    native_result = evaluate(amount=750)
    assert native_result["decision"] == "human_approval_required"
    tenant_result = evaluate(tenant_id="demo_customer", amount=750)
    assert "high_value_refund_policy" not in tenant_result["triggered_policies"]
    assert tenant_result["decision"] == "allow"
    # Above the tenant threshold the override routes to THEIR approvals team.
    tenant_big = evaluate(tenant_id="demo_customer", amount=1500)
    assert "high_value_refund_policy" in tenant_big["triggered_policies"]
    assert tenant_big["route_to"] == "demo_finance_approvals"


def test_missing_tenant_id_falls_back_to_native():
    result = evaluate(amount=750)  # no tenant_id in payload
    assert "high_value_refund_policy" in result["triggered_policies"]
    assert result["decision"] == "human_approval_required"
    assert result["route_to"] == "approval_queue"


def test_unknown_tenant_falls_back_to_native_with_flag():
    result = evaluate(tenant_id="ghost_tenant", amount=750)
    assert result["decision"] == "human_approval_required"  # native behaviour
    assert "tenant_library_not_found" in result["flags"]


def test_tenant_critical_policies_still_enforced():
    # demo_customer's overrides must NOT weaken critical native protections.
    result = evaluate(
        tenant_id="demo_customer",
        task_type="data_export",
        proposed_action="export_data",
    )
    assert result["decision"] == "block"
    assert "pii_data_export_policy" in result["triggered_policies"]


def test_policy_library_endpoints():
    response = client.get("/policies/native")
    assert response.status_code == 200
    body = response.json()
    assert body["version"] == "v1"
    assert body["count"] >= 8

    response = client.get("/policies/customer/demo_customer")
    assert response.status_code == 200
    assert response.json()["tenant_id"] == "demo_customer"

    response = client.get("/policies/customer/ghost_tenant")
    assert response.status_code == 404

    response = client.get("/policies/resolved/demo_customer")
    assert response.status_code == 200
    body = response.json()
    assert body["tenant_id"] == "demo_customer"
    assert any(p.get("library") == "customer" for p in body["policies"])

    response = client.get("/policies/resolved/ghost_tenant")
    assert response.status_code == 404


def test_validate_endpoint_accepts_candidate_library():
    # Stored library validates clean.
    response = client.post("/policies/customer/demo_customer/validate")
    assert response.status_code == 200
    assert response.json()["valid"] is True

    # A hostile candidate posted in the body is rejected with reasons.
    hostile = {
        "tenant_id": "demo_customer",
        "overrides": {"pii_data_export_policy": {"enabled": False}},
        "custom_policies": [{"policy_id": "incomplete_policy"}],
    }
    response = client.post("/policies/customer/demo_customer/validate", json=hostile)
    assert response.status_code == 200
    body = response.json()
    assert body["valid"] is False
    assert any("cannot be disabled" in e for e in body["errors"])
    assert any("missing required field" in e for e in body["errors"])


# ---------------------------------------------------------------------------
# Operational endpoints
# ---------------------------------------------------------------------------

def test_health():
    response = client.get("/health")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ok"
    assert body["policies_loaded"] >= 5


def test_metrics_counts_decisions():
    before = client.get("/metrics").json()["total_requests"]
    evaluate()
    after = client.get("/metrics").json()
    assert after["total_requests"] == before + 1
    assert after["audit_chain_intact"] is True


def test_cors_allows_crelis_domains():
    # Browsers send a preflight OPTIONS request before cross-origin POSTs;
    # the engine must grant our production frontends.
    for origin in ["https://demo.crelis.ai", "https://crelis.ai"]:
        response = client.options(
            "/trust/evaluate",
            headers={
                "Origin": origin,
                "Access-Control-Request-Method": "POST",
            },
        )
        assert response.status_code == 200, origin
        assert response.headers.get("access-control-allow-origin") == origin


def test_cors_rejects_unknown_origin():
    response = client.options(
        "/trust/evaluate",
        headers={
            "Origin": "https://evil.example.com",
            "Access-Control-Request-Method": "POST",
        },
    )
    # Starlette answers preflights from unknown origins with 400 and no
    # allow-origin header — the browser will refuse to send the real request.
    assert response.headers.get("access-control-allow-origin") is None


def test_policies_listing_and_reload():
    response = client.get("/policies")
    assert response.status_code == 200
    assert response.json()["count"] >= 5

    response = client.post("/policies/reload")
    assert response.status_code == 200
    assert response.json()["status"] == "reloaded"
