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
