"""
Regression tests for the model-deployment / explainability classification bug.

Reported: "Deploy a credit scoring model without explainability documentation."
was evaluated as refund_request / allow / no policies. Root cause was a stale
task_type=refund_request sent by the UI; separately, the bare message matched
no AI Model Governance policy. These tests pin the engine-side behaviour:

  * the message must NOT be classified as refund_request when no task_type
    forces it,
  * task_type=model_deployment must trigger an AI Model Governance policy and
    not allow,
  * the free-text message alone must trigger the explainability policy and
    surface the model_governance_gap detection signal.
"""

from __future__ import annotations

from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)

MESSAGE = "Deploy a credit scoring model without explainability documentation."


def evaluate(**overrides):
    body = {"request_id": "REQ-MODELGOV", "user_message": MESSAGE, **overrides}
    response = client.post("/trust/evaluate", json=body)
    assert response.status_code == 200, response.text
    return response.json()


def test_message_alone_is_not_refund_request():
    # No task_type is forced — the engine must not invent a refund intent.
    r = evaluate()
    assert "refund_request" not in r["detection"]["detected_intents"]
    assert r["decision"] != "allow"


def test_message_alone_triggers_ai_governance_policy_and_signal():
    r = evaluate()
    assert "aim_credit_decision_no_reason_codes_policy" in r["triggered_policies"]
    assert "model_governance_gap" in r["detection"]["detected_risk_signals"]
    assert r["decision"] == "human_agent_required"


def test_task_type_model_deployment_not_allow():
    # The verification case from the bug report.
    r = evaluate(task_type="model_deployment")
    assert r["decision"] != "allow"
    assert "refund_request" not in r["detection"]["detected_intents"]
    assert any(p.startswith("aim_") for p in r["triggered_policies"]), r["triggered_policies"]
    assert "aim_production_model_deployment_gate_policy" in r["triggered_policies"]


def test_stale_refund_task_type_is_the_only_thing_that_forces_refund():
    # Documents the original symptom: ONLY an explicit refund task_type makes
    # the engine echo refund_request — confirming the fix belongs in the UI
    # (stop sending the stale task_type), which is handled in the frontend.
    r = evaluate(task_type="refund_request")
    assert "refund_request" in r["detection"]["detected_intents"]
