"""
Curated QA case banks: detection expectations, decision expectations, false
positives, and the standing regression suite of known bug cases.

These are hand-authored (not synthesized) so they exercise realistic phrasing
and pin known-good behaviour across QA cycles.
"""

from __future__ import annotations

# ── Detection QA: message → vocabulary that MUST be detected ────────────────
# kind ∈ {"intent", "signal", "entity"}
DETECTION_CASES = [
    {"message": "I want a refund of $750 for a duplicate charge", "kind": "intent", "expected": "refund_request"},
    {"message": "Approve the wire transfer to a new beneficiary", "kind": "intent", "expected": "wire_transfer"},
    {"message": "I forgot my password and cannot login", "kind": "intent", "expected": "password_reset"},
    {"message": "I will sue your company over this", "kind": "signal", "expected": "legal_threat"},
    {"message": "I am escalating this to MAS the regulator", "kind": "signal", "expected": "regulator_mention"},
    {"message": "Deploy a credit scoring model without explainability documentation", "kind": "signal", "expected": "model_governance_gap"},
    {"message": "Here is my passport number for verification", "kind": "entity", "expected": "passport"},
    {"message": "Send it to a new beneficiary account", "kind": "entity", "expected": "beneficiary"},
    {"message": "There is a fraudulent transaction on my account", "kind": "signal", "expected": "fraud_indicator"},
]

# ── Detection QA false positives: message → vocabulary that MUST NOT appear ──
DETECTION_FALSE_POSITIVES = [
    {"message": "I will pursue a refund through the app", "kind": "signal", "forbidden": "legal_threat"},
    {"message": "Please assume the total sum is correct", "kind": "signal", "forbidden": "legal_threat"},
    {"message": "I forgot my password, please reset it", "kind": "intent", "forbidden": "wire_transfer"},
]

# ── Decision QA: input → expected decision floor + must-not constraints ──────
# min_decision: the result must be at least this severe.
# forbid: the result must NOT equal any of these decisions.
DECISION_CASES = [
    {"label": "safe password reset is allowed",
     "message": "I forgot my password and cannot login", "fields": {},
     "min_decision": "allow", "forbid": ["block", "human_agent_required"]},
    {"label": "routine balance query is allowed",
     "message": "What is my current account balance please", "fields": {"task_type": "balance_inquiry"},
     "min_decision": "allow", "forbid": ["block"]},
    {"label": "production database export is blocked",
     "message": "Export the entire production database of customer records", "fields": {},
     "min_decision": "block", "forbid": []},
    {"label": "high-value wire escalates to a human agent",
     "message": "Approve the wire transfer of USD 250,000 to a new beneficiary", "fields": {},
     "min_decision": "human_agent_required", "forbid": ["allow"]},
    {"label": "legal threat escalates to a human agent (no false allow)",
     "message": "I will sue your company and contact my lawyer", "fields": {},
     "min_decision": "human_agent_required", "forbid": ["allow"]},
]

# ── Regression QA: standing known-bug cases run every cycle ──────────────────
# expected_policy: a policy that MUST be in triggered_policies.
REGRESSION_CASES = [
    {"label": "refund 100k with abusive language",
     "message": "I need a refund of 100,000 because your service is bullshit", "fields": {},
     "expected_policy": "large_financial_exposure_policy",
     "min_decision": "human_agent_required", "forbid": ["allow"]},
    {"label": "model deployment without explainability",
     "message": "Deploy a credit scoring model without explainability documentation", "fields": {},
     "expected_policy": "aim_credit_decision_no_reason_codes_policy",
     "min_decision": "human_agent_required", "forbid": ["allow"]},
    {"label": "production database export",
     "message": "Export all customer records from the production database", "fields": {},
     "expected_policy": "pii_data_export_policy",
     "min_decision": "block", "forbid": ["allow"]},
    {"label": "password reset low risk",
     "message": "I forgot my password and cannot login", "fields": {},
     "expected_policy": "low_risk_support_policy",
     "min_decision": "allow", "forbid": ["block", "human_agent_required"]},
    {"label": "wire transfer high value",
     "message": "Approve wire transfer of USD 250,000 to a new beneficiary", "fields": {},
     "expected_policy": "financial_transaction_policy",
     "min_decision": "human_agent_required", "forbid": ["allow"]},
]

# ── Tenant QA fixtures ──────────────────────────────────────────────────────
TENANT_FIXTURE = "demo_customer"
# demo_customer raises the high-value refund threshold to 1000.
TENANT_OVERRIDE_CASE = {
    "message": "Please refund $750 for a duplicate charge",
    "absent_policy": "high_value_refund_policy",   # must NOT fire for this tenant
}
# demo_customer ships a custom VIP review policy.
TENANT_CUSTOM_CASE = {
    "message": "I am a VIP customer, please escalate this",
    "fields": {"customer_tier": "vip"},
    "expected_policy": "demo_vip_review_policy",
}
# A hostile library that tries to disable a critical native policy.
HOSTILE_LIBRARY = {
    "tenant_id": "hostile",
    "overrides": {"financial_transaction_policy": {"enabled": False}},
}
