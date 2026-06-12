# Crelis Native Catalog — Authoring Specification (v1)

This document governs every `catalog_*.json` file in this directory. The
validation suite (`app/tests/test_native_catalog.py`) enforces the mechanical
rules below; the regulatory quality bar is enforced by review.

## File shape

```json
{
  "library": "crelis_native_catalog",
  "version": "v1",
  "category": "<Category Name>",
  "maintainer": "Crelis Regulatory Policy Office",
  "policies": [ ... ]
}
```

## Policy shape (ALL fields required)

```json
{
  "policy_id": "dp_nric_bulk_export_block_policy",
  "name": "Bulk NRIC export interdiction",
  "category": "Data Privacy & PII Protection",
  "subcategory": "National ID Handling",
  "description": "1-3 sentences. Concrete scenario + why the decision is what it is.",
  "severity": "low | medium | high | critical",
  "decision": "allow | human_approval_required | human_agent_required | block",
  "route_to": "snake_case_queue_name" or null,
  "enabled": true,
  "critical": false,
  "allowed_by_native_policy": true,
  "applicable_industries": ["banking", "insurance"] or ["all"],
  "applicable_regions": ["SG", "HK", "APAC", "global", ...],
  "regulatory_references": ["Singapore PDPA s.26 — Transfer Limitation"] or [],
  "condition": { "<operator>": <value>, ... },
  "risk_modifier": 0,
  "version": "v1"
}
```

- `policy_id`: `^[a-z0-9][a-z0-9_]*_policy$`, prefixed per category, unique,
  stable forever.
- `route_to: null` means "use the engine default route for the decision".
- `risk_modifier`: integer −20…30. Guidance: block 0; human_agent 10–25;
  human_approval 5–15; allow-with-flag 5–15.
- Do NOT use `risk_floor` / `risk_ceiling` — they are not part of the catalog
  schema.

## Decision semantics

The engine has exactly four decisions (priority: block > human_agent_required
> human_approval_required > allow). There is no separate "flag" decision —
a *flag-style* policy is `decision: "allow"` with a positive `risk_modifier`:
it appears in the triggered-policy list and raises the risk score without
gating the action.

Target mix per category (±10%): 15–25% allow/flag · 35–45% human_approval ·
25–35% human_agent · 5–12% block.

`critical: true` is reserved for policies a customer must NEVER be able to
disable: sanctions screening, CSAM, credential exfiltration, bulk PII export,
statutory regulator-notification duties. At most 2–4 per category, and
`critical: true` requires `allowed_by_native_policy: false`.

## Condition system (AND semantics; 1–3 operators per policy)

ONLY these operators exist. Anything else fails closed (the policy never
fires) and fails validation:

| Operator | Value | Matches against |
|---|---|---|
| `message_contains_any` | list of lowercase phrases | whole-word, case-insensitive match in user_message |
| `task_type_in` | list of strings | the caller-supplied task_type (any value is legal) |
| `proposed_action_in` | list of strings | caller-supplied proposed_action |
| `industry_in` | list of strings | caller-supplied industry |
| `channel_in` | list of strings | caller-supplied channel |
| `customer_tier_in` | list of strings | caller-supplied customer_tier |
| `amount_greater_than` / `amount_less_than` / `amount_at_least` | number | effective amount (field or extracted from message — the larger wins) |
| `detected_intent_in` | list from the intent vocabulary | detection engine output |
| `detected_risk_signal_in` | list from the signal vocabulary | detection engine output |
| `detected_entity_in` | list from the entity vocabulary | detection engine output |

Detection vocabularies (closed sets — values outside them fail validation):

- intents: refund_request, billing_dispute, legal_escalation, data_export,
  password_reset, mfa_reset, wire_transfer, customer_complaint,
  fraud_suspicion, regulator_complaint, vip_escalation,
  security_access_request, production_database_access
- risk signals: legal_threat, regulator_mention, abusive_language,
  urgent_pressure, fraud_indicator, credential_reset, admin_access,
  pii_exposure, production_data_access, external_transfer,
  large_financial_amount, vip_customer, reputational_risk
- entities: passport, nric, account_number, database, production_system,
  beneficiary, customer_record, regulator, region, customer_tier, email,
  phone_number, credit_card, amount, currency

Because the closed vocabularies are small, MOST scenario specificity comes
from `message_contains_any` with 4–10 precise, multi-word, lowercase phrases
(e.g. "aadhaar number", "sanctions list", "terminate the employee",
"recommended dosage"), optionally combined with industry / amount / task_type
context. `task_type_in` / `proposed_action_in` values are free-form — use
realistic agent task types (e.g. "employee_termination", "claim_approval",
"model_deployment") to govern structured agent-to-agent calls.

## Calibration guards (hard — enforced by tests)

1. NEVER `block` on: wire transfers, beneficiary changes, refunds, any
   amount-threshold policy, legal threats, or regulator mentions. Money
   movement and legal escalation go to humans (`human_agent_required`);
   blocks are for data exfiltration, prohibited content, sanctions hits,
   credential exfiltration, and similar interdictions.
2. Any policy referencing `password_reset` intent or `credential_reset`
   signal must be `decision: "allow"` (routine resets are the canonical
   low-risk automation case).
3. `industry_in` / `channel_in` may never be the only condition.
   `customer_tier_in` alone caps at human_approval_required.
4. Tone-only policies (abusive_language / urgent_pressure / customer
   complaint / billing dispute, without a >= 10000 amount gate or specific
   phrases) cap at human_approval_required.
5. `mfa_reset` intent alone or `admin_access` signal alone caps at
   human_approval_required.
6. refund_request-intent policies need an amount gate or message phrases.
7. Pure amount escalations to human_agent_required need thresholds >= 10000.
8. PROTECTED MESSAGES — these exact sentences are pinned by the regression
   suite. Your `message_contains_any` phrases must not match the level-0
   sentence at all, and matches against the others must not carry a decision
   above the listed cap (allow=1, approval=2, agent=3):

   - level 0: "i would like a refund please."
   - level 1: "i forgot my password and cannot login" · "i forgot my
     password." · "please unlock my account"
   - level 2: "my invoice has a wrong charge" · "i want my money back" ·
     "i need a manager immediately" · "your service is a scam" · "this is a
     scam and your support is useless." · "please refund $750 for a duplicate
     charge" · "i need mfa reset for my admin account" · "my email is
     jane@example.com, refund me."
   - level 3: all other money / legal / urgency sentences in the suite.

   Practical rule of thumb: never use generic single words ("refund",
   "password", "account", "manager", "urgent", "export", "please", "service")
   as phrases — always specific multi-word phrases.

## Regulatory citation rules

Cite only where the regulation genuinely governs the scenario, with the
instrument and provision/guideline name: "Singapore PDPA s.26D — Data Breach
Notification", "MAS FEAT Principles (2018) — Fairness F2", "APRA CPS 234
para 36", "India DPDP Act 2023 s.8 — Data Fiduciary Obligations", "China PIPL
art. 38 — Cross-border Transfer". A wrong citation is worse than none: if the
policy is best practice rather than law, use
["Industry best practice — <one-line anchor>"] or [].

## Anti-templating

Within a category, no two policies may share a description skeleton with
nouns swapped. Vary trigger style across the category: keyword patterns,
detected entities/intents/signals, structured task types, amount thresholds,
contextual combinations (industry + phrases, tier + amount, channel + intent).
Every description must say something a compliance officer would recognise as
domain-specific, not generic filler.
