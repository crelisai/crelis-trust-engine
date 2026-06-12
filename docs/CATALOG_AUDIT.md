# Native Catalog v1 — Pre-Commit Audit

Generated mechanically against `app/data/native_policies/` (14 `catalog_*.json`
files + `crelis_default_v1.json`). Reproduce with the validation suite:

```
pytest app/tests/test_native_catalog.py -v
```

All figures below are computed by loading the merged native library through
`app.services.policy_loader.load_native_library()` and inspecting the raw
catalog files — no hand counts.

---

## 1. Policy count by category

| Category | Policies |
|---|---|
| AI Model Governance & Explainability | 37 |
| Cybersecurity & Access Control | 37 |
| Data Privacy & PII Protection | 37 |
| ESG & Responsible AI | 37 |
| Financial Services & Banking | 37 |
| Fraud, AML & Financial Crime | 37 |
| HR & Workplace AI | 37 |
| Healthcare & Life Sciences | 37 |
| Insurance & Claims Governance | 37 |
| Intellectual Property & Confidentiality | 37 |
| Legal, Regulatory & Compliance | 37 |
| Prompt Injection & Adversarial Input | 37 |
| Retail, E-commerce & Consumer Protection | 37 |
| Telecom, Critical Infrastructure & Government | 37 |
| **Catalog subtotal** | **518** |
| Core (`crelis_default_v1`) | 16 |
| **TOTAL NATIVE** | **534** |

Decision mix across all 534: `human_approval_required` 212 · `human_agent_required`
172 · `allow` 90 · `block` 60. A deliberate escalate-first posture: most policies
route to a human; hard blocks are a minority reserved for interdictions.

---

## 2. Top 20 critical policies

55 policies are `critical: true` (46 catalog + 9 core) — never disableable by a
customer, and a customer may only RAISE their decision/severity. The 20 highest by
(decision priority, severity, risk_modifier) are all critical-severity blocks:

| policy_id | decision | category |
|---|---|---|
| dp_nric_bulk_export_block_policy | block | Data Privacy & PII Protection |
| dp_aadhaar_disclosure_block_policy | block | Data Privacy & PII Protection |
| fs_core_banking_production_access_block_policy | block | Financial Services & Banking |
| fs_payment_credential_exfiltration_block_policy | block | Financial Services & Banking |
| fs_bulk_account_data_export_block_policy | block | Financial Services & Banking |
| ins_sanctions_designated_party_block_policy | block | Insurance & Claims Governance |
| ins_policyholder_record_bulk_export_block_policy | block | Insurance & Claims Governance |
| hc_bulk_record_export_block_policy | block | Healthcare & Life Sciences |
| aim_social_scoring_use_block_policy | block | AI Model Governance & Explainability |
| aim_workplace_emotion_recognition_block_policy | block | AI Model Governance & Explainability |
| pi_credential_phishing_roleplay_block_policy | block | Prompt Injection & Adversarial Input |
| pi_system_secret_probe_block_policy | block | Prompt Injection & Adversarial Input |
| pi_audit_log_falsification_block_policy | block | Prompt Injection & Adversarial Input |
| pi_governance_bypass_instruction_block_policy | block | Prompt Injection & Adversarial Input |
| sec_api_secret_message_exfiltration_block_policy | block | Cybersecurity & Access Control |
| sec_logging_disable_block_policy | block | Cybersecurity & Access Control |
| sec_production_backup_deletion_block_policy | block | Cybersecurity & Access Control |
| aml_sanctions_list_match_block_policy | block | Fraud, AML & Financial Crime |
| aml_sanctions_screening_override_block_policy | block | Fraud, AML & Financial Crime |
| aml_tipping_off_disclosure_block_policy | block | Fraud, AML & Financial Crime |

These map to the scenarios a regulator expects to be uncompromisable: sanctions
screening, tipping-off, credential/PII/source-code exfiltration, audit-log
integrity, and prohibited AI uses.

---

## 3. Native policy category tree

96 subcategories across the 14 categories (6–8 each). Representative slices:

```
Fraud, AML & Financial Crime (37)
    7  Suspicious Transaction Patterns
    6  Sanctions & Watchlists
    6  Customer Risk Profiles
    6  Reporting Duties & Tipping-Off
    5  Scam & Victim Response
    4  Crypto & New Channels
    3  Account Controls & Internal Fraud

Healthcare & Life Sciences (37)
    6  Clinical Decision Boundaries
    6  Prescriptions & Medication Safety
    6  Patient Records & Confidentiality
    6  Telehealth & Cross-border Care
    5  Mental Health & Crisis Response
    5  Research, Trials & Genomics
    3  Insurance Interface & Therapeutic Marketing

Data Privacy & PII Protection (37)
    6  Cross-Border Transfer & Localisation
    5  National ID Handling
    5  Consent & Purpose Limitation
    5  Data Subject Rights
    4  Children's & Biometric Data
    4  Breach Response
    4  Retention & Erasure
    4  Direct Marketing & Third-Party Sharing
```

The full tree is enumerable from the `subcategory` field of every policy.

---

## 4. Sample policy from each category

| Category | policy_id | decision | grounding |
|---|---|---|---|
| Data Privacy & PII Protection | dp_nric_bulk_export_block_policy | block (critical) | Singapore PDPA s.24 — Protection Obligation |
| Financial Services & Banking | fs_beneficiary_registration_change_policy | human_agent | HKMA SPM TM-E-1 — Risk Management of E-banking |
| Insurance & Claims Governance | ins_claim_above_auto_settlement_threshold_policy | human_approval | IRDAI PPHI Regulations 2017 reg.15 (amount > 5,000) |
| Healthcare & Life Sciences | hc_ai_diagnosis_request_policy | human_agent | Singapore Healthcare Services Act 2020 |
| AI Model Governance & Explainability | aim_credit_decision_no_reason_codes_policy | human_agent | MAS FEAT Principles (2018) — Transparency |
| Prompt Injection & Adversarial Input | pi_ignore_previous_instructions_block_policy | block | OWASP Top 10 for LLM Applications — LLM01 |
| Cybersecurity & Access Control | sec_api_secret_message_exfiltration_block_policy | block (critical) | MAS TRM Guidelines 2021 — Access Management |
| Fraud, AML & Financial Crime | aml_sanctions_list_match_block_policy | block (critical) | UN Security Council Consolidated List |
| HR & Workplace AI | hr_protected_attribute_screening_policy | human_agent | TAFEP Fair Employment Guidelines |
| Legal, Regulatory & Compliance | lrc_customer_legal_advice_drafting_policy | human_agent | Singapore Legal Profession Act 1966 s.33 |
| Telecom, Critical Infrastructure & Government | cig_cii_config_change_control_policy | human_approval | Singapore Cybersecurity Act 2018 s.11 |
| Retail, E-commerce & Consumer Protection | rec_pricing_error_order_honour_policy | human_agent | *Chwee Kin Keong v Digilandmall.com* [2005] SGCA 2 |
| Intellectual Property & Confidentiality | ipc_source_code_personal_export_block_policy | block (critical) | *Coco v A N Clark (Engineers) Ltd* [1969] RPC 41 |
| ESG & Responsible AI | esg_carbon_neutral_claim_approval_policy | human_approval | ACCC Making Environmental Claims Guide (2023) |

---

## 5. Validation script output

```
app/tests/test_native_catalog.py::test_catalog_minimums                                PASSED
app/tests/test_native_catalog.py::test_policy_ids_unique_and_stable                     PASSED
app/tests/test_native_catalog.py::test_catalog_schema_and_enums                         PASSED
app/tests/test_native_catalog.py::test_catalog_conditions_use_supported_operators_only  PASSED
app/tests/test_native_catalog.py::test_catalog_phrases_respect_protected_messages       PASSED
app/tests/test_native_catalog.py::test_catalog_decision_calibration_guards              PASSED
app/tests/test_native_catalog.py::test_loader_merges_catalog_after_core                 PASSED
7 passed
```

Full engine suite (core + catalog): **101 passed**.

---

## 6. Duplicate policy IDs

**None.** All 534 ids (catalog + core) are unique. Every catalog id matches
`^[a-z0-9][a-z0-9_]*_policy$` and is category-prefixed.

---

## 7. Policies with missing / best-practice-only regulatory references

- **67 with empty `regulatory_references`** — by design. These are predominantly the
  `allow`/flag routine-operations policies (e.g. `hr_leave_balance_query_allow_policy`,
  `sec_ir_runbook_lookup_allow_policy`, `cig_network_health_query_policy`,
  `fs_account_opening_enquiry_allow_policy`, `ipc_nda_template_request_allow_policy`)
  where no statute genuinely governs the scenario. Per the authoring spec, an empty
  list is preferred over a contrived citation.
- **133 with best-practice-only references** (`"Industry best practice — ..."`),
  concentrated where soft-law is the right corpus: Prompt Injection 22 (OWASP/MITRE),
  Legal 18, Fraud/AML 12, Insurance 11, Healthcare 11.
- **318 carry statutory / regulatory citations** with instrument + provision.

A human compliance pass over the 318 cited policies is recommended before
customer-facing use — citations were authored by domain-prompted generation and
spot-checked, not formally legal-reviewed.

---

## 8. Reachability analysis (against the current detection engine)

Checked four failure modes per policy: unknown operators, detection vocabulary that
does not exist in the shipped libraries, dead phrase lists (phrases the whole-word
matcher can never match), and contradictory amount ranges.

| Metric | Count |
|---|---|
| Catalog policies analysed | 518 |
| (a) unknown operators | 0 |
| (b) vocabulary that does not exist | 0 |
| (c) dead phrase lists (matcher-immune) | 0 |
| (d) contradictory amount ranges | 0 |
| **Effectively unreachable (a∣b∣c∣d)** | **0** |

### The three bottom-line questions

- **How many can actually fire today using the current detection engine?**
  **All 518** (534 incl. core). Every condition uses a live operator and, where it
  references detection output, only vocabulary the detection engine actually produces.
- **How many require detection vocabulary that does not yet exist?**
  **0.** Enforced by `test_catalog_conditions_use_supported_operators_only`: any
  `detected_intent_in` / `detected_risk_signal_in` / `detected_entity_in` value
  outside the shipped vocabularies fails the build. Scenario specificity beyond the
  closed vocab is carried by `message_contains_any` phrase lists.
- **How many are effectively unreachable?**
  **0**, by all four checks above.

### Reachability nuance

| Bucket | Count | Notes |
|---|---|---|
| Fireable from FREE TEXT alone | 380 | message phrases / detection / amounts — exercisable from the Decision Studio textarea |
| Need structured request fields | 138 | fireable by any API caller |
| ↳ of those, not reachable from the demo task-type dropdown | 94 | key on exotic `task_type` values (`claim_approval`, `model_deployment`, `cii_config_change`, …) |

The 94 are reachable today via the API. The prototype's Advanced Context Task Type
field has been made free-text (datalist-backed) so these are now reachable from the
demo UI as well.
