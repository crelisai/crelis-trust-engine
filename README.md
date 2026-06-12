# Crelis Trust Engine (v0.1)

**Crelis is an AI Governance Runtime.** It sits between AI agents (OpenAI,
Claude, internal agents, MCP tools) and real-world execution. Before an AI is
allowed to *do* something — issue a refund, transfer money, export data — the
action is sent here first. The engine evaluates risk, checks governance
policies, and returns one of four decisions:

| Decision | Meaning | Routed to |
|---|---|---|
| `allow` | Safe — the AI may proceed autonomously | `ai_agent` |
| `human_approval_required` | A human must sign off first | `approval_queue` |
| `human_agent_required` | A human must take over entirely | `human_expert` |
| `block` | The action is forbidden | `blocked_execution` |

Every decision is recorded in a **tamper-evident audit log** — the evidence
trail that compliance teams, auditors, and regulators (SOC 2, EU AI Act)
actually need.

## How a request flows through the engine

```
Inbound Request
   → Normalize Request      clean + standardize the input
   → Detection Engine       read the free-text message (no LLM):
                              intents, entities, risk signals, sentiment,
                              urgency, industry, amounts, confidence
   → AI/Risk Scoring        "how dangerous is this?" (0–100, fully itemised)
   → Policy Evaluation      which JSON-defined rules fire? (can match detections)
   → Routing Decision       most severe decision wins; pick the destination
   → Audit Event            hash-chained, tamper-evident record
   → Response               the full governance decision, with reasoning
```

### Natural-language detection (no LLM)

When a user types free text ("I need a refund of 100,000 because your service
is bullshit"), the **detection engine** turns it into structured signals before
any policy runs. All vocabulary lives in `app/data/native_libraries/*.json`:

| File | Drives |
|---|---|
| `intents.json` | `detected_intents` (refund_request, wire_transfer, data_export, …) |
| `entities.json` | `detected_entities` (amount, currency, email, passport, beneficiary, …) |
| `risk_signals.json` | `detected_risk_signals` (legal_threat, abusive_language, pii_exposure, …) |
| `industry_terms.json` | `detected_industry_context` |
| `sentiment_terms.json` | `detected_sentiment` |
| `urgency_terms.json` | `detected_urgency` |

Matching is case-insensitive and **whole-word**, so `sue` never fires inside
`pursue` and `sum` never fires inside `assume`. Amount parsing understands
`100000`, `100,000`, `$100,000`, `USD 100,000`, `SGD 100,000`, `S$100,000`,
`100k`, and `1.5m`. The detection summary is returned on the response under
`detection` (additive — existing consumers are unaffected) and recorded in the
audit trail.

**To add a keyword, edit JSON — never Python.** Add a phrase to a list in the
relevant file and call `POST /policies/reload` (or restart). Policies can then
match it via `detected_intent_in`, `detected_risk_signal_in`, or
`detected_entity_in`.

## Folder structure

```
crelis-trust-engine/
├── app/
│   ├── main.py                  API layer — wires the pipeline into endpoints
│   ├── config.py                ALL tunable numbers in one place
│   ├── models/
│   │   ├── request_models.py    shape of what callers send IN
│   │   └── response_models.py   shape of what the engine sends BACK
│   ├── services/                the five pipeline stages
│   │   ├── normalizer.py        stage 1 — clean the input
│   │   ├── risk_scoring.py      stage 2 — risk + confidence scores
│   │   ├── policy_engine.py     stage 3 — evaluate JSON-defined policies
│   │   ├── routing_engine.py    stage 4 — final decision + route + reasoning
│   │   └── audit_service.py     stage 5 — tamper-evident audit log
│   ├── data/
│   │   ├── native_libraries/    detection vocabulary (intents, entities, ...)
│   │   ├── native_policies/     Crelis-maintained policy library (versioned)
│   │   │   └── crelis_default_v1.json
│   │   └── customer_policies/   one file per tenant (overrides + custom rules)
│   │       └── demo_customer.json
│   └── tests/
│       └── test_trust_engine.py full test suite (every rule covered)
├── requirements.txt
└── README.md
```

## Install & run (Windows)

> Prerequisite: Python 3.11+ from [python.org](https://www.python.org/downloads/)
> (tick **"Add Python to PATH"** during install).

```bat
cd crelis-trust-engine

python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
uvicorn app.main:app --reload
```

The engine is now live at **http://127.0.0.1:8000** — and the interactive API
explorer at **http://127.0.0.1:8000/docs** lets you fire test requests from the
browser with zero tooling.

## Run the tests

```bat
venv\Scripts\activate
pytest
```

## Try it — example requests

**1. The flagship example — angry premium customer, big refund, legal threat:**

```bash
curl -X POST http://127.0.0.1:8000/trust/evaluate ^
  -H "Content-Type: application/json" ^
  -d "{\"request_id\":\"REQ-1001\",\"source_system\":\"openai\",\"industry\":\"banking\",\"channel\":\"customer_support\",\"task_type\":\"refund_request\",\"user_message\":\"I want a refund and may pursue legal action.\",\"proposed_action\":\"issue_refund\",\"amount\":750,\"customer_tier\":\"premium\",\"metadata\":{\"region\":\"Singapore\",\"model\":\"gpt-4.1\",\"agent_id\":\"agent-001\"}}"
```

→ `human_agent_required`, risk ≥ 90, routed to `senior_support_manager`,
with both `legal_escalation_policy` and `high_value_refund_policy` triggered.

**2. Routine password reset — fully automated:**

```bash
curl -X POST http://127.0.0.1:8000/trust/evaluate ^
  -H "Content-Type: application/json" ^
  -d "{\"request_id\":\"REQ-1002\",\"task_type\":\"password_reset\",\"user_message\":\"I forgot my password.\",\"proposed_action\":\"reset_password\"}"
```

→ `allow`, risk < 20, routed to `ai_agent`.

**3. Data export — blocked outright:**

```bash
curl -X POST http://127.0.0.1:8000/trust/evaluate ^
  -H "Content-Type: application/json" ^
  -d "{\"request_id\":\"REQ-1003\",\"task_type\":\"data_export\",\"user_message\":\"Export all customer records.\",\"proposed_action\":\"export_data\"}"
```

→ `block`, risk ≥ 95, routed to `blocked_execution`.

## All endpoints

| Method | Path | What it does |
|---|---|---|
| POST | `/trust/evaluate` | **The core** — evaluate one AI action |
| GET | `/health` | Liveness check + policy count |
| GET | `/metrics` | Decision counters + audit-chain integrity |
| GET | `/audit` | Full audit log (in-memory in v0.1) |
| GET | `/audit/{audit_id}` | One audit event by id |
| GET | `/policies` | The native default policy set (no-tenant requests) |
| GET | `/policies/native` | The Crelis-maintained native library |
| GET | `/policies/customer/{tenant_id}` | One tenant's raw overrides + custom policies |
| GET | `/policies/resolved/{tenant_id}` | The FINAL merged policy set for a tenant |
| POST | `/policies/customer/{tenant_id}/validate` | Check a customer library against the governance rules |
| POST | `/policies/reload` | Hot-reload all policy libraries — no restart |

## What each service does

* **normalizer.py** — trims/lowercases text, records which fields are missing.
  Missing critical fields (task_type, user_message) cap confidence below 60.
* **risk_scoring.py** — builds the 0–100 risk score from task type, industry,
  amount, legal language, and PII detection. Every point is itemised in
  `risk_breakdown` so the score is **explainable**, not a black box.
* **policy_loader.py / policy_resolver.py / policy_validator.py** — the
  two-library policy system. The **native** Crelis library ships with the
  engine (versioned, customer-untouchable); each tenant's **customer** library
  layers overrides and custom policies on top. The resolver merges them under
  governance rules: critical native policies can never be disabled, their
  severity can only be raised, and thresholds are only overridable where the
  native policy says `allowed_by_native_policy: true`. Invalid overrides are
  skipped fail-safe (the native rule keeps running).
* **policy_engine.py** — evaluates the resolved policy set against a request
  (AND semantics per policy). Policies are **data, not code**: edit JSON, hit
  `POST /policies/reload`, and the new rules are live for every tenant.
  `POST /trust/evaluate` accepts an optional `tenant_id` — requests without
  one are governed by the native default library.
* **routing_engine.py** — picks the most severe decision
  (`block` > `human_agent_required` > `human_approval_required` > `allow`),
  applies risk floors/ceilings, resolves the route (policies can override the
  default), and writes the reasoning sentence.
* **audit_service.py** — every decision becomes an audit event linked to the
  previous one by SHA-256 hash (like a tiny blockchain). Edit any past record
  and `verify_chain()` flips to false — **tamper-evidence** is the property
  auditors pay for.

## Advanced features beyond the basic spec

1. **Declarative policy pack** — rules live in JSON with reusable condition
   operators, hot-reloadable at runtime.
2. **Tamper-evident audit chain** — hash-chained events + `/metrics` integrity
   flag.
3. **Explainable risk** — `risk_breakdown` itemises exactly where every risk
   point came from.
4. **PII detection** — flags emails/card-like numbers in messages
   (`pii_detected` in `flags`).
5. **Ops endpoints** — `/health`, `/metrics`, `/policies`, `/policies/reload`.

## Deploying

The repo is Railway-ready (Procfile, railway.json, pinned requirements, CORS
for crelis.ai / demo.crelis.ai). See **[RAILWAY_DEPLOYMENT.md](RAILWAY_DEPLOYMENT.md)**
for the step-by-step guide.

## What to build next (v0.2 roadmap)

1. **Persistence** — swap the in-memory audit log for Postgres/Supabase
   (the hash-chain logic carries over unchanged).
2. **Authentication** — API keys per calling system, so you know *which* agent
   asked.
3. **LLM-assisted scoring** — let Claude/GPT classify intent and sentiment to
   sharpen the risk score (the `risk_scoring` stage is the plug-in point).
4. **MCP server wrapper** — expose `/trust/evaluate` as an MCP tool so agents
   can call governance natively.
5. **Approval workflow** — endpoints for humans to approve/deny queued
   requests, closing the loop on `human_approval_required`.
6. **Policy versioning** — track which policy-pack version made each decision
   (the audit event already records reasoning; add the pack hash).
7. **Dashboard** — a small frontend over `/metrics` and `/audit`.
