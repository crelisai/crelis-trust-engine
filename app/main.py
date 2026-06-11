"""
Crelis Trust Engine — API layer.

This file wires the five pipeline stages into HTTP endpoints:

    Inbound Request
      → Normalize        (services/normalizer.py)
      → Risk Scoring     (services/risk_scoring.py)
      → Policy Evaluation(services/policy_engine.py)
      → Routing Decision (services/routing_engine.py)
      → Audit Event      (services/audit_service.py)
      → Response

Run locally:
    uvicorn app.main:app --reload
Then open http://127.0.0.1:8000/docs for the interactive API explorer.
"""

from __future__ import annotations

from fastapi import FastAPI, HTTPException

from app import config
from app.models.request_models import TrustRequest
from app.models.response_models import (
    AuditListResponse,
    HealthResponse,
    MetricsResponse,
    TrustDecision,
)
from app.services import risk_scoring, routing_engine
from app.services.audit_service import audit_service
from app.services.normalizer import normalize_request
from app.services.policy_engine import policy_engine

app = FastAPI(
    title=config.ENGINE_NAME,
    version=config.ENGINE_VERSION,
    description=(
        "AI Governance Runtime — evaluates AI action requests against risk "
        "models and declarative policies, returns auditable routing decisions."
    ),
)


# ---------------------------------------------------------------------------
# Core endpoint
# ---------------------------------------------------------------------------

@app.post("/trust/evaluate", response_model=TrustDecision, tags=["governance"])
def evaluate(request: TrustRequest) -> TrustDecision:
    """
    Evaluate one AI action request and return a governance decision.

    This is the engine's whole pipeline in five readable steps.
    """
    # 1. Normalize — clean the input into a predictable shape.
    normalized = normalize_request(request)

    # 2. Score — how risky is it, and how complete is our picture?
    base_risk, risk_breakdown, flags = risk_scoring.calculate_risk(normalized)
    confidence = risk_scoring.calculate_confidence(normalized)
    if normalized["missing_critical"]:
        flags = flags + [f"missing_{f}" for f in normalized["missing_critical"]]

    # 3. Policies — which declarative rules fire?
    triggered, risk_floor, risk_ceiling = policy_engine.evaluate(normalized)

    # 4. Route — pick the winning decision, final risk, destination, reasoning.
    decision, route_to, final_risk, reasoning = routing_engine.decide(
        normalized, triggered, base_risk, risk_floor, risk_ceiling, policy_engine
    )

    # 5. Audit — record the decision in the tamper-evident log.
    audit_event = audit_service.record(
        request_id=normalized["request_id"],
        source_system=normalized["source_system"],
        industry=normalized["industry"],
        task_type=normalized["task_type"],
        decision=decision,
        risk_score=final_risk,
        confidence_score=confidence,
        triggered_policies=[p.id for p in triggered],
        reasoning=reasoning,
    )

    # 6. Respond.
    return TrustDecision(
        request_id=normalized["request_id"],
        audit_id=audit_event.audit_id,
        decision=decision,
        risk_score=final_risk,
        confidence_score=confidence,
        triggered_policies=[p.id for p in triggered],
        route_to=route_to,
        reasoning=reasoning,
        timestamp=audit_event.timestamp,
        schema_version=config.DECISION_SCHEMA_VERSION,
        risk_breakdown=risk_breakdown,
        policy_details=triggered,
        flags=flags,
        engine_version=config.ENGINE_VERSION,
    )


# ---------------------------------------------------------------------------
# Operational endpoints (advanced features)
# ---------------------------------------------------------------------------

@app.get("/health", response_model=HealthResponse, tags=["ops"])
def health() -> HealthResponse:
    """Liveness check — useful for load balancers and uptime monitors."""
    return HealthResponse(
        status="ok",
        engine=config.ENGINE_NAME,
        version=config.ENGINE_VERSION,
        policies_loaded=len(policy_engine.policies),
    )


@app.get("/metrics", response_model=MetricsResponse, tags=["ops"])
def metrics() -> MetricsResponse:
    """Aggregate decision counters + audit-chain integrity flag."""
    return MetricsResponse(
        total_requests=audit_service.total(),
        decisions=audit_service.decision_counts(),
        audit_chain_length=len(audit_service.all_events()),
        audit_chain_intact=audit_service.verify_chain(),
    )


@app.get("/audit", response_model=AuditListResponse, tags=["audit"])
def list_audit_events() -> AuditListResponse:
    """Dump the in-memory audit log (v0.1 — becomes paginated DB queries in v0.2)."""
    events = audit_service.all_events()
    return AuditListResponse(
        count=len(events),
        chain_intact=audit_service.verify_chain(),
        events=events,
    )


@app.get("/audit/{audit_id}", tags=["audit"])
def get_audit_event(audit_id: str):
    """Fetch one audit event by its id, e.g. AUD-2026-0001."""
    event = audit_service.get(audit_id)
    if event is None:
        raise HTTPException(status_code=404, detail=f"Audit event '{audit_id}' not found.")
    return event


@app.get("/policies", tags=["policies"])
def list_policies():
    """Show the currently-loaded policy pack (transparency for operators)."""
    return {
        "pack_version": policy_engine.pack_version,
        "count": len(policy_engine.policies),
        "policies": policy_engine.policies,
    }


@app.post("/policies/reload", tags=["policies"])
def reload_policies():
    """
    Hot-reload policy_rules.json from disk WITHOUT restarting the server.
    Edit the JSON, call this, and the new rules are live.
    """
    try:
        count = policy_engine.load()
    except Exception as exc:  # bad JSON should report clearly, not crash the app
        raise HTTPException(status_code=400, detail=f"Policy reload failed: {exc}")
    return {"status": "reloaded", "policies_loaded": count}
