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

from typing import Any, Dict, Optional

from fastapi import Body, FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware

from app import config
from app.models.request_models import TrustRequest
from app.models.response_models import (
    AuditListResponse,
    HealthResponse,
    MetricsResponse,
    RiskFactor,
    TrustDecision,
)
from app.models.response_models import DetectionResult
from app.services import (
    detection_engine,
    policy_loader,
    policy_resolver,
    policy_validator,
    risk_scoring,
    routing_engine,
)
from app.services.audit_service import audit_service
from app.services.normalizer import normalize_request

app = FastAPI(
    title=config.ENGINE_NAME,
    version=config.ENGINE_VERSION,
    description=(
        "AI Governance Runtime — evaluates AI action requests against risk "
        "models and declarative policies, returns auditable routing decisions."
    ),
)

# Allow the Crelis web frontends (and local dev servers) to call this API
# directly from the browser. Origins are configured in app/config.py and can
# be extended at deploy time via the CORS_EXTRA_ORIGINS env var.
app.add_middleware(
    CORSMiddleware,
    allow_origins=config.CORS_ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
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

    # 3. Policies — resolve the tenant's policy set (native + customer
    #    overrides + custom policies), then evaluate the request against it.
    engine, resolved = policy_resolver.engine_for(request.tenant_id)
    if resolved["customer_library_missing"]:
        # Unknown tenant: we governed with native defaults — say so visibly.
        flags = flags + ["tenant_library_not_found"]
    triggered, risk_floor, risk_ceiling, risk_modifier = engine.evaluate(normalized)
    if risk_modifier:
        risk_breakdown = risk_breakdown + [
            RiskFactor(
                factor="policy_risk_modifiers",
                points=risk_modifier,
                detail="Risk adjustment contributed by triggered policies.",
            )
        ]

    # 4. Route — pick the winning decision, final risk, destination, reasoning.
    decision, route_to, final_risk, reasoning = routing_engine.decide(
        normalized, triggered, base_risk, risk_floor, risk_ceiling, engine,
        risk_modifier=risk_modifier,
    )

    # 5. Audit — record the decision in the tamper-evident log.
    detection = normalized["detection"]
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
        route_to=route_to,
        detected_intents=normalized["detected_intents"],
        detected_risk_signals=normalized["detected_risk_signals"],
        detection_confidence=detection["detection_confidence"],
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
        detection=DetectionResult(
            detected_intents=normalized["detected_intents"],
            detected_entities={
                k: [str(v) for v in vals]
                for k, vals in detection["detected_entities"].items()
            },
            detected_risk_signals=normalized["detected_risk_signals"],
            detected_sentiment=detection["detected_sentiment"],
            detected_urgency=detection["detected_urgency"],
            detected_industry_context=detection["detected_industry_context"],
            detected_amounts=detection["detected_amounts"],
            detection_confidence=detection["detection_confidence"],
        ),
        engine_version=config.ENGINE_VERSION,
    )


# ---------------------------------------------------------------------------
# Operational endpoints (advanced features)
# ---------------------------------------------------------------------------

@app.get("/health", response_model=HealthResponse, tags=["ops"])
def health() -> HealthResponse:
    """Liveness check — useful for load balancers and uptime monitors."""
    engine, _ = policy_resolver.engine_for(None)
    return HealthResponse(
        status="ok",
        engine=config.ENGINE_NAME,
        version=config.ENGINE_VERSION,
        policies_loaded=len(engine.policies),
    )


@app.get("/metrics", response_model=MetricsResponse, tags=["ops"])
def metrics() -> MetricsResponse:
    """Aggregate decision counters + audit-chain integrity flag."""
    engine, _ = policy_resolver.engine_for(None)
    return MetricsResponse(
        total_requests=audit_service.total(),
        decisions=audit_service.decision_counts(),
        audit_chain_length=len(audit_service.all_events()),
        audit_chain_intact=audit_service.verify_chain(),
        average_risk_score=audit_service.average_risk_score(),
        policies_loaded=len(engine.policies),
        last_decision_at=audit_service.last_event_at(),
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
    """The native default policy set (what governs requests with no tenant)."""
    engine, resolved = policy_resolver.engine_for(None)
    return {
        "pack_version": engine.pack_version,
        "count": len(engine.policies),
        "policies": resolved["policies"],
    }


@app.post("/policies/reload", tags=["policies"])
def reload_policies():
    """
    Hot-reload every policy library from disk WITHOUT restarting the server.
    Edit the JSON files, call this, and the new rules are live for all tenants.
    """
    detection_engine.reload()
    policy_resolver.clear_cache()
    try:
        engine, _ = policy_resolver.engine_for(None)
    except Exception as exc:  # bad JSON should report clearly, not crash the app
        raise HTTPException(status_code=400, detail=f"Policy reload failed: {exc}")
    return {"status": "reloaded", "policies_loaded": len(engine.policies)}


# ---------------------------------------------------------------------------
# Policy library endpoints (native vs customer vs resolved)
# ---------------------------------------------------------------------------

@app.get("/policies/native", tags=["policies"])
def get_native_policies():
    """The Crelis-maintained native policy library (latest shipped version)."""
    library = policy_loader.load_native_library()
    return {
        "library": library.get("library", "crelis_native"),
        "version": library.get("version"),
        "available_versions": policy_loader.list_native_versions(),
        "count": len(library.get("policies", [])),
        "policies": library.get("policies", []),
    }


@app.get("/policies/customer/{tenant_id}", tags=["policies"])
def get_customer_policies(tenant_id: str):
    """One tenant's raw customer policy library (overrides + custom policies)."""
    customer = policy_loader.load_customer_library(tenant_id)
    if customer is None:
        raise HTTPException(
            status_code=404,
            detail=f"No customer policy library found for tenant '{tenant_id}'.",
        )
    return customer


@app.get("/policies/resolved/{tenant_id}", tags=["policies"])
def get_resolved_policies(tenant_id: str):
    """
    The FINAL policy set for a tenant after resolution:
    native library + customer overrides + customer custom policies.
    """
    resolved = policy_resolver.resolve(tenant_id)
    if resolved["customer_library_missing"] or resolved["tenant_id"] is None:
        raise HTTPException(
            status_code=404,
            detail=f"No customer policy library found for tenant '{tenant_id}'.",
        )
    return resolved


@app.post("/policies/customer/{tenant_id}/validate", tags=["policies"])
def validate_customer_policies(
    tenant_id: str,
    library: Optional[Dict[str, Any]] = Body(
        None,
        description=(
            "Optional candidate library to validate BEFORE saving. "
            "Omit the body to validate the tenant's stored library."
        ),
    ),
):
    """
    Validate a customer policy library against the governance rules
    (critical natives can't be disabled, severity can only be raised, ...).
    """
    if library is None:
        library = policy_loader.load_customer_library(tenant_id)
        if library is None:
            raise HTTPException(
                status_code=404,
                detail=f"No customer policy library found for tenant '{tenant_id}'.",
            )
    native = policy_loader.load_native_library()
    report = policy_validator.validate_customer_library(library, native)
    return {"tenant_id": tenant_id, **report}
