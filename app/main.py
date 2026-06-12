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
    TrustDecision,
)
from app.services import (
    detection_engine,
    policy_loader,
    policy_resolver,
    policy_validator,
)
from app.services.audit_service import audit_service
from app.services.evaluation import evaluate_request
from app.api.qa_routes import router as qa_router

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

# Trust Engine QA Center (lifecycle policy/detection/routing/audit/tenant QA).
app.include_router(qa_router)


# ---------------------------------------------------------------------------
# Core endpoint
# ---------------------------------------------------------------------------

@app.post("/trust/evaluate", response_model=TrustDecision, tags=["governance"])
def evaluate(request: TrustRequest) -> TrustDecision:
    """
    Evaluate one AI action request and return a governance decision.

    Thin wrapper over `app.services.evaluation.evaluate_request`, which runs the
    five-stage pipeline (normalize → score → policies → route → audit).
    """
    return evaluate_request(request)


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
