"""
Core evaluation pipeline, extracted so it can be called in-process.

`evaluate_request` is the single source of truth for the five-stage pipeline.
The HTTP endpoint (`POST /trust/evaluate`) is a thin wrapper around it, and the
QA Center calls it with `record_audit=False` so QA sweeps over hundreds of
policies never pollute the real audit chain. The returned TrustDecision shape
is identical regardless of `record_audit`.
"""

from __future__ import annotations

from datetime import datetime, timezone

from app import config
from app.models.request_models import TrustRequest
from app.models.response_models import DetectionResult, RiskFactor, TrustDecision
from app.services import policy_resolver, risk_scoring, routing_engine
from app.services.audit_service import audit_service
from app.services.normalizer import normalize_request


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def evaluate_request(request: TrustRequest, *, record_audit: bool = True) -> TrustDecision:
    """Run one request through the full governance pipeline.

    When `record_audit` is False the decision is computed identically but no
    audit event is written (used by QA dry-runs); audit_id/timestamp are filled
    with non-recorded placeholders.
    """
    # 1. Normalize — clean the input into a predictable shape.
    normalized = normalize_request(request)

    # 2. Score — how risky is it, and how complete is our picture?
    base_risk, risk_breakdown, flags = risk_scoring.calculate_risk(normalized)
    confidence = risk_scoring.calculate_confidence(normalized)
    if normalized["missing_critical"]:
        flags = flags + [f"missing_{f}" for f in normalized["missing_critical"]]

    # 3. Policies — resolve the tenant's policy set, then evaluate.
    engine, resolved = policy_resolver.engine_for(request.tenant_id)
    if resolved["customer_library_missing"]:
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

    # 4. Route — winning decision, final risk, destination, reasoning.
    decision, route_to, final_risk, reasoning = routing_engine.decide(
        normalized, triggered, base_risk, risk_floor, risk_ceiling, engine,
        risk_modifier=risk_modifier,
    )

    # 5. Audit — record the decision in the tamper-evident log (unless dry-run).
    detection = normalized["detection"]
    if record_audit:
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
        audit_id, timestamp = audit_event.audit_id, audit_event.timestamp
    else:
        audit_id, timestamp = "QA-NOAUDIT", _utc_now_iso()

    # 6. Respond.
    return TrustDecision(
        request_id=normalized["request_id"],
        audit_id=audit_id,
        decision=decision,
        risk_score=final_risk,
        confidence_score=confidence,
        triggered_policies=[p.id for p in triggered],
        route_to=route_to,
        reasoning=reasoning,
        timestamp=timestamp,
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
