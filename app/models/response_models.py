"""
Response models — what the engine sends BACK to the caller.

These also describe the audit event, the explainable risk breakdown, and the
health/metrics payloads. Everything the engine "decides" is captured here so it
is fully typed, validated, and self-documenting.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class RiskFactor(BaseModel):
    """One line-item explaining where a chunk of the risk score came from."""

    factor: str = Field(..., description="Name of the contributing factor.")
    points: float = Field(..., description="How many risk points it added.")
    detail: str = Field("", description="Human-readable explanation.")


class TriggeredPolicy(BaseModel):
    """A policy that matched the request, with why it matched."""

    id: str
    description: str = ""
    decision: str
    route_to: Optional[str] = None
    matched_on: str = Field("", description="Which condition caused the match.")


class DetectionResult(BaseModel):
    """
    The natural-language detection summary for one request.

    Additive, non-breaking field on TrustDecision — existing consumers that
    ignore it are unaffected; the Analyze box can render it to show WHY the
    engine decided what it did.
    """

    detected_intents: List[str] = Field(default_factory=list)
    detected_entities: Dict[str, List[str]] = Field(default_factory=dict)
    detected_risk_signals: List[str] = Field(default_factory=list)
    detected_sentiment: str = "neutral"
    detected_urgency: str = "none"
    detected_industry_context: List[str] = Field(default_factory=list)
    detected_amounts: List[float] = Field(default_factory=list)
    detection_confidence: float = 0.0


class AuditEvent(BaseModel):
    """
    An immutable, tamper-evident record of one governance decision.

    The `prev_hash` + `event_hash` pair chains every audit event to the one
    before it (like a tiny blockchain). If anyone edits a past record, every
    hash after it breaks — which is exactly what auditors and regulators want.
    """

    audit_id: str
    request_id: str
    timestamp: str
    source_system: Optional[str] = None
    industry: Optional[str] = None
    task_type: Optional[str] = None
    decision: str
    risk_score: float
    confidence_score: float
    triggered_policies: List[str] = Field(default_factory=list)
    reasoning: str = ""
    route_to: str = Field(
        "", description="Where the routing engine sent this request."
    )

    # Detection summary (added with the NL pipeline; defaulted for old events):
    detected_intents: List[str] = Field(default_factory=list)
    detected_risk_signals: List[str] = Field(default_factory=list)
    detection_confidence: float = 0.0

    # Tamper-evidence fields:
    sequence: int = Field(..., description="Position of this event in the chain.")
    prev_hash: str = Field(..., description="Hash of the previous audit event.")
    event_hash: str = Field(..., description="Hash of THIS audit event's content.")


class TrustDecision(BaseModel):
    """The primary object returned from POST /trust/evaluate."""

    request_id: str
    audit_id: str
    decision: str
    risk_score: float
    confidence_score: float
    triggered_policies: List[str] = Field(default_factory=list)
    route_to: str
    reasoning: str
    timestamp: str

    # --- Advanced / explainability fields (extra value over the base spec) ---
    schema_version: str = Field(
        ..., description="Version of this decision payload's shape."
    )
    risk_breakdown: List[RiskFactor] = Field(
        default_factory=list,
        description="Itemised explanation of how the risk score was built.",
    )
    policy_details: List[TriggeredPolicy] = Field(
        default_factory=list,
        description="Full detail of each policy that fired.",
    )
    flags: List[str] = Field(
        default_factory=list,
        description="Notable signals detected (e.g. 'pii_detected').",
    )
    detection: Optional[DetectionResult] = Field(
        None,
        description="Natural-language detection summary (intents, entities, signals).",
    )
    engine_version: str = ""


class HealthResponse(BaseModel):
    """Lightweight liveness payload for /health."""

    status: str
    engine: str
    version: str
    policies_loaded: int


class MetricsResponse(BaseModel):
    """Aggregate counters for /metrics — useful for dashboards."""

    total_requests: int
    decisions: Dict[str, int]
    audit_chain_length: int
    audit_chain_intact: bool
    average_risk_score: float = Field(
        0.0, description="Mean risk score across all recorded decisions."
    )
    policies_loaded: int = Field(
        0, description="Number of policies in the native default set."
    )
    last_decision_at: Optional[str] = Field(
        None, description="Timestamp of the most recent audit event, if any."
    )


class AuditListResponse(BaseModel):
    """Paginated-ish dump of the in-memory audit log for /audit."""

    count: int
    chain_intact: bool
    events: List[AuditEvent]
