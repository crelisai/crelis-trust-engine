"""QA result / run data models (Pydantic, JSON-serializable for the API)."""

from __future__ import annotations

from typing import Dict, List, Optional

from pydantic import BaseModel, Field

# A single QA check outcome.
STATUSES = ("pass", "fail", "warning")
LAYERS = ("detection", "policy", "scoring", "routing", "audit", "tenant")
SEVERITIES = ("low", "medium", "high", "critical")


class QAResult(BaseModel):
    run_id: str
    timestamp: str
    tenant_id: Optional[str] = None
    policy_id: Optional[str] = None
    category: str                       # which QA lifecycle category, e.g. "Reachability QA"
    check_type: str                     # specific check, e.g. "policy_triggers"
    status: str                         # pass | fail | warning
    severity: str = "medium"            # low | medium | high | critical
    expected: str = ""
    actual: str = ""
    suspected_root_cause: str = ""
    suggested_fix: str = ""
    impacted_layer: str = "policy"      # detection | policy | scoring | routing | audit | tenant


class QARunSummary(BaseModel):
    run_id: str
    timestamp: str
    tenant_scope: List[str] = Field(default_factory=list)
    total_checks: int = 0
    passed: int = 0
    failed: int = 0
    warnings: int = 0
    # Headline health metrics surfaced on the QA Center page.
    health_score: float = 100.0
    pass_rate: float = 100.0
    failed_policies: int = 0
    critical_failures: int = 0
    unreachable_policies: int = 0
    structured_only_policies: int = 0
    false_allows: int = 0
    audit_chain_intact: bool = True
    tenant_override_health: str = "healthy"   # healthy | degraded | unknown
    by_layer: Dict[str, int] = Field(default_factory=dict)        # failures+warnings by layer
    by_category: Dict[str, Dict[str, int]] = Field(default_factory=dict)


class QARun(BaseModel):
    summary: QARunSummary
    results: List[QAResult] = Field(default_factory=list)


class ValidationGateResult(BaseModel):
    """Outcome of validating a candidate customer policy before activation."""
    tenant_id: Optional[str] = None
    policy_id: Optional[str] = None
    status: str                          # validated | draft_failed_validation
    activate_allowed: bool
    errors: List[str] = Field(default_factory=list)
    results: List[QAResult] = Field(default_factory=list)
