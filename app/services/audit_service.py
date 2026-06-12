"""
Stage 5 — Audit Service (tamper-evident, in-memory for v0.1).

Every decision the engine makes is written to an append-only log. Two advanced
properties make this more than a plain list:

  1. HASH CHAIN — each event stores a SHA-256 hash of its own content PLUS the
     hash of the previous event. Editing any past record breaks every hash
     after it, so tampering is detectable. This is the property compliance
     teams (SOC 2, EU AI Act, MAS guidelines) actually pay for.

  2. VERIFIABILITY — `verify_chain()` re-computes the whole chain on demand,
     and /metrics exposes whether it is intact.

v0.1 stores the log in memory (per the spec: no database yet). v0.2 swaps the
list for a database table — the hashing logic stays identical.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Dict, List, Optional

from app.models.response_models import AuditEvent

# The very first event in a chain links back to this constant.
GENESIS_HASH = "0" * 64


def _utc_now_iso() -> str:
    """Current UTC time in ISO-8601 with a trailing 'Z', e.g. 2026-06-12T10:30:00Z."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _hash_event(payload: Dict) -> str:
    """Deterministically hash an event's content (sorted keys = stable hash)."""
    encoded = json.dumps(payload, sort_keys=True, default=str).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


class AuditService:
    """Append-only, hash-chained, in-memory audit log."""

    def __init__(self) -> None:
        self._events: List[AuditEvent] = []
        self._counter = 0
        self._decision_counts: Dict[str, int] = {}

    # -- writing --------------------------------------------------------------

    def record(
        self,
        *,
        request_id: str,
        source_system: Optional[str],
        industry: Optional[str],
        task_type: Optional[str],
        decision: str,
        risk_score: float,
        confidence_score: float,
        triggered_policies: List[str],
        reasoning: str,
        detected_intents: Optional[List[str]] = None,
        detected_risk_signals: Optional[List[str]] = None,
        detection_confidence: float = 0.0,
    ) -> AuditEvent:
        """Create, chain, store, and return a new audit event."""
        self._counter += 1
        year = datetime.now(timezone.utc).year
        audit_id = f"AUD-{year}-{self._counter:04d}"
        timestamp = _utc_now_iso()
        prev_hash = self._events[-1].event_hash if self._events else GENESIS_HASH

        # Hash everything EXCEPT event_hash itself. Numbers are coerced to
        # float FIRST so the hash computed here matches the one recomputed
        # later from the stored Pydantic model (which types them as float —
        # json.dumps renders 91 and 91.0 differently).
        content = {
            "audit_id": audit_id,
            "request_id": request_id,
            "timestamp": timestamp,
            "source_system": source_system,
            "industry": industry,
            "task_type": task_type,
            "decision": decision,
            "risk_score": float(risk_score),
            "confidence_score": float(confidence_score),
            "triggered_policies": triggered_policies,
            "reasoning": reasoning,
            "detected_intents": detected_intents or [],
            "detected_risk_signals": detected_risk_signals or [],
            "detection_confidence": float(detection_confidence),
            "sequence": self._counter,
            "prev_hash": prev_hash,
        }
        event = AuditEvent(**content, event_hash=_hash_event(content))

        self._events.append(event)
        self._decision_counts[decision] = self._decision_counts.get(decision, 0) + 1
        return event

    # -- reading ----------------------------------------------------------------

    def all_events(self) -> List[AuditEvent]:
        return list(self._events)

    def get(self, audit_id: str) -> Optional[AuditEvent]:
        for event in self._events:
            if event.audit_id == audit_id:
                return event
        return None

    def decision_counts(self) -> Dict[str, int]:
        return dict(self._decision_counts)

    def total(self) -> int:
        return self._counter

    # -- integrity ----------------------------------------------------------------

    def verify_chain(self) -> bool:
        """
        Recompute every hash from scratch. True only if NOTHING was altered
        and every link points at the right predecessor.
        """
        prev_hash = GENESIS_HASH
        for event in self._events:
            if event.prev_hash != prev_hash:
                return False
            content = event.model_dump(exclude={"event_hash"})
            if _hash_event(content) != event.event_hash:
                return False
            prev_hash = event.event_hash
        return True


# One shared log for the whole app.
audit_service = AuditService()
