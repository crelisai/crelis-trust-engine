"""
Customer-policy validation gate.

When a customer creates a custom policy, this runs QA on it BEFORE activation:
schema validation (governance rules) + a reachability proof (can it actually
fire?). If either fails the policy is returned as `draft_failed_validation` and
must not be activated. This is the function a future "create policy" flow calls.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, Optional

from app.models.request_models import TrustRequest
from app.qa.models import QAResult, ValidationGateResult
from app.qa.synth import synthesize
from app.services import policy_loader, policy_validator
from app.services.normalizer import normalize_request
from app.services.policy_engine import PolicyEngine
from app.services.policy_resolver import _custom_to_internal


def _ts() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def validate_candidate_policy(policy: Dict[str, Any], tenant_id: Optional[str] = None) -> ValidationGateResult:
    run_id = "QA-VALIDATE"
    ts = _ts()
    results = []
    pid = policy.get("policy_id") if isinstance(policy, dict) else None

    native = policy_loader.load_native_library()
    native_ids = {p["id"] for p in native.get("policies", [])}

    # 1. Schema / governance validation.
    errors = policy_validator.validate_custom_policy(policy, native_ids, set())
    results.append(QAResult(
        run_id=run_id, timestamp=ts, tenant_id=tenant_id, policy_id=pid,
        category="Policy Schema QA", check_type="candidate_schema_validation",
        status="pass" if not errors else "fail",
        severity="high" if errors else "low",
        expected="candidate policy satisfies the custom-policy schema and governance rules",
        actual="ok" if not errors else "; ".join(errors),
        suspected_root_cause="" if not errors else "Candidate policy violates required-field / operator / collision rules.",
        suggested_fix="" if not errors else "Fix the reported field(s) before resubmitting.",
        impacted_layer="policy",
    ))

    # 2. Reachability proof — only meaningful if the schema is valid.
    reachable = False
    if not errors:
        try:
            internal = _custom_to_internal(policy)
            engine = PolicyEngine([internal], version="candidate")
            message, fields, _ = synthesize(policy.get("condition", {}))
            req = TrustRequest(request_id="QA-CAND", user_message=message, tenant_id=tenant_id, **fields)
            normalized = normalize_request(req)
            triggered, *_ = engine.evaluate(normalized)
            reachable = internal["id"] in [t.id for t in triggered]
        except Exception as exc:  # malformed condition surfaces as unreachable, not a crash
            reachable = False
            results.append(QAResult(
                run_id=run_id, timestamp=ts, tenant_id=tenant_id, policy_id=pid,
                category="Reachability QA", check_type="candidate_reachability_error",
                status="fail", severity="high",
                expected="candidate condition is evaluable",
                actual=f"error: {exc}", impacted_layer="policy",
            ))
        else:
            results.append(QAResult(
                run_id=run_id, timestamp=ts, tenant_id=tenant_id, policy_id=pid,
                category="Reachability QA", check_type="candidate_reachability",
                status="pass" if reachable else "fail",
                severity="high",
                expected="candidate policy triggers for at least one realistic input",
                actual="reachable" if reachable else "no synthesized input fired the policy",
                suspected_root_cause="" if reachable else "Condition cannot be satisfied by any input.",
                suggested_fix="" if reachable else "Adjust the condition operators/phrases so the policy can fire.",
                impacted_layer="policy",
            ))

    passed = (not errors) and reachable
    return ValidationGateResult(
        tenant_id=tenant_id, policy_id=pid,
        status="validated" if passed else "draft_failed_validation",
        activate_allowed=passed,
        errors=errors,
        results=results,
    )
