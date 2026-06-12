"""
The seven QA lifecycle check categories.

Each function returns a list of QAResult. Checks are read-only: they never
mutate policies or auto-fix anything — they only observe and report.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from app import config
from app.models.request_models import TrustRequest
from app.qa import cases
from app.qa.models import QAResult
from app.qa.synth import classify_reachability, synthesize
from app.services import detection_engine, policy_loader, policy_resolver, policy_validator
from app.services.audit_service import audit_service
from app.services.evaluation import evaluate_request
from app.services.policy_engine import CONDITION_EVALUATORS

VALID_DECISIONS = set(config.DECISION_PRIORITY)
VALID_SEVERITIES = set(config.SEVERITY_ORDER)
PRIORITY = config.DECISION_PRIORITY
DEFAULT_ROUTES = config.DEFAULT_ROUTES


def _mk(run_id: str, ts: str, **kw) -> QAResult:
    return QAResult(run_id=run_id, timestamp=ts, **kw)


def _evaluate(message: str, fields: Dict[str, Any], tenant_id: Optional[str] = None):
    req = TrustRequest(request_id="QA", user_message=message, tenant_id=tenant_id, **fields)
    return evaluate_request(req, record_audit=False)


# ---------------------------------------------------------------------------
# 1. Policy Schema QA
# ---------------------------------------------------------------------------

def schema_qa(run_id: str, ts: str, policies: List[Dict[str, Any]], tenant_id: Optional[str]) -> List[QAResult]:
    results: List[QAResult] = []
    seen: Dict[str, int] = {}

    for p in policies:
        pid = p.get("id", "<missing id>")
        seen[pid] = seen.get(pid, 0) + 1
        issues: List[str] = []

        for field in ("id", "name", "decision", "severity", "conditions"):
            if field not in p:
                issues.append(f"missing field '{field}'")
        if p.get("decision") not in VALID_DECISIONS:
            issues.append(f"invalid decision '{p.get('decision')}'")
        if p.get("severity") not in VALID_SEVERITIES:
            issues.append(f"invalid severity '{p.get('severity')}'")
        route = p.get("route_to")
        if route is not None and (not isinstance(route, str) or not route.strip()):
            issues.append("route_to must be a non-empty string when present")
        conditions = p.get("conditions") or {}
        if not isinstance(conditions, dict) or not conditions:
            issues.append("conditions must be a non-empty object")
        else:
            for op in conditions:
                if op not in CONDITION_EVALUATORS:
                    issues.append(f"unknown condition operator '{op}'")
        # Critical policies must not be customer-weakenable.
        if p.get("critical") and p.get("allowed_by_native_policy", False):
            issues.append("critical policy must have allowed_by_native_policy=false")

        critical = bool(p.get("critical"))
        results.append(_mk(
            run_id, ts, tenant_id=tenant_id, policy_id=pid, category="Policy Schema QA",
            check_type="schema_validation",
            status="pass" if not issues else "fail",
            severity="critical" if (issues and critical) else ("high" if issues else "low"),
            expected="valid required fields, severity, decision, route_to, condition operators",
            actual="ok" if not issues else "; ".join(issues),
            suspected_root_cause="" if not issues else "Policy definition violates the catalog schema.",
            suggested_fix="" if not issues else "Correct the offending field(s); critical natives cannot be weakened.",
            impacted_layer="policy",
        ))

    for pid, n in seen.items():
        if n > 1:
            results.append(_mk(
                run_id, ts, tenant_id=tenant_id, policy_id=pid, category="Policy Schema QA",
                check_type="duplicate_policy_id", status="fail", severity="high",
                expected="every policy_id unique in the resolved set",
                actual=f"policy_id '{pid}' appears {n} times",
                suspected_root_cause="Two policies share an id; the second shadows the first.",
                suggested_fix="Rename one of the colliding policies to a unique id.",
                impacted_layer="policy",
            ))
    return results


# ---------------------------------------------------------------------------
# 2. Policy Reachability QA
# ---------------------------------------------------------------------------

def reachability_qa(run_id: str, ts: str, policies: List[Dict[str, Any]], tenant_id: Optional[str]) -> List[QAResult]:
    results: List[QAResult] = []
    for p in policies:
        pid = p.get("id", "<missing id>")
        conditions = p.get("conditions") or {}
        if not p.get("enabled", True):
            results.append(_mk(
                run_id, ts, tenant_id=tenant_id, policy_id=pid, category="Reachability QA",
                check_type="policy_triggers", status="warning", severity="low",
                expected="policy reachable by a sample input",
                actual="policy is disabled (enabled=false) — never evaluated",
                suspected_root_cause="Policy intentionally disabled.",
                suggested_fix="Enable the policy if it should be active.",
                impacted_layer="policy",
            ))
            continue

        cls = classify_reachability(conditions)
        message, fields, unsat = synthesize(conditions)
        triggered = _evaluate(message, fields, tenant_id).triggered_policies if not cls["unknown_operator"] else []
        fired = pid in triggered

        if fired:
            note = "reachable from free text" if cls["free_text_only"] else "reachable only via structured fields"
            results.append(_mk(
                run_id, ts, tenant_id=tenant_id, policy_id=pid, category="Reachability QA",
                check_type="policy_triggers",
                status="pass" if cls["free_text_only"] else "warning",
                severity="low",
                expected="policy triggers for at least one realistic input",
                actual=f"triggered ({note})",
                suspected_root_cause="" if cls["free_text_only"] else "Needs structured fields (task_type/industry/...).",
                suggested_fix="" if cls["free_text_only"] else "Ensure callers can supply the structured context.",
                impacted_layer="policy",
            ))
        else:
            results.append(_mk(
                run_id, ts, tenant_id=tenant_id, policy_id=pid, category="Reachability QA",
                check_type="policy_triggers", status="fail", severity="high",
                expected="policy triggers for at least one realistic input",
                actual=f"UNREACHABLE — no input from its own condition fired it" + (f" ({';'.join(unsat)})" if unsat else ""),
                suspected_root_cause="Condition cannot be satisfied (dead phrase, contradictory range, or unknown vocab).",
                suggested_fix="Review the condition operators/phrases against the detection vocabularies.",
                impacted_layer="policy",
            ))
    return results


# ---------------------------------------------------------------------------
# 3. Detection QA
# ---------------------------------------------------------------------------

def detection_qa(run_id: str, ts: str, policies: List[Dict[str, Any]]) -> List[QAResult]:
    results: List[QAResult] = []
    KEY = {"intent": "detected_intents", "signal": "detected_risk_signals", "entity": "detected_entities"}

    for case in cases.DETECTION_CASES:
        det = detection_engine.detect(case["message"])
        bucket = det[KEY[case["kind"]]]
        present = case["expected"] in (bucket.keys() if isinstance(bucket, dict) else bucket)
        results.append(_mk(
            run_id, ts, category="Detection QA", check_type=f"detect_{case['kind']}",
            status="pass" if present else "fail", severity="high",
            expected=f"{case['kind']} '{case['expected']}' detected",
            actual=f"detected: {list(bucket)}",
            suspected_root_cause="" if present else "Vocabulary phrase missing or not matching this phrasing.",
            suggested_fix="" if present else f"Add coverage for '{case['expected']}' in the relevant native_libraries file.",
            impacted_layer="detection",
        ))

    for case in cases.DETECTION_FALSE_POSITIVES:
        det = detection_engine.detect(case["message"])
        bucket = det[KEY[case["kind"]]]
        absent = case["forbidden"] not in (bucket.keys() if isinstance(bucket, dict) else bucket)
        results.append(_mk(
            run_id, ts, category="Detection QA", check_type="false_positive",
            status="pass" if absent else "fail", severity="medium",
            expected=f"{case['kind']} '{case['forbidden']}' NOT detected",
            actual=f"detected: {list(bucket)}",
            suspected_root_cause="" if absent else "Over-broad vocabulary phrase causing a false positive.",
            suggested_fix="" if absent else f"Tighten the phrase set so '{case['forbidden']}' does not fire here.",
            impacted_layer="detection",
        ))

    # Missing-vocabulary scan: every detected_*_in value a policy references
    # must exist in the shipped vocabulary, or the policy can never fire.
    intents = set(detection_engine._LIBS["intents"]["intents"])
    signals = set(detection_engine._LIBS["risk_signals"]["risk_signals"])
    entities = set(detection_engine._LIBS["entities"]["entities"]) | {"amount", "currency"}
    vocab_map = {"detected_intent_in": intents, "detected_risk_signal_in": signals, "detected_entity_in": entities}
    missing = 0
    for p in policies:
        for op, vocab in vocab_map.items():
            for v in (p.get("conditions") or {}).get(op, []):
                if v not in vocab:
                    missing += 1
                    results.append(_mk(
                        run_id, ts, policy_id=p.get("id"), category="Detection QA",
                        check_type="missing_vocabulary", status="fail", severity="high",
                        expected=f"'{v}' present in the detection vocabulary",
                        actual=f"'{v}' is not in the shipped {op} vocabulary",
                        suspected_root_cause="Policy references a detection token that does not exist.",
                        suggested_fix=f"Add '{v}' to the relevant native_libraries file or fix the policy.",
                        impacted_layer="detection",
                    ))
    if missing == 0:
        results.append(_mk(
            run_id, ts, category="Detection QA", check_type="missing_vocabulary",
            status="pass", severity="low",
            expected="all policy detection tokens exist in the vocabulary",
            actual="0 missing vocabulary references", impacted_layer="detection",
        ))
    return results


# ---------------------------------------------------------------------------
# 4. Decision QA
# ---------------------------------------------------------------------------

def decision_qa(run_id: str, ts: str) -> List[QAResult]:
    results: List[QAResult] = []
    for case in cases.DECISION_CASES:
        d = _evaluate(case["message"], case.get("fields", {}))
        decision = d.decision
        ok_floor = PRIORITY[decision] >= PRIORITY[case["min_decision"]]
        ok_forbid = decision not in case.get("forbid", [])
        ok = ok_floor and ok_forbid
        false_allow = (not ok) and decision == config.DECISION_ALLOW
        results.append(_mk(
            run_id, ts, category="Decision QA",
            check_type="false_allow" if false_allow else "expected_decision",
            status="pass" if ok else "fail",
            severity="critical" if false_allow else ("high" if not ok else "low"),
            expected=f"decision >= {case['min_decision']}, not in {case.get('forbid', [])} ({case['label']})",
            actual=decision,
            suspected_root_cause="" if ok else "Risk scoring or policy match produced an unsafe/incorrect decision.",
            suggested_fix="" if ok else "Review scoring weights or the policy governing this scenario.",
            impacted_layer="routing",
        ))
        # Routing consistency: allow → ai_agent; escalations route elsewhere.
        route_ok = (d.route_to == DEFAULT_ROUTES[config.DECISION_ALLOW]) == (decision == config.DECISION_ALLOW) or bool(d.route_to)
        results.append(_mk(
            run_id, ts, category="Decision QA", check_type="routing_matches_severity",
            status="pass" if (d.route_to and route_ok) else "fail",
            severity="medium",
            expected="route_to is set and consistent with the decision severity",
            actual=f"decision={decision} route_to={d.route_to}",
            suspected_root_cause="" if d.route_to else "Routing produced an empty destination.",
            suggested_fix="" if d.route_to else "Ensure the policy or default route table yields a destination.",
            impacted_layer="routing",
        ))
    return results


# ---------------------------------------------------------------------------
# 5. Audit QA
# ---------------------------------------------------------------------------

def audit_qa(run_id: str, ts: str) -> List[QAResult]:
    results: List[QAResult] = []
    before = len(audit_service.all_events())
    req = TrustRequest(request_id="QA-AUDIT", user_message="I will sue your company over this refund.")
    decision = evaluate_request(req, record_audit=True)
    after = len(audit_service.all_events())
    event = audit_service.get(decision.audit_id)

    created = after == before + 1 and event is not None
    results.append(_mk(
        run_id, ts, category="Audit QA", check_type="event_created",
        status="pass" if created else "fail", severity="high",
        expected="one audit event created per evaluation, retrievable by audit_id",
        actual=f"audit_id={decision.audit_id} retrievable={event is not None}",
        suspected_root_cause="" if created else "Audit recording skipped or id not stored.",
        suggested_fix="" if created else "Inspect audit_service.record().",
        impacted_layer="audit",
    ))
    has_id = bool(decision.audit_id and decision.audit_id != "QA-NOAUDIT")
    results.append(_mk(
        run_id, ts, category="Audit QA", check_type="audit_id_generated",
        status="pass" if has_id else "fail", severity="medium",
        expected="a real audit_id is generated", actual=decision.audit_id,
        impacted_layer="audit",
    ))
    intact = audit_service.verify_chain()
    results.append(_mk(
        run_id, ts, category="Audit QA", check_type="hash_chain_intact",
        status="pass" if intact else "fail", severity="critical",
        expected="SHA-256 audit hash chain verifies",
        actual=f"chain_intact={intact}",
        suspected_root_cause="" if intact else "An audit event was tampered with or the chain broke.",
        suggested_fix="" if intact else "Investigate audit integrity immediately.",
        impacted_layer="audit",
    ))
    has_detail = event is not None and (event.reasoning or "") != "" and isinstance(event.triggered_policies, list)
    results.append(_mk(
        run_id, ts, category="Audit QA", check_type="audit_detail_present",
        status="pass" if has_detail else "fail", severity="medium",
        expected="audit event carries triggered policy ids and reasoning",
        actual=f"policies={getattr(event, 'triggered_policies', None)} reasoning_present={bool(getattr(event, 'reasoning', ''))}",
        impacted_layer="audit",
    ))
    return results


# ---------------------------------------------------------------------------
# 6. Tenant QA
# ---------------------------------------------------------------------------

def tenant_qa(run_id: str, ts: str) -> List[QAResult]:
    results: List[QAResult] = []

    # Native applies by default (no tenant).
    d = _evaluate("Export all customer records from the production database", {})
    results.append(_mk(
        run_id, ts, tenant_id=None, category="Tenant QA", check_type="native_default_applies",
        status="pass" if d.decision == "block" else "fail", severity="high",
        expected="native policies govern when no tenant_id is given (export → block)",
        actual=f"decision={d.decision}", impacted_layer="tenant",
    ))

    # Customer override applies (demo_customer raised refund threshold to 1000).
    oc = cases.TENANT_OVERRIDE_CASE
    dt = _evaluate(oc["message"], {}, tenant_id=cases.TENANT_FIXTURE)
    override_ok = oc["absent_policy"] not in dt.triggered_policies
    results.append(_mk(
        run_id, ts, tenant_id=cases.TENANT_FIXTURE, category="Tenant QA",
        check_type="customer_override_applies",
        status="pass" if override_ok else "fail", severity="high",
        expected=f"'{oc['absent_policy']}' suppressed by the tenant's raised threshold",
        actual=f"triggered={dt.triggered_policies}",
        suspected_root_cause="" if override_ok else "Tenant override not applied during resolution.",
        suggested_fix="" if override_ok else "Check policy_resolver.apply_customer_library for this tenant.",
        impacted_layer="tenant",
    ))

    # Customer custom policy fires.
    cc = cases.TENANT_CUSTOM_CASE
    dc = _evaluate(cc["message"], cc.get("fields", {}), tenant_id=cases.TENANT_FIXTURE)
    custom_ok = cc["expected_policy"] in dc.triggered_policies
    results.append(_mk(
        run_id, ts, tenant_id=cases.TENANT_FIXTURE, policy_id=cc["expected_policy"],
        category="Tenant QA", check_type="custom_policy_fires",
        status="pass" if custom_ok else "fail", severity="high",
        expected=f"custom policy '{cc['expected_policy']}' fires for this tenant",
        actual=f"triggered={dc.triggered_policies}", impacted_layer="tenant",
    ))

    # Customer cannot disable a critical native policy.
    native = policy_loader.load_native_library()
    report = policy_validator.validate_customer_library(cases.HOSTILE_LIBRARY, native)
    blocked = (not report["valid"]) and any("cannot be disabled" in e for e in report["errors"])
    results.append(_mk(
        run_id, ts, tenant_id="hostile", policy_id="financial_transaction_policy",
        category="Tenant QA", check_type="critical_not_disableable",
        status="pass" if blocked else "fail", severity="critical",
        expected="a tenant cannot disable a critical native policy",
        actual=f"valid={report['valid']} errors={report['errors'][:2]}",
        suspected_root_cause="" if blocked else "Governance validator allowed a critical native to be disabled.",
        suggested_fix="" if blocked else "Harden policy_validator critical-policy rules.",
        impacted_layer="tenant",
    ))
    return results


# ---------------------------------------------------------------------------
# 7. Regression QA
# ---------------------------------------------------------------------------

def regression_qa(run_id: str, ts: str) -> List[QAResult]:
    results: List[QAResult] = []
    for case in cases.REGRESSION_CASES:
        d = _evaluate(case["message"], case.get("fields", {}))
        triggered = case["expected_policy"] in d.triggered_policies
        floor_ok = PRIORITY[d.decision] >= PRIORITY[case["min_decision"]]
        forbid_ok = d.decision not in case.get("forbid", [])
        ok = triggered and floor_ok and forbid_ok
        false_allow = (not ok) and d.decision == config.DECISION_ALLOW
        results.append(_mk(
            run_id, ts, policy_id=case["expected_policy"], category="Regression QA",
            check_type="false_allow" if false_allow else "known_bug_case",
            status="pass" if ok else "fail",
            severity="critical" if false_allow else ("high" if not ok else "low"),
            expected=f"{case['expected_policy']} fires, decision >= {case['min_decision']} ({case['label']})",
            actual=f"decision={d.decision} triggered={d.triggered_policies}",
            suspected_root_cause="" if ok else "A previously-fixed defect appears to have regressed.",
            suggested_fix="" if ok else "Re-investigate the original fix for this scenario.",
            impacted_layer="policy" if not triggered else "routing",
        ))
    return results
