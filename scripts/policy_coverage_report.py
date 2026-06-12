"""
Policy coverage harness.

For every native policy (core + catalog), synthesize a realistic request that
should satisfy that policy's condition, run it through the real /trust/evaluate
pipeline, and verify the policy actually triggers. Reports coverage gaps,
wrong-policy captures, decision mismatches, and reachability classification.

Run from the repo root:
    venv\\Scripts\\python.exe scripts\\policy_coverage_report.py

Outputs:
    docs/POLICY_COVERAGE_REPORT.md
    docs/policy_coverage_failures.csv

This script is read-only with respect to engine logic and policy data.
"""

from __future__ import annotations

import csv
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from fastapi.testclient import TestClient  # noqa: E402

from app.main import app  # noqa: E402
from app.services import policy_loader  # noqa: E402

LIB = ROOT / "app" / "data" / "native_libraries"
DOCS = ROOT / "docs"

client = TestClient(app)

# ---------------------------------------------------------------------------
# Vocabulary (used to synthesize inputs for detection-based conditions)
# ---------------------------------------------------------------------------

INTENTS = json.loads((LIB / "intents.json").read_text(encoding="utf-8"))["intents"]
SIGNALS = json.loads((LIB / "risk_signals.json").read_text(encoding="utf-8"))["risk_signals"]
ENTITIES = json.loads((LIB / "entities.json").read_text(encoding="utf-8"))["entities"]

REGEX_ENTITY_SAMPLES = {
    "email": "jane@example.com",
    "phone_number": "+1 415 555 0172",
    "credit_card": "4111 1111 1111 1111",
    "nric": "s1234567a",
}

STRUCTURED_OPS = {
    "task_type_in", "proposed_action_in", "industry_in", "channel_in", "customer_tier_in",
}
# Every structured field a condition can key on is settable from the Decision
# Studio UI (task_type is now free text; the rest are inputs/selects), so a
# policy is UI-unreachable only if it uses an operator outside this universe.
UI_REACHABLE_OPS = STRUCTURED_OPS | {
    "message_contains_any", "detected_intent_in", "detected_risk_signal_in",
    "detected_entity_in", "amount_greater_than", "amount_less_than", "amount_at_least",
}


def intent_phrase(intent: str) -> str | None:
    phrases = INTENTS.get(intent)
    return phrases[0] if phrases else None


def satisfy_entity(entity: str, msg_parts: list[str]) -> bool:
    spec = ENTITIES.get(entity)
    if not spec:
        return False
    match = spec["match"]
    if match == "phrase":
        msg_parts.append(spec["phrases"][0])
        return True
    if match == "regex":
        sample = REGEX_ENTITY_SAMPLES.get(entity)
        if sample:
            msg_parts.append(sample)
            return True
        return False
    if match in ("amount", "currency"):
        msg_parts.append("$25,000")
        return True
    return False


def satisfy_signal(signal: str, msg_parts: list[str]) -> bool:
    spec = SIGNALS.get(signal)
    if not spec:
        return False
    if "phrases" in spec:
        msg_parts.append(spec["phrases"][0])
        return True
    if "derived_from_intents" in spec:
        phrase = intent_phrase(spec["derived_from_intents"][0])
        if phrase:
            msg_parts.append(phrase)
            return True
    if "derived_from_entities" in spec:
        return satisfy_entity(spec["derived_from_entities"][0], msg_parts)
    if "derived_amount_threshold" in spec:
        msg_parts.append(f"${int(spec['derived_amount_threshold']) + 1}")
        return True
    if spec.get("derived_abusive_and_complaint"):
        msg_parts.append(SIGNALS["abusive_language"]["phrases"][0])
        complaint = intent_phrase("customer_complaint")
        if complaint:
            msg_parts.append(complaint)
        return True
    return False


def synthesize(conditions: dict) -> tuple[str, dict, list[str]]:
    """Return (message, structured_fields, unsatisfiable_reasons) for a condition."""
    msg_parts: list[str] = []
    fields: dict = {}
    unsat: list[str] = []
    gt = atleast = lt = None

    for op, val in conditions.items():
        if op == "message_contains_any":
            msg_parts.append(val[0])
        elif op == "task_type_in":
            fields["task_type"] = val[0]
        elif op == "proposed_action_in":
            fields["proposed_action"] = val[0]
        elif op == "industry_in":
            fields["industry"] = val[0]
        elif op == "channel_in":
            fields["channel"] = val[0]
        elif op == "customer_tier_in":
            fields["customer_tier"] = val[0]
        elif op == "amount_greater_than":
            gt = val
        elif op == "amount_at_least":
            atleast = val
        elif op == "amount_less_than":
            lt = val
        elif op == "detected_intent_in":
            phrase = intent_phrase(val[0])
            (msg_parts.append(phrase) if phrase else unsat.append(f"intent:{val[0]}"))
        elif op == "detected_risk_signal_in":
            if not satisfy_signal(val[0], msg_parts):
                unsat.append(f"signal:{val[0]}")
        elif op == "detected_entity_in":
            if not satisfy_entity(val[0], msg_parts):
                unsat.append(f"entity:{val[0]}")
        else:
            unsat.append(f"unsupported_op:{op}")

    lower = None
    if gt is not None:
        lower = gt + 1
    if atleast is not None:
        lower = max(lower or 0, atleast)
    amount = lower
    if lt is not None:
        if amount is None:
            amount = max(0, lt - 1)
        elif amount >= lt:
            unsat.append("amount_range_conflict")
    if amount is not None:
        fields["amount"] = amount

    message = " ".join(f"{p}." for p in msg_parts) if msg_parts else "Please process this routine request."
    return message, fields, unsat


# ---------------------------------------------------------------------------
# Static reachability classification
# ---------------------------------------------------------------------------

def classify(conditions: dict) -> dict:
    ops = set(conditions)
    return {
        "requires_task_type": "task_type_in" in ops,
        "requires_structured": bool(ops & STRUCTURED_OPS),
        "free_text_only": not (ops & STRUCTURED_OPS),
        "ui_unreachable": bool(ops - UI_REACHABLE_OPS),
    }


# ---------------------------------------------------------------------------
# Run coverage
# ---------------------------------------------------------------------------

def main() -> None:
    library = policy_loader.load_native_library()
    policies = library["policies"]

    rows = []
    for p in policies:
        pid = p["id"]
        category = p.get("category", "Core (v1)")
        conditions = p.get("conditions", {})
        enabled = p.get("enabled", True)
        decision = p["decision"]
        cls = classify(conditions)

        message, fields, unsat = synthesize(conditions)
        body = {"request_id": "COV", "user_message": message, **fields}
        resp = client.post("/trust/evaluate", json=body).json()
        triggered = resp["triggered_policies"]
        final_decision = resp["decision"]

        if not enabled:
            status = "DISABLED"
        elif pid in triggered:
            status = "TRIGGERED"
        elif triggered:
            status = "WRONG_POLICY"
        else:
            status = "NOT_TRIGGERED"

        success = status == "TRIGGERED"
        decision_match = (final_decision == decision) if success else None

        rows.append({
            "policy_id": pid,
            "category": category,
            "status": status,
            "policy_decision": decision,
            "final_decision": final_decision,
            "decision_match": decision_match,
            "triggered_policies": ";".join(triggered),
            "message": message,
            "fields": json.dumps(fields),
            "unsat": ";".join(unsat),
            **cls,
        })

    # -- aggregate ----------------------------------------------------------
    total = len(rows)
    by_status = Counter(r["status"] for r in rows)
    triggered_ok = by_status["TRIGGERED"]
    not_triggered = by_status["NOT_TRIGGERED"]
    wrong_policy = by_status["WRONG_POLICY"]
    disabled = by_status["DISABLED"]
    decision_mismatch = sum(1 for r in rows if r["status"] == "TRIGGERED" and r["decision_match"] is False)
    requires_task_type = sum(1 for r in rows if r["requires_task_type"])
    requires_structured = sum(1 for r in rows if r["requires_structured"])
    free_text_only = sum(1 for r in rows if r["free_text_only"])
    ui_unreachable = sum(1 for r in rows if r["ui_unreachable"])

    cat_stats: dict = defaultdict(lambda: Counter())
    for r in rows:
        cat_stats[r["category"]][r["status"]] += 1

    failures = [r for r in rows if r["status"] in ("NOT_TRIGGERED", "WRONG_POLICY")]
    decision_failures = [r for r in rows if r["status"] == "TRIGGERED" and r["decision_match"] is False]

    DOCS.mkdir(exist_ok=True)

    # -- CSV ----------------------------------------------------------------
    csv_path = DOCS / "policy_coverage_failures.csv"
    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["policy_id", "category", "status", "policy_decision", "final_decision",
                    "decision_match", "triggered_policies", "message", "fields", "unsat_reasons"])
        for r in failures + decision_failures:
            w.writerow([r["policy_id"], r["category"], r["status"], r["policy_decision"],
                        r["final_decision"], r["decision_match"], r["triggered_policies"],
                        r["message"], r["fields"], r["unsat"]])

    # -- Markdown -----------------------------------------------------------
    pct = lambda n: f"{100 * n / total:.1f}%"
    lines = []
    lines.append("# Native Policy Coverage Report\n")
    lines.append("Auto-generated by `scripts/policy_coverage_report.py`. For each native")
    lines.append("policy, a request is synthesized from the policy's own condition and run")
    lines.append("through `/trust/evaluate`; the policy should appear in `triggered_policies`.\n")
    lines.append("## Summary\n")
    lines.append("| Metric | Count | % |")
    lines.append("|---|---:|---:|")
    lines.append(f"| Total native policies | {total} | 100% |")
    lines.append(f"| Triggered successfully | {triggered_ok} | {pct(triggered_ok)} |")
    lines.append(f"| Not triggered (nothing fired) | {not_triggered} | {pct(not_triggered)} |")
    lines.append(f"| Wrong policy (other fired, not expected) | {wrong_policy} | {pct(wrong_policy)} |")
    lines.append(f"| Disabled (intentionally off) | {disabled} | {pct(disabled)} |")
    lines.append(f"| Decision mismatch (triggered, decision differs) | {decision_mismatch} | {pct(decision_mismatch)} |")
    lines.append("")
    lines.append("## Reachability\n")
    lines.append("| Metric | Count | % |")
    lines.append("|---|---:|---:|")
    lines.append(f"| Reachable from free text only | {free_text_only} | {pct(free_text_only)} |")
    lines.append(f"| Require structured fields | {requires_structured} | {pct(requires_structured)} |")
    lines.append(f"| Require structured task_type | {requires_task_type} | {pct(requires_task_type)} |")
    lines.append(f"| Unreachable from the UI | {ui_unreachable} | {pct(ui_unreachable)} |")
    lines.append("")
    lines.append("## Coverage by category\n")
    lines.append("| Category | Total | Triggered | Not triggered | Wrong policy | Disabled |")
    lines.append("|---|---:|---:|---:|---:|---:|")
    for cat in sorted(cat_stats):
        c = cat_stats[cat]
        tot = sum(c.values())
        lines.append(f"| {cat} | {tot} | {c['TRIGGERED']} | {c['NOT_TRIGGERED']} | {c['WRONG_POLICY']} | {c['DISABLED']} |")
    lines.append("")
    lines.append(f"## Failures ({len(failures)})\n")
    if failures:
        lines.append("| policy_id | category | status | synthesized message | triggered instead | unsat |")
        lines.append("|---|---|---|---|---|---|")
        for r in failures:
            lines.append(f"| `{r['policy_id']}` | {r['category']} | {r['status']} | "
                         f"{r['message'][:60]} | {r['triggered_policies'][:50] or '—'} | {r['unsat'] or '—'} |")
    else:
        lines.append("None — every enabled policy was triggered by its synthesized input.")
    lines.append("")
    if decision_failures:
        lines.append(f"## Decision mismatches ({len(decision_failures)})\n")
        lines.append("These triggered correctly but a co-firing higher-priority policy changed the final decision.\n")
        lines.append("| policy_id | policy decision | final decision | co-fired |")
        lines.append("|---|---|---|---|")
        for r in decision_failures[:40]:
            lines.append(f"| `{r['policy_id']}` | {r['policy_decision']} | {r['final_decision']} | {r['triggered_policies'][:60]} |")
        lines.append("")

    (DOCS / "POLICY_COVERAGE_REPORT.md").write_text("\n".join(lines), encoding="utf-8")

    # -- stdout -------------------------------------------------------------
    print(f"total={total} triggered={triggered_ok} not_triggered={not_triggered} "
          f"wrong_policy={wrong_policy} disabled={disabled} decision_mismatch={decision_mismatch}")
    print(f"free_text_only={free_text_only} requires_structured={requires_structured} "
          f"requires_task_type={requires_task_type} ui_unreachable={ui_unreachable}")
    print(f"\nReports written: {DOCS / 'POLICY_COVERAGE_REPORT.md'}")
    print(f"                {csv_path}")
    print("\n--- TOP 20 FAILURES ---")
    for r in failures[:20]:
        print(f"  [{r['status']:13}] {r['policy_id']:50} cat={r['category'][:24]:24} "
              f"unsat={r['unsat'] or '-'} | got={r['triggered_policies'][:40] or '-'}")
    if not failures:
        print("  (no coverage failures)")


if __name__ == "__main__":
    main()
