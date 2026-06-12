"""
In-memory QA run store (v1).

Holds completed QA runs for the session. Swapped for a database table in a
later version; the API surface stays identical.
"""

from __future__ import annotations

from typing import Dict, List, Optional

from app.qa.models import QARun, QARunSummary

_runs: "Dict[str, QARun]" = {}
_order: List[str] = []
_counter = 0


def next_run_id() -> str:
    global _counter
    _counter += 1
    return f"QA-{_counter:04d}"


def save_run(run: QARun) -> None:
    _runs[run.summary.run_id] = run
    _order.append(run.summary.run_id)


def get_run(run_id: str) -> Optional[QARun]:
    return _runs.get(run_id)


def latest_run() -> Optional[QARun]:
    if not _order:
        return None
    return _runs[_order[-1]]


def list_summaries() -> List[QARunSummary]:
    # Newest first.
    return [_runs[rid].summary for rid in reversed(_order)]


def clear() -> None:
    global _counter
    _runs.clear()
    _order.clear()
    _counter = 0
