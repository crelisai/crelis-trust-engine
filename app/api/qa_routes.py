"""
Trust Engine QA Center API.

    POST /qa/run               run a QA cycle (optional tenant_id / categories)
    GET  /qa/runs              list past run summaries (newest first)
    GET  /qa/runs/{run_id}     full run (summary + every result)
    GET  /qa/failures          failures (optionally a specific run / include warnings)
    GET  /qa/summary           latest run summary (headline health metrics)
    GET  /qa/policy/{id}       every QA result for one policy in a run
    POST /qa/validate-policy   gate a candidate customer policy before activation
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from app.qa import runner, store
from app.qa.models import QAResult, QARun, QARunSummary, ValidationGateResult
from app.qa.validate_policy import validate_candidate_policy

router = APIRouter(prefix="/qa", tags=["qa"])


class QARunRequest(BaseModel):
    tenant_id: Optional[str] = None
    categories: Optional[List[str]] = Field(
        None, description="Subset of: schema, reachability, detection, decision, audit, tenant, regression.",
    )


class ValidatePolicyRequest(BaseModel):
    tenant_id: Optional[str] = None
    policy: Dict[str, Any] = Field(..., description="Candidate customer custom policy (authoring schema).")


def _resolve_run(run_id: Optional[str]) -> QARun:
    run = store.get_run(run_id) if run_id else store.latest_run()
    if run is None:
        raise HTTPException(status_code=404, detail="No QA run found. POST /qa/run first.")
    return run


@router.post("/run", response_model=QARunSummary)
def run_qa(body: Optional[QARunRequest] = None) -> QARunSummary:
    body = body or QARunRequest()
    run = runner.run_qa(tenant_id=body.tenant_id, categories=body.categories)
    return run.summary


@router.get("/runs", response_model=List[QARunSummary])
def list_runs() -> List[QARunSummary]:
    return store.list_summaries()


@router.get("/runs/{run_id}", response_model=QARun)
def get_run(run_id: str) -> QARun:
    return _resolve_run(run_id)


@router.get("/failures", response_model=List[QAResult])
def get_failures(run_id: Optional[str] = None, include_warnings: bool = False) -> List[QAResult]:
    run = _resolve_run(run_id)
    statuses = {"fail", "warning"} if include_warnings else {"fail"}
    return [r for r in run.results if r.status in statuses]


@router.get("/summary")
def get_summary() -> Dict[str, Any]:
    run = store.latest_run()
    return {"has_run": run is not None, "summary": run.summary if run else None}


@router.get("/policy/{policy_id}", response_model=List[QAResult])
def get_policy_results(policy_id: str, run_id: Optional[str] = None) -> List[QAResult]:
    run = _resolve_run(run_id)
    return [r for r in run.results if r.policy_id == policy_id]


@router.post("/validate-policy", response_model=ValidationGateResult)
def validate_policy(body: ValidatePolicyRequest) -> ValidationGateResult:
    return validate_candidate_policy(body.policy, body.tenant_id)
