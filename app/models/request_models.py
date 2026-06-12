"""
Request models — what the OUTSIDE world sends INTO the engine.

We use Pydantic, which automatically:
  * validates incoming JSON (rejects garbage before it reaches our logic),
  * documents the API (FastAPI turns these models into interactive docs),
  * gives us autocomplete and type-safety while coding.
"""

from __future__ import annotations

from typing import Any, Dict, Optional

from pydantic import BaseModel, Field


class TrustRequest(BaseModel):
    """
    A single AI-action request to be governed.

    Only `request_id` is strictly required — every other field is optional so
    the engine can still respond (with low confidence) to incomplete requests,
    which is exactly what a real governance runtime must do.
    """

    request_id: str = Field(
        ...,
        description="Caller-supplied unique id for this request, e.g. 'REQ-1001'.",
        examples=["REQ-1001"],
    )
    tenant_id: Optional[str] = Field(
        None,
        description=(
            "Tenant/account whose policy library governs this request. "
            "Omit to use the native Crelis default policies."
        ),
        examples=["demo_customer"],
    )
    source_system: Optional[str] = Field(
        None,
        description="Which system/agent framework originated the action.",
        examples=["openai", "anthropic", "internal-agent"],
    )
    industry: Optional[str] = Field(
        None,
        description="Vertical the action runs in (drives risk weighting).",
        examples=["banking", "healthcare", "ecommerce"],
    )
    channel: Optional[str] = Field(
        None,
        description="Channel the request came through.",
        examples=["customer_support", "api", "chat"],
    )
    task_type: Optional[str] = Field(
        None,
        description="What kind of action is being attempted.",
        examples=["refund_request", "wire_transfer", "password_reset"],
    )
    user_message: Optional[str] = Field(
        None,
        description="The end-user's natural-language message, if any.",
    )
    proposed_action: Optional[str] = Field(
        None,
        description="The concrete action the AI wants to execute.",
        examples=["issue_refund", "export_data"],
    )
    amount: Optional[float] = Field(
        None,
        description="Monetary amount involved, if applicable.",
        ge=0,
    )
    customer_tier: Optional[str] = Field(
        None,
        description="Customer segment (can influence routing).",
        examples=["standard", "premium", "vip"],
    )
    metadata: Dict[str, Any] = Field(
        default_factory=dict,
        description="Free-form extra context (region, model, agent_id, ...).",
    )

    # Pydantic v2 config: provide a full example so the /docs page is friendly.
    model_config = {
        "json_schema_extra": {
            "example": {
                "request_id": "REQ-1001",
                "source_system": "openai",
                "industry": "banking",
                "channel": "customer_support",
                "task_type": "refund_request",
                "user_message": "I want a refund and may pursue legal action.",
                "proposed_action": "issue_refund",
                "amount": 750,
                "customer_tier": "premium",
                "metadata": {
                    "region": "Singapore",
                    "model": "gpt-4.1",
                    "agent_id": "agent-001",
                },
            }
        }
    }
