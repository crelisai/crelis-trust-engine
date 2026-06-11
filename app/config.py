"""
Central configuration for the Crelis Trust Engine.

Everything that a *non-developer* might want to tune lives here in one place:
risk thresholds, the order of decision severity, and default routing targets.

Keeping these as plain Python constants (instead of scattering "magic numbers"
through the code) means a founder can adjust the engine's behaviour by editing
ONE file, without touching the actual logic.
"""

from __future__ import annotations


# ---------------------------------------------------------------------------
# Engine metadata
# ---------------------------------------------------------------------------

ENGINE_NAME = "Crelis Trust Engine"
ENGINE_VERSION = "0.1.0"

# The schema version of the decision object we return. Bump this whenever the
# shape of the response changes so downstream consumers can adapt safely.
DECISION_SCHEMA_VERSION = "2026-06-12"


# ---------------------------------------------------------------------------
# Decisions
# ---------------------------------------------------------------------------
# The four possible outcomes of a governance evaluation.

DECISION_ALLOW = "allow"
DECISION_HUMAN_APPROVAL = "human_approval_required"
DECISION_HUMAN_AGENT = "human_agent_required"
DECISION_BLOCK = "block"

# Severity ranking. When several policies fire at once, the engine picks the
# MOST severe decision. Higher number = more severe = wins.
#
#   block               (4)  -> strongest, stops everything
#   human_agent_required(3)
#   human_approval_required(2)
#   allow               (1)  -> weakest, only wins if nothing else fired
DECISION_PRIORITY = {
    DECISION_ALLOW: 1,
    DECISION_HUMAN_APPROVAL: 2,
    DECISION_HUMAN_AGENT: 3,
    DECISION_BLOCK: 4,
}

# Default place to send a request for each decision. A policy can override this
# with its own `route_to` (e.g. "senior_support_manager") when it needs to.
DEFAULT_ROUTES = {
    DECISION_ALLOW: "ai_agent",
    DECISION_HUMAN_APPROVAL: "approval_queue",
    DECISION_HUMAN_AGENT: "human_expert",
    DECISION_BLOCK: "blocked_execution",
}


# ---------------------------------------------------------------------------
# Risk scoring knobs (0–100 scale)
# ---------------------------------------------------------------------------
# These weights feed the risk_scoring service. Tune them to make the engine
# more cautious (raise the numbers) or more permissive (lower them).

# Baseline risk contributed purely by the *type* of task being attempted.
TASK_TYPE_RISK = {
    "password_reset": 5,
    "balance_inquiry": 5,
    "refund_request": 35,
    "issue_refund": 35,
    "wire_transfer": 70,
    "data_export": 75,
    "account_closure": 50,
    "loan_approval": 60,
}
DEFAULT_TASK_RISK = 25  # used when a task_type isn't in the table above

# Extra risk contributed by the industry the action runs in.
INDUSTRY_RISK = {
    "banking": 20,
    "finance": 20,
    "healthcare": 25,
    "insurance": 15,
    "ecommerce": 5,
    "retail": 5,
}
DEFAULT_INDUSTRY_RISK = 10

# Money-based risk. Any monetary amount above this threshold starts adding risk.
AMOUNT_RISK_THRESHOLD = 500          # currency units
AMOUNT_RISK_MAX = 25                 # most risk money alone can add
AMOUNT_RISK_PER_1000 = 10            # risk added per 1,000 over the threshold

# Risk added when the customer's language signals legal / regulatory escalation.
LEGAL_LANGUAGE_RISK = 35

# Risk added when the customer's language is abusive or hostile.
ABUSIVE_LANGUAGE_RISK = 20

# Risk added when the message appears to contain PII (emails, card numbers...).
PII_RISK = 15

# Final risk is always clamped to this range.
RISK_MIN = 0
RISK_MAX = 100


# ---------------------------------------------------------------------------
# Confidence scoring knobs (0–100 scale)
# ---------------------------------------------------------------------------
# Confidence answers: "how sure is the engine that it has enough information to
# make a good decision?" A request missing key fields should score LOW.

CONFIDENCE_BASE = 50
CONFIDENCE_HAS_MESSAGE = 18
CONFIDENCE_HAS_TASK_TYPE = 18
CONFIDENCE_HAS_ACTION = 6
CONFIDENCE_HAS_INDUSTRY = 4
CONFIDENCE_HAS_AMOUNT_OR_NA = 4
CONFIDENCE_METADATA_BONUS_MAX = 2  # +1 per metadata key, capped
CONFIDENCE_MAX = 95                # we never claim to be 100% certain
CONFIDENCE_MIN = 0

# If a CRITICAL field (task_type or user_message) is missing, the engine is
# flying half-blind — confidence is hard-capped below this value.
CONFIDENCE_CRITICAL_MISSING_CAP = 55


# ---------------------------------------------------------------------------
# CORS (which websites may call this API from a browser)
# ---------------------------------------------------------------------------
# Production frontends plus local dev servers. Extra origins can be added at
# deploy time via the CORS_EXTRA_ORIGINS env var (comma-separated), so the
# Railway dashboard can grant access to a new domain without a code change.

import os

CORS_ALLOWED_ORIGINS = [
    "https://crelis.ai",
    "https://www.crelis.ai",
    "https://demo.crelis.ai",
    # Local development frontends:
    "http://localhost:3000",
    "http://localhost:5173",
    "http://127.0.0.1:5173",
]

_extra = os.getenv("CORS_EXTRA_ORIGINS", "")
CORS_ALLOWED_ORIGINS += [o.strip() for o in _extra.split(",") if o.strip()]
