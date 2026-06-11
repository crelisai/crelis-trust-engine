"""
Stage 2 — Risk & Confidence Scoring.

Two questions get answered here:

  1. RISK       — "How dangerous is this action?"           (0–100)
  2. CONFIDENCE — "How much information do we have to judge?" (0–100)

The risk score is built additively from independent signals (task type,
industry, money, legal language, PII) and every contribution is recorded as a
RiskFactor line-item, so the final number is fully explainable — a key selling
point for governance buyers who must justify decisions to auditors.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Tuple

from app import config
from app.models.response_models import RiskFactor

# ---------------------------------------------------------------------------
# Signal detectors
# ---------------------------------------------------------------------------

# Words/phrases that signal a legal or regulatory escalation.
LEGAL_KEYWORDS = ["sue", "legal action", "lawyer", "regulator"]

# Words/phrases that signal an abusive or hostile customer interaction.
ABUSIVE_KEYWORDS = ["bullshit", "scam", "fraud", "useless", "terrible service"]

# Lightweight PII patterns (advanced feature: flags sensitive data in flight).
# v0.1 keeps this intentionally simple — real products would use a proper
# PII-detection library or model here.
PII_PATTERNS = {
    "email_address": re.compile(r"[\w.+-]+@[\w-]+\.[\w.]+"),
    "card_number": re.compile(r"\b(?:\d[ -]?){13,19}\b"),
    "national_id_like": re.compile(r"\b[A-Z]\d{7}[A-Z]\b"),  # e.g. SG NRIC shape
}


def keyword_in_message(keyword: str, message: str) -> bool:
    """
    Whole-word/phrase match, case-insensitive.

    Plain substring search would wrongly find 'sue' inside 'pursue' —
    word boundaries (\\b) prevent those false escalations.
    """
    return re.search(rf"\b{re.escape(keyword)}\b", message, re.IGNORECASE) is not None


def detect_legal_language(message: str | None) -> List[str]:
    """Return the legal-escalation keywords found in the message (if any)."""
    if not message:
        return []
    return [kw for kw in LEGAL_KEYWORDS if keyword_in_message(kw, message)]


def detect_abusive_language(message: str | None) -> List[str]:
    """Return the abusive/hostile keywords found in the message (if any)."""
    if not message:
        return []
    return [kw for kw in ABUSIVE_KEYWORDS if keyword_in_message(kw, message)]


def detect_pii(message: str | None) -> List[str]:
    """Return the names of PII patterns found in the message (if any)."""
    if not message:
        return []
    return [name for name, pattern in PII_PATTERNS.items() if pattern.search(message)]


# ---------------------------------------------------------------------------
# Risk score
# ---------------------------------------------------------------------------

def calculate_risk(normalized: Dict[str, Any]) -> Tuple[float, List[RiskFactor], List[str]]:
    """
    Build the risk score from the normalized request.

    Returns (risk_score, breakdown, flags):
      * risk_score — final clamped 0–100 number,
      * breakdown  — one RiskFactor per contributing signal (explainability),
      * flags      — short machine-readable signals like "pii_detected".
    """
    breakdown: List[RiskFactor] = []
    flags: List[str] = []

    # --- Signal 1: what KIND of action is this? -----------------------------
    task_type = normalized.get("task_type")
    task_risk = config.TASK_TYPE_RISK.get(task_type, config.DEFAULT_TASK_RISK)
    breakdown.append(
        RiskFactor(
            factor="task_type",
            points=task_risk,
            detail=f"Task '{task_type or 'unknown'}' has a baseline risk of {task_risk}.",
        )
    )

    # --- Signal 2: the proposed action (if riskier than the task itself) ----
    action = normalized.get("proposed_action")
    action_risk = config.TASK_TYPE_RISK.get(action, 0)
    if action and action_risk > task_risk:
        extra = action_risk - task_risk
        breakdown.append(
            RiskFactor(
                factor="proposed_action",
                points=extra,
                detail=f"Proposed action '{action}' raises risk above the task baseline.",
            )
        )

    # --- Signal 3: which industry does this run in? -------------------------
    industry = normalized.get("industry")
    industry_risk = config.INDUSTRY_RISK.get(industry, config.DEFAULT_INDUSTRY_RISK)
    breakdown.append(
        RiskFactor(
            factor="industry",
            points=industry_risk,
            detail=f"Industry '{industry or 'unknown'}' adds {industry_risk} risk.",
        )
    )

    # --- Signal 4: how much money is involved? ------------------------------
    # `amount` is the effective amount: the structured field or, when absent
    # or understated, the largest monetary mention parsed from the message.
    amount = normalized.get("amount")
    amount_source = normalized.get("amount_source")
    if amount_source == "message":
        flags.append("amount_extracted_from_message")
    elif amount_source == "message_exceeds_field":
        flags.append("amount_extracted_from_message")
        flags.append("amount_mismatch")
    if amount is not None and amount > config.AMOUNT_RISK_THRESHOLD:
        over = amount - config.AMOUNT_RISK_THRESHOLD
        amount_risk = min(
            config.AMOUNT_RISK_MAX,
            (over / 1000.0) * config.AMOUNT_RISK_PER_1000,
        )
        amount_risk = round(amount_risk, 1)
        breakdown.append(
            RiskFactor(
                factor="amount",
                points=amount_risk,
                detail=(
                    f"Amount {amount} exceeds the {config.AMOUNT_RISK_THRESHOLD} "
                    f"threshold, adding {amount_risk} risk."
                ),
            )
        )
        flags.append("high_value_amount")

    # --- Signal 5: does the customer's language signal legal trouble? -------
    legal_hits = detect_legal_language(normalized.get("user_message"))
    if legal_hits:
        breakdown.append(
            RiskFactor(
                factor="legal_language",
                points=config.LEGAL_LANGUAGE_RISK,
                detail=f"Message contains legal-escalation language: {', '.join(legal_hits)}.",
            )
        )
        flags.append("legal_language_detected")

    # --- Signal 6: is the customer's language abusive or hostile? -----------
    abusive_hits = detect_abusive_language(normalized.get("user_message"))
    if abusive_hits:
        breakdown.append(
            RiskFactor(
                factor="abusive_language",
                points=config.ABUSIVE_LANGUAGE_RISK,
                detail=f"Message contains abusive/hostile language: {', '.join(abusive_hits)}.",
            )
        )
        flags.append("abusive_language_detected")

    # --- Signal 7 (advanced): does the message carry PII? -------------------
    pii_hits = detect_pii(normalized.get("raw_user_message"))
    if pii_hits:
        breakdown.append(
            RiskFactor(
                factor="pii_in_message",
                points=config.PII_RISK,
                detail=f"Message appears to contain PII: {', '.join(pii_hits)}.",
            )
        )
        flags.append("pii_detected")

    total = sum(item.points for item in breakdown)
    risk_score = max(config.RISK_MIN, min(config.RISK_MAX, round(total, 1)))
    return risk_score, breakdown, flags


# ---------------------------------------------------------------------------
# Confidence score
# ---------------------------------------------------------------------------

def calculate_confidence(normalized: Dict[str, Any]) -> float:
    """
    Estimate how complete this request is.

    A fully-described request lands in the 85–95 band; a request missing
    task_type or user_message is hard-capped below 60 — the engine should be
    visibly LESS sure when it's judging with half the picture.
    """
    score = float(config.CONFIDENCE_BASE)

    if normalized.get("user_message"):
        score += config.CONFIDENCE_HAS_MESSAGE
    if normalized.get("task_type"):
        score += config.CONFIDENCE_HAS_TASK_TYPE
    if normalized.get("proposed_action"):
        score += config.CONFIDENCE_HAS_ACTION
    if normalized.get("industry"):
        score += config.CONFIDENCE_HAS_INDUSTRY
    if normalized.get("amount") is not None:
        score += config.CONFIDENCE_HAS_AMOUNT_OR_NA

    metadata = normalized.get("metadata") or {}
    score += min(len(metadata), config.CONFIDENCE_METADATA_BONUS_MAX)

    # Hard cap when critical context is missing.
    if normalized.get("missing_critical"):
        score = min(score, config.CONFIDENCE_CRITICAL_MISSING_CAP)

    return max(config.CONFIDENCE_MIN, min(config.CONFIDENCE_MAX, round(score, 1)))
