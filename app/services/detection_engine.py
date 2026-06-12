"""
Detection Engine — the natural-language layer of the Trust Engine.

Turns a free-text user message into structured signals the rest of the engine
can reason about, WITHOUT any LLM:

    User Message
      → Intent Classification     (intents.json)
      → Entity Extraction         (entities.json + amount/currency parser)
      → Risk Signal Detection     (risk_signals.json, incl. derived signals)
      → Sentiment / Urgency        (sentiment_terms.json / urgency_terms.json)
      → Industry Context           (industry_terms.json)
      → Detection Confidence

All vocabulary lives in app/data/native_libraries/*.json, so the detection
behaviour is updated by editing JSON — never Python. Matching is
case-insensitive and whole-word: 'sue' never fires inside 'pursue', 'sum'
never fires inside 'assume'.

`detect(message)` returns a dict with exactly these keys:
    detected_intents, detected_entities, detected_risk_signals,
    detected_sentiment, detected_urgency, detected_industry_context,
    detected_amounts, detection_confidence
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Dict, List

LIB_DIR = Path(__file__).resolve().parent.parent / "data" / "native_libraries"


# ---------------------------------------------------------------------------
# Whole-word phrase matching
# ---------------------------------------------------------------------------
# A phrase matches only when it is NOT surrounded by other letters/digits.
# This single rule gives us the false-positive protection the spec requires:
#   'sue'  in 'pursue'  -> no match (preceded by 'r')
#   'sum'  in 'assume'  -> no match (preceded by 's')
#   'mas'  in 'christmas'-> no match (preceded by 't')

_PHRASE_CACHE: Dict[str, re.Pattern] = {}


def _phrase_regex(phrase: str) -> re.Pattern:
    pattern = _PHRASE_CACHE.get(phrase)
    if pattern is None:
        pattern = re.compile(
            r"(?<![a-z0-9])" + re.escape(phrase.lower()) + r"(?![a-z0-9])"
        )
        _PHRASE_CACHE[phrase] = pattern
    return pattern


def _normalize(message: str | None) -> str:
    """Lowercase and collapse whitespace so multi-word phrases match reliably."""
    if not message:
        return ""
    return re.sub(r"\s+", " ", message.lower()).strip()


def keyword_in_message(keyword: str, message: str | None) -> bool:
    """Whole-word, case-insensitive membership test (used across the engine)."""
    if not message:
        return False
    return _phrase_regex(keyword).search(_normalize(message)) is not None


def _matched_phrases(normalized: str, phrases: List[str]) -> List[str]:
    return [p for p in phrases if _phrase_regex(p).search(normalized)]


# ---------------------------------------------------------------------------
# Amount & currency parsing
# ---------------------------------------------------------------------------
# Supports: 100000  100,000  $100,000  USD 100,000  SGD 100,000  S$100,000
#           100k  1.5m  £250  €1,000  RM 5,000

_CURRENCY_CODES = {
    "us$": "USD", "s$": "SGD", "$": "USD", "usd": "USD", "sgd": "SGD",
    "eur": "EUR", "€": "EUR", "gbp": "GBP", "£": "GBP", "aud": "AUD",
    "myr": "MYR", "rm": "MYR", "inr": "INR",
}

_MULTIPLIERS = {
    "k": 1_000, "thousand": 1_000,
    "m": 1_000_000, "mil": 1_000_000, "million": 1_000_000,
    "b": 1_000_000_000, "bn": 1_000_000_000, "billion": 1_000_000_000,
}

_AMOUNT_RE = re.compile(
    r"""
    (?<![a-z0-9])
    (?P<cur>us\$|s\$|usd|sgd|eur|gbp|aud|myr|rm|inr|\$|€|£)?\s?
    (?P<num>\d{1,3}(?:,\d{3})+(?:\.\d+)?|\d+(?:\.\d+)?)
    \s?(?P<suf>k|m|mil|million|bn|b|billion|thousand)?
    (?![a-z0-9])
    """,
    re.IGNORECASE | re.VERBOSE,
)


def extract_amounts(message: str | None) -> List[float]:
    """Every monetary value found in the message, normalised to plain floats."""
    if not message:
        return []
    found: List[float] = []
    for match in _AMOUNT_RE.finditer(message):
        try:
            value = float(match.group("num").replace(",", ""))
        except ValueError:
            continue
        suffix = (match.group("suf") or "").lower()
        if suffix in _MULTIPLIERS:
            value *= _MULTIPLIERS[suffix]
        found.append(value)
    # Preserve order but drop duplicates.
    seen: set = set()
    unique: List[float] = []
    for value in found:
        if value not in seen:
            seen.add(value)
            unique.append(value)
    return unique


def extract_currencies(message: str | None) -> List[str]:
    """Distinct currency codes/symbols mentioned, normalised to ISO-ish codes."""
    if not message:
        return []
    codes: List[str] = []
    for match in _AMOUNT_RE.finditer(message):
        raw = (match.group("cur") or "").lower()
        code = _CURRENCY_CODES.get(raw)
        if code and code not in codes:
            codes.append(code)
    return codes


# ---------------------------------------------------------------------------
# Library loading (cached; reloadable)
# ---------------------------------------------------------------------------

_LIBS: Dict[str, Any] = {}
_COMPILED_ENTITY_RES: Dict[str, re.Pattern] = {}


def _load_libs() -> None:
    if _LIBS:
        return
    for name in (
        "intents", "entities", "risk_signals",
        "industry_terms", "sentiment_terms", "urgency_terms",
    ):
        with open(LIB_DIR / f"{name}.json", "r", encoding="utf-8") as f:
            _LIBS[name] = json.load(f)
    # Pre-compile entity regexes.
    for ent_name, spec in _LIBS["entities"]["entities"].items():
        if spec.get("match") == "regex":
            _COMPILED_ENTITY_RES[ent_name] = re.compile(spec["pattern"], re.IGNORECASE)


def reload() -> None:
    """Forget cached libraries so the next detect() re-reads them from disk."""
    _LIBS.clear()
    _COMPILED_ENTITY_RES.clear()
    _PHRASE_CACHE.clear()


# ---------------------------------------------------------------------------
# Detection
# ---------------------------------------------------------------------------

def _detect_intents(normalized: str) -> List[str]:
    intents = []
    for intent, phrases in _LIBS["intents"]["intents"].items():
        if _matched_phrases(normalized, phrases):
            intents.append(intent)
    return intents


def _detect_entities(message: str, normalized: str) -> Dict[str, List[Any]]:
    entities: Dict[str, List[Any]] = {}

    amounts = extract_amounts(message)
    if amounts:
        entities["amount"] = amounts
    currencies = extract_currencies(message)
    if currencies:
        entities["currency"] = currencies

    for ent_name, spec in _LIBS["entities"]["entities"].items():
        match_type = spec.get("match")
        if match_type == "phrase":
            hits = _matched_phrases(normalized, spec["phrases"])
            if hits:
                entities[ent_name] = sorted(set(hits))
        elif match_type == "regex":
            found = _COMPILED_ENTITY_RES[ent_name].findall(message)
            if found:
                # findall may return tuples for grouped patterns; keep strings.
                values = [f if isinstance(f, str) else "".join(f) for f in found]
                entities[ent_name] = sorted({v.strip() for v in values if v.strip()})
    return entities


def _detect_risk_signals(
    normalized: str,
    intents: List[str],
    entities: Dict[str, List[Any]],
    amounts: List[float],
) -> List[str]:
    signals: List[str] = []
    intent_set = set(intents)
    entity_set = set(entities)

    for signal, spec in _LIBS["risk_signals"]["risk_signals"].items():
        fired = False

        phrases = spec.get("phrases")
        if phrases and _matched_phrases(normalized, phrases):
            fired = True

        threshold = spec.get("derived_amount_threshold")
        if threshold is not None and any(a >= threshold for a in amounts):
            fired = True

        from_entities = spec.get("derived_from_entities")
        if from_entities and entity_set.intersection(from_entities):
            fired = True

        from_intents = spec.get("derived_from_intents")
        if from_intents and intent_set.intersection(from_intents):
            fired = True

        if spec.get("derived_abusive_and_complaint"):
            if "abusive_language" in signals and "customer_complaint" in intent_set:
                fired = True

        if fired:
            signals.append(signal)
    return signals


def _detect_sentiment(normalized: str) -> str:
    terms = _LIBS["sentiment_terms"]["sentiment"]
    neg = len(_matched_phrases(normalized, terms["negative"]))
    pos = len(_matched_phrases(normalized, terms["positive"]))
    if neg > pos:
        return "negative"
    if pos > neg:
        return "positive"
    return "neutral"


def _detect_urgency(normalized: str) -> str:
    terms = _LIBS["urgency_terms"]["urgency"]
    if _matched_phrases(normalized, terms["high"]):
        return "high"
    if _matched_phrases(normalized, terms["medium"]):
        return "medium"
    return "none"


def _detect_industries(normalized: str) -> List[str]:
    industries = []
    for industry, phrases in _LIBS["industry_terms"]["industries"].items():
        if _matched_phrases(normalized, phrases):
            industries.append(industry)
    return industries


def _confidence(message: str, intents, entities, signals, industries) -> float:
    if not message.strip():
        return 0.0
    score = 40.0
    if intents:
        score += 25
    if entities:
        score += 15
    if signals:
        score += 15
    if industries:
        score += 5
    return min(95.0, round(score, 1))


def detect(message: str | None) -> Dict[str, Any]:
    """Run the full detection pipeline over one message. Pure on its input."""
    _load_libs()
    message = message or ""
    normalized = _normalize(message)

    intents = _detect_intents(normalized)
    entities = _detect_entities(message, normalized)
    amounts = entities.get("amount", [])
    signals = _detect_risk_signals(normalized, intents, entities, amounts)
    sentiment = _detect_sentiment(normalized)
    urgency = _detect_urgency(normalized)
    industries = _detect_industries(normalized)

    return {
        "detected_intents": intents,
        "detected_entities": entities,
        "detected_risk_signals": signals,
        "detected_sentiment": sentiment,
        "detected_urgency": urgency,
        "detected_industry_context": industries,
        "detected_amounts": amounts,
        "detection_confidence": _confidence(
            message, intents, entities, signals, industries
        ),
    }
