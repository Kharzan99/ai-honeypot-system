# app/detector.py
import joblib
import json
import re
from .config import DETECTOR_PIPELINE_PATH, RULES_CONFIG_PATH, RULE_THRESHOLD, ML_PROB_THRESHOLD
from typing import Dict

# load pipeline and rules at import
_detector = None
_rules = None

def _load_detector():
    global _detector
    if _detector is None:
        _detector = joblib.load(DETECTOR_PIPELINE_PATH)
    return _detector

def _load_rules():
    global _rules
    if _rules is None:
        try:
            with open(RULES_CONFIG_PATH, "r") as f:
                _rules = json.load(f)
        except Exception:
            # default fallback
            _rules = {"RULE_KEYWORDS": [], "RULE_THRESHOLD": RULE_THRESHOLD}
    # ensure keys
    _rules.setdefault("RULE_KEYWORDS", [])
    _rules.setdefault("RULE_THRESHOLD", RULE_THRESHOLD)
    _rules.setdefault("ML_PROB_THRESHOLD", ML_PROB_THRESHOLD)
    return _rules

# helper cleaned for consistency with model training
def clean_text(text: str) -> str:
    if not isinstance(text, str):
        return ""
    t = text.lower()
    t = re.sub(r'http\S+', ' <URL> ', t)
    t = re.sub(r'\+?\d[\d\s\-]{6,}\d', ' <PHONE> ', t)
    t = re.sub(r'[^a-z0-9<> ]', ' ', t)
    t = re.sub(r'\s+', ' ', t).strip()
    return t

# Enhanced rule scoring with word boundaries and pattern detection
URL_PAT = re.compile(r'https?://|www\.', re.IGNORECASE)
PHONE_PAT = re.compile(r'\+?\d{1,3}[-\s]?\d{8,15}')
UPI_PAT = re.compile(r'\b[A-Za-z0-9._\-]{2,256}@[A-Za-z0-9._\-]{2,40}\b', re.IGNORECASE)

def rule_score(message_text: str) -> Dict:
    """
    Enhanced rule scoring:
    - Uses word-boundary matching for keywords
    - Weighted scoring for different risk levels
    - Bonus points for URL/phone/UPI combined with payment/urgency keywords
    - Returns score, matched keywords, and threshold
    """
    rules = _load_rules()
    t = message_text if isinstance(message_text, str) else ""
    score = 0.0
    matched = []
    
    # Word-boundary keyword matching
    for kw in rules.get("RULE_KEYWORDS", []):
        # Create word-boundary pattern for each keyword
        pattern = re.compile(r'\b' + re.escape(kw.lower()) + r'\b', re.IGNORECASE)
        if pattern.search(t):
            matched.append(kw)
            score += 0.8  # Base score per keyword
    
    # Boost for contact methods/URLs
    has_url = bool(URL_PAT.search(t))
    has_phone = bool(PHONE_PAT.search(t))
    has_upi = bool(UPI_PAT.search(t))
    
    if has_url:
        score += 2.0
    if has_phone:
        score += 1.5
    if has_upi:
        score += 1.5
    
    # Combination bonus: payment/urgency keywords + contact info = higher confidence
    t_lower = t.lower()
    payment_like = any(kw in t_lower for kw in ('upi', 'transfer', 'send money', 'pay', 'paytm'))
    urgency_like = any(kw in t_lower for kw in ('immediately', 'urgent', 'verify now', 'account blocked', 'suspended'))
    contact_present = has_url or has_phone or has_upi
    
    if (payment_like or urgency_like) and contact_present:
        score += 1.25  # Bonus for typical scam pattern
    
    return {"score": float(score), "matched": matched, "threshold": rules.get("RULE_THRESHOLD", RULE_THRESHOLD)}

def predict(message_text: str) -> Dict:
    """
    Returns:
      {
        "scamDetected": bool,
        "score": float,
        "reason": "rule" or "ml",
        "details": { ... }
      }
    """
    detector = _load_detector()
    # Use raw text for rule scoring to preserve URLs/phones/UPIs
    r = rule_score(message_text)
    if r["score"] >= r["threshold"]:
        # high precision rule hit
        return {"scamDetected": True, "score": min(1.0, r["score"] / (r["threshold"] + 2.0)), "reason": "rule", "details": r}
    # fallback to ML - use cleaned text for ML model
    txt_clean = clean_text(message_text)
    try:
        prob = float(detector.predict_proba([txt_clean])[0][1])
    except Exception:
        # try raw text if pipeline expects uncleaned
        try:
            prob = float(detector.predict_proba([message_text])[0][1])
        except Exception:
            prob = 0.0
    scam = prob >= _load_rules().get("ML_PROB_THRESHOLD", ML_PROB_THRESHOLD)
    return {"scamDetected": scam, "score": prob, "reason": "ml", "details": {"probability": prob}}
