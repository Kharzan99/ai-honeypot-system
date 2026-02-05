# app/agent.py
import random
import re
import logging
from typing import Dict, Any, Optional, List

log = logging.getLogger(__name__)

# ---------- Persona & templates ----------
PERSONA_SHORT = (
    "You are acting AS a normal middle-class Indian person. "
    "Tone: polite, slightly worried about finances, curious, uses short sentences. "
    "Do NOT claim to be an AI or bot. Keep replies natural and human-like."
)

# friendlier, more natural Indian-sounding templates
TEMPLATES = {
    "ask_reason": {
        "low": [
            "What happened? Why would the bank block my account?",
            "I'm worried, why will my account be blocked?",
            "Can you explain what's the problem with my account?"
        ],
        "medium": [
            "That sounds serious. Can you tell me exactly what's wrong with my account?",
            "Okay, please explain what they told you about my account."
        ],
        "high": [
            "Alright, please tell me step-by-step what they asked so I can do it.",
            "Please explain the steps they gave you, so I can check properly."
        ]
    },
    "ask_for_upi": {
        "low": [
            "If this needs payment, which UPI ID should I use? Please share it.",
            "I don't want to rush, what UPI ID should I send money to?"
        ],
        "medium": [
            "Okay, could you share the UPI ID or phone number you'll use for payment?",
            "If payment is needed, what's the UPI ID or phone number I should use?"
        ],
        "high": [
            "Please send the UPI ID or phone number where I should transfer the money.",
            "Share the UPI ID/phone and I'll try to make the payment."
        ]
    },
    "ask_for_phone": {
        "low": [
            "Can you give me a phone number to call or message about this?",
            "Which number should I contact for this?"
        ],
        "medium": [
            "Please share the phone number (with country code) for payment or help.",
        ],
        "high": [
            "Give me the phone number and I'll call or message to sort this."
        ]
    },
    "stalling": {
        "any": [
            "I'm busy now, can you message the details and I'll check later?",
            "Give me some time, I'll look and reply soon."
        ]
    },
    "confirm": {
        "any": [
            "Okay, got it. One second while I check.",
            "Understood. Let me confirm and get back to you."
        ]
    }
}

# ---------- Small helper functions ----------
def pick_template(intent: str, trust_score: int) -> str:
    """Pick a template based on intent and trust band."""
    band = "low" if trust_score < 35 else "medium" if trust_score < 70 else "high"
    bucket = TEMPLATES.get(intent, None)
    if not bucket:
        bucket = {"any": ["Okay, please tell me more."]}
    if band in bucket:
        choices = bucket[band]
    elif "any" in bucket:
        choices = bucket["any"]
    else:
        choices = [t for v in bucket.values() for t in v]
    return random.choice(choices)

def sanitize_reply(text: str) -> str:
    # remove suspicious example tokens like "(example@upi)" if present
    text = re.sub(r'\(.*example.*\)', '', text, flags=re.IGNORECASE)
    text = re.sub(r'\s{2,}', ' ', text).strip()
    # ensure proper punctuation
    if text and text[-1] not in ".?!":
        text = text + "."
    return text

# ---------- Session state updater ----------
def update_session_state(session_state: Dict[str, Any], incoming_text: str, extracted: Dict[str, Any]) -> Dict[str, Any]:
    """
    Update session_state in-place from incoming message & extracted intelligence.
    """
    s = session_state
    s.setdefault("trust_score", 0)
    s.setdefault("messages_count", 0)
    s.setdefault("upi_seen", False)
    s.setdefault("link_seen", False)
    s.setdefault("phone_seen", False)

    txt = (incoming_text or "").lower() or ""

    # calming / polite words => increase trust
    if any(w in txt for w in ("please", "thank", "thanks", "sorry", "regards", "details", "kindly")):
        s["trust_score"] = min(100, s["trust_score"] + 10)

    # urgency/pressure words => decrease trust
    if any(w in txt for w in ("immediately", "urgent", "now", "last chance", "blocked", "suspend", "suspended", "verify now")):
        s["trust_score"] = max(0, s["trust_score"] - 18)

    # extracted items increase flags & small trust adjustments
    if extracted.get("upiIds"):
        s["upi_seen"] = True
        s["trust_score"] = min(100, s["trust_score"] + 18)
    if extracted.get("phishingLinks"):
        s["link_seen"] = True
        s["trust_score"] = max(0, s["trust_score"] - 5)
    if extracted.get("phoneNumbers"):
        s["phone_seen"] = True
        s["trust_score"] = min(100, s["trust_score"] + 10)
    if extracted.get("suspiciousKeywords"):
        s["trust_score"] = max(0, s["trust_score"] - (2 * len(extracted.get("suspiciousKeywords", []))))

    s["trust_score"] = int(max(0, min(100, s["trust_score"])))
    return s

# ---------- Main generator ----------
def generate_agent_reply(session_state: Dict[str, Any],
                         last_message: Dict[str, Any],
                         extracted: Dict[str, Any],
                         mode: str = "template",
                         llm_generate: Optional[callable] = None) -> Dict[str, Any]:
    """
    Returns: {'reply': str, 'intent': str, 'session_state': updated_state}
    mode: 'template' or 'llm' (if llm_generate provided, will call it to rephrase)
    """
    session_state.setdefault("stage", "initial")
    
    # ✅ FIRST: Update session state (sets upi_seen, link_seen, adjusts trust_score)
    update_session_state(session_state, last_message.get("text", ""), extracted)
    
    # ✅ THEN: Get updated trust and flags for intent decision
    trust = session_state.get("trust_score", 0)

    # Decision logic (escalation)
    intent = "ask_reason"
    if session_state.get("upi_seen"):
        intent = "confirm"
    else:
        if session_state.get("link_seen") and trust >= 30:
            intent = "ask_for_upi"
        elif any(k in (extracted.get("suspiciousKeywords") or []) for k in ("upi", "pay", "transfer", "paytm")) and trust >= 40:
            intent = "ask_for_upi"
        else:
            intent = "ask_reason"

    # pick base template
    reply = pick_template(intent, trust)

    # softer ask if trust low
    if intent == "ask_for_upi" and trust < 40:
        reply = "I am not comfortable sending money yet — please tell me which account or UPI ID they mentioned and why."

    # Optionally rephrase with LLM for naturalness
    if mode == "llm" and llm_generate:
        # build a short prompt for rephrasing
        short_summary = session_state.get("long_summary", "") or ""
        recent_texts = [m.get("text") for m in session_state.get("short_memory", [])[-3:]]
        recent = " | ".join([r for r in recent_texts if r])
        prompt = (
            f"{PERSONA_SHORT}\n"
            f"Session summary: {short_summary}\n"
            f"Trust score: {session_state.get('trust_score')}\n"
            f"Recent incoming: {recent}\n\n"
            f"Task: Produce a short natural human reply (one or two sentences) that fits the persona and intent '{intent}'. "
            f"Keep it conversational, avoid examples like '(example@upi)', and sound like a normal Indian person."
        )
        try:
            lm_reply = llm_generate(prompt)
            if lm_reply and isinstance(lm_reply, str) and len(lm_reply.strip()) > 0:
                # use the first non-empty line
                parts = [line.strip() for line in lm_reply.splitlines() if line.strip()]
                if parts:
                    reply = parts[0]
        except Exception as e:
            log.warning(f"LLM generation failed: {e} — falling back to template")

    reply = sanitize_reply(reply)

    # update stage
    if intent in ("ask_for_upi", "ask_for_phone"):
        session_state["stage"] = "payment_extraction"
    elif intent == "ask_reason":
        session_state["stage"] = "information_gathering"

    return {"reply": reply, "intent": intent, "session_state": session_state}
