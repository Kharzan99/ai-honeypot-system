# app/callback.py
import requests
import logging
from .config import GUVI_CALLBACK_URL, HTTP_TIMEOUT

log = logging.getLogger(__name__)

def _clean_extracted_for_callback(extracted: dict) -> dict:
    """Ensure extracted intelligence has all required keys with clean string lists (no None values)."""
    keys = ["bankAccounts", "upiIds", "phishingLinks", "phoneNumbers", "suspiciousKeywords"]
    out = {}
    for k in keys:
        lst = extracted.get(k) or []
        # ensure list, filter out None, cast to str, limit length
        cleaned = []
        for it in lst:
            if it is None:
                continue
            s = str(it).strip()
            if not s:
                continue
            # truncate very long entries
            if len(s) > 300:
                s = s[:300] + "…"
            cleaned.append(s)
        out[k] = cleaned
    return out

def send_final_result(session_id: str, scam_detected: bool, total_messages: int,
                      extracted_intelligence: dict, agent_notes: str) -> dict:
    # Clean extracted intelligence to ensure all required keys present with safe values
    cleaned_intel = _clean_extracted_for_callback(extracted_intelligence)
    payload = {
        "sessionId": session_id,
        "scamDetected": scam_detected,
        "totalMessagesExchanged": total_messages,
        "extractedIntelligence": cleaned_intel,
        "agentNotes": agent_notes
    }
    try:
        r = requests.post(GUVI_CALLBACK_URL, json=payload, timeout=HTTP_TIMEOUT)
        r.raise_for_status()
        return {"ok": True, "status_code": r.status_code, "text": r.text}
    except Exception as e:
        log.exception("Failed to send final result")
        return {"ok": False, "error": str(e)}
