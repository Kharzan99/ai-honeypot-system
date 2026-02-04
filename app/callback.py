# app/callback.py
import requests
import logging
from .config import GUVI_CALLBACK_URL, HTTP_TIMEOUT

log = logging.getLogger(__name__)

def send_final_result(session_id: str, scam_detected: bool, total_messages: int,
                      extracted_intelligence: dict, agent_notes: str) -> dict:
    payload = {
        "sessionId": session_id,
        "scamDetected": scam_detected,
        "totalMessagesExchanged": total_messages,
        "extractedIntelligence": extracted_intelligence,
        "agentNotes": agent_notes
    }
    try:
        r = requests.post(GUVI_CALLBACK_URL, json=payload, timeout=HTTP_TIMEOUT)
        r.raise_for_status()
        return {"ok": True, "status_code": r.status_code, "text": r.text}
    except Exception as e:
        log.exception("Failed to send final result")
        return {"ok": False, "error": str(e)}
