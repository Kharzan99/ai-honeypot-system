# app/main.py
import logging
import json
import traceback
from fastapi import FastAPI, Header, HTTPException, Request, BackgroundTasks
from pydantic import BaseModel
from typing import Any, Dict, Optional
from .config import API_KEY, LLM_MODE
from .detector import predict
from .agent import generate_agent_reply
from .intelligence import extract_all
from . import session_store
from .callback import send_final_result
from . import llm as llm_module

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("ai-honeypot")

app = FastAPI(title="Agentic HoneyPot API")

class Message(BaseModel):
    sender: str
    text: str
    timestamp: str = None

class EventPayload(BaseModel):
    sessionId: str
    message: Message
    conversationHistory: list = []
    metadata: dict = {}

def verify_key(x_api_key: str = Header(...)):
    if x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API key")

@app.post("/event", summary="Handle incoming conversation event")
async def handle_event(request: Request, background: BackgroundTasks, x_api_key: str = Header(...)):
    """
    Robust handler that:
      - logs headers + raw body for debugging
      - attempts to parse JSON manually (works even if tester uses slightly different Content-Type)
      - validates with EventPayload
      - runs detection + agent flow as before
    """
    try:
        # 1) auth
        verify_key(x_api_key)

        # 2) read raw body and headers (for debugging)
        raw_headers = dict(request.headers)
        try:
            raw_body_bytes = await request.body()
            raw_body_text = raw_body_bytes.decode("utf-8", errors="replace")
        except Exception:
            raw_body_text = "<could not read raw body>"
        log.info(f"Incoming /event headers: {raw_headers}")
        log.info(f"Incoming /event raw body: {raw_body_text}")

        # 3) try parse JSON safely
        try:
            payload_json = await request.json()
        except Exception as e:
            # The tester might have sent non-JSON or incorrect content-type.
            log.warning(f"Failed to parse JSON automatically: {e}")
            # Try a best-effort manual parse from the raw text
            try:
                payload_json = json.loads(raw_body_text) if raw_body_text else {}
            except Exception as e2:
                log.error(f"Manual JSON parse also failed: {e2}")
                raise HTTPException(status_code=422, detail="Invalid or missing JSON body")

        # 4) validate with Pydantic (EventPayload)
        try:
            payload = EventPayload.parse_obj(payload_json)
        except Exception as e:
            # Log validation errors and the payload for easy debugging
            log.error("EventPayload validation error: %s", e)
            log.error("Payload that failed validation: %s", payload_json)
            # Return a clear 422 with details for the tester
            raise HTTPException(status_code=422, detail=f"Invalid request body: {str(e)}")

        # 5) proceed with original logic using 'payload'
        session_id = payload.sessionId
        msg = payload.message
        raw_text = msg.text or ""

        extracted = extract_all(raw_text)
        log.info(f"[{session_id}] Extracted intelligence: {extracted}")

        det = predict(raw_text)
        log.info(f"[{session_id}] Detection result: scamDetected={det['scamDetected']}, reason={det.get('reason')}, score={det.get('score')}")

        session_state = session_store.get_session(session_id) or {
            "trust_score": 0,
            "stage": "initial",
            "messages_count": 0,
            "upi_seen": False,
            "link_seen": False,
            "phone_seen": False,
            "extracted_intelligence": {
                "bankAccounts": [],
                "upiIds": [],
                "phishingLinks": [],
                "phoneNumbers": [],
                "suspiciousKeywords": []
            },
            "message_history": []
        }

        out = {
            "sessionId": session_id,
            "scamDetected": det["scamDetected"],
            "detectionScore": det.get("score"),
            "detectionReason": det.get("reason"),
            "agentReply": None,
            "extractedIntelligence": extracted,
            "finalized": False
        }

        if det["scamDetected"]:
            last_message = {"text": raw_text, "sender": msg.sender}
            agent_out = generate_agent_reply(
                session_state=session_state,
                last_message=last_message,
                extracted=extracted,
                mode="template",
                llm_generate=None
            )

            session_state = agent_out.get("session_state", session_state)
            session_state["message_history"].append({
                "sender": msg.sender,
                "text": raw_text,
                "timestamp": msg.timestamp
            })
            session_state["message_history"].append({
                "sender": "agent",
                "text": agent_out["reply"],
                "timestamp": None
            })

            out["agentReply"] = {
                "reply": agent_out["reply"],
                "intent": agent_out["intent"]
            }

            intel_count = sum(len(v) for v in extracted.values())
            total_messages = len(session_state["message_history"])
            has_payment_info = bool(extracted.get("upiIds") or extracted.get("phoneNumbers") or extracted.get("phishingLinks"))
            if has_payment_info and total_messages >= 3:
                out["finalized"] = True
                log.info(f"[{session_id}] Auto-finalizing: intel_count={intel_count}, messages={total_messages}")
                agent_notes = f"auto-finalized by agent. extracted={extracted}, messages={total_messages}"
                background.add_task(send_final_result, session_id, True, total_messages, extracted, agent_notes)

        session_store.save_session(session_id, session_state)
        return out

    except HTTPException:
        # Re-raise FastAPI HTTP exceptions
        raise
    except Exception as e:
        log.exception("Error in handle_event (unexpected): %s", e)
        # Provide minimal info (avoid exposing secrets)
        return {"error": "internal_server_error", "detail": str(e)}

@app.get("/session/{session_id}")
def get_session_state(session_id: str, x_api_key: str = Header(...)):
    verify_key(x_api_key)
    state = session_store.get_session(session_id) or {}
    return {
        "sessionId": session_id,
        "trustScore": state.get("trust_score", 0),
        "stage": state.get("stage", "initial"),
        "messagesCount": state.get("messages_count", 0),
        "extractedIntelligence": state.get("extracted_intelligence", {}),
        "messageHistory": state.get("message_history", []),
        "shortMemory": state.get("short_memory", []),
        "longSummary": state.get("long_summary", "")
    }

@app.post("/session/{session_id}/delete")
def delete_session(session_id: str, x_api_key: str = Header(...)):
    verify_key(x_api_key)
    session_store.delete_session(session_id)
    return {"sessionId": session_id, "status": "deleted"}


@app.get("/health")
def health():
    return {"ok": True, "service": "ai-honeypot", "version": "v1"}

@app.post("/event-echo")
async def event_echo(request: Request, x_api_key: str = Header(None)):
    # Echo raw body + headers (no validation) - only for debugging
    raw_body = await request.body()
    try:
        parsed = await request.json()
    except Exception:
        parsed = None
    return {
        "headers": dict(request.headers),
        "raw_body": raw_body.decode("utf-8", errors="replace"),
        "parsed_json": parsed
    }
