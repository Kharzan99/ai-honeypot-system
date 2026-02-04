# app/main.py
import logging
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
async def handle_event(payload: EventPayload, background: BackgroundTasks, x_api_key: str = Header(...)):
    try:
        verify_key(x_api_key)
        session_id = payload.sessionId
        msg = payload.message
        raw_text = msg.text or ""

        # 1) Extract intelligence from raw message text
        extracted = extract_all(raw_text)
        log.info(f"[{session_id}] Extracted intelligence: {extracted}")

        # 2) Run detector
        det = predict(raw_text)
        log.info(f"[{session_id}] Detection result: scamDetected={det['scamDetected']}, reason={det.get('reason')}, score={det.get('score')}")

        # 3) Load or initialize session state
        session_state = session_store.get_session(session_id)

        # Bootstrap from conversationHistory if provided and session is empty
        if payload.conversationHistory and not session_state.get("message_history"):
            log.info(f"[{session_id}] Bootstrapping session from {len(payload.conversationHistory)} conversation history entries")
            for m in payload.conversationHistory:
                # m expected as dict with sender, text, timestamp
                hist_entry = {
                    "sender": m.get("sender"),
                    "text": m.get("text"),
                    "timestamp": m.get("timestamp")
                }
                session_store.add_incoming_message(session_id, hist_entry, {})
            # reload state after bootstrap
            session_state = session_store.get_session(session_id)

        # 4) Add incoming message to memory manager (updates short_memory, long_summary, message counts)
        incoming = {"sender": msg.sender, "text": raw_text, "timestamp": msg.timestamp}
        session_state = session_store.add_incoming_message(session_id, incoming, extracted)

        # 5) Build response envelope
        out: Dict[str, Any] = {
            "sessionId": session_id,
            "scamDetected": det["scamDetected"],
            "detectionScore": det.get("score"),
            "detectionReason": det.get("reason"),
            "agentReply": None,
            "extractedIntelligence": session_state.get("extracted_intelligence", {}),
            "finalized": False
        }

        # may use LLM rephraser if configured
        llm_instance = None
        if LLM_MODE == "subprocess":
            try:
                llm_instance = llm_module.get_llm()
            except Exception as e:
                log.exception("Failed to init LLM subprocess: %s", e)
                llm_instance = None

        # 6) If scam detected, activate agent and reply
        if det["scamDetected"]:
            last_message = {"text": raw_text, "sender": msg.sender}
            # use llm_generate only if llm instance is available
            agent_out = generate_agent_reply(
                session_state=session_state,
                last_message=last_message,
                extracted=extracted,
                mode="llm" if llm_instance else "template",
                llm_generate=(llm_instance.generate if llm_instance else None)
            )

            session_state = agent_out.get("session_state", session_state)

            # add agent reply to memory (agent is sender)
            agent_entry = {"sender": "agent", "text": agent_out["reply"], "timestamp": None}
            session_state = session_store.add_incoming_message(session_id, agent_entry, {})

            out["agentReply"] = {
                "reply": agent_out["reply"],
                "intent": agent_out["intent"]
            }

            # decide auto-finalize
            intel_count = sum(len(v) for v in session_state.get("extracted_intelligence", {}).values())
            total_messages = len(session_state.get("message_history", []))
            has_payment_info = bool(session_state.get("extracted_intelligence", {}).get("upiIds") or session_state.get("extracted_intelligence", {}).get("phoneNumbers") or session_state.get("extracted_intelligence", {}).get("phishingLinks"))
            if has_payment_info and total_messages >= 3 and not session_state.get("finalized"):
                out["finalized"] = True
                session_state["finalized"] = True  # persist finalization state
                log.info(f"[{session_id}] Auto-finalizing: intel_count={intel_count}, messages={total_messages}")
                agent_notes = f"auto-finalized by agent. extracted={session_state.get('extracted_intelligence', {})}, messages={total_messages}"
                # save session before sending callback to prevent duplicate callbacks
                session_store.save_session(session_id, session_state)
                background.add_task(send_final_result, session_id, True, total_messages, session_state.get('extracted_intelligence', {}), agent_notes)

        # 7) Save final state (if not already saved during finalization)
        if not out.get("finalized"):
            session_store.save_session(session_id, session_state)

        return out
    except Exception as e:
        log.exception(f"Error in handle_event: {e}")
        return {"error": str(e), "status": "failed"}

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
