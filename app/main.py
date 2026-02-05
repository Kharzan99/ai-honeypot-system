# app/main.py
import logging
import json
import os
import re
from datetime import datetime, timezone
from fastapi import FastAPI, Header, HTTPException, Request, BackgroundTasks
from pydantic import BaseModel, Field, ValidationError as PydanticValidationError
from typing import Any, Dict, Optional, Union, List

from .config import API_KEY, LLM_MODE
from .detector import predict
from .agent import generate_agent_reply
from .intelligence import extract_all
from . import session_store
from .callback import send_final_result
from . import llm as llm_module
from .llm import normalize_output_text

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("ai-honeypot")

# Logging security controls
LOG_RAW_BODY = os.environ.get("LOG_RAW_BODY", "false").lower() in ("1", "true", "yes")

URL_RE = re.compile(r'https?://[^\s,;]+', re.IGNORECASE)
UPI_RE = re.compile(r'\b[A-Za-z0-9._\-]{2,256}@[A-Za-z0-9._\-]{2,40}\b')
PHONE_RE = re.compile(r'(\+?\d[\d\s\-\(\)]{7,}\d)')

def mask_headers(headers: dict) -> dict:
    """Redact sensitive headers (x-api-key) before logging."""
    h = dict(headers)
    if "x-api-key" in h:
        h["x-api-key"] = "***REDACTED***"
    return h

def sanitize_text_for_log(text: str, max_len: int = 140) -> str:
    """Remove URLs, UPI IDs, phone numbers from text for safe logging."""
    if not isinstance(text, str):
        return ""
    s = text
    s = URL_RE.sub("<URL>", s)
    s = UPI_RE.sub("<UPI>", s)
    s = PHONE_RE.sub("<PHONE>", s)
    s = " ".join(s.split())  # collapse whitespace
    if len(s) > max_len:
        return s[:max_len] + "…"
    return s

app = FastAPI(title="Agentic HoneyPot API")


# --- Models (updated) ---
class Message(BaseModel):
    sender: str
    text: str
    # Accept string ISO timestamps OR integer unix timestamps (seconds or ms)
    timestamp: Optional[Union[str, int]] = None


class EventPayload(BaseModel):
    sessionId: str
    message: Message
    conversationHistory: List[Dict[str, Any]] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)

    class Config:
        # pydantic v2: use json_schema_extra to avoid deprecation warning
        json_schema_extra = {
            "example": {
                "sessionId": "wertyu-dfghj-ertyui",
                "message": {
                    "sender": "scammer",
                    "text": "Your bank account will be blocked today. Verify immediately.",
                    "timestamp": "2026-01-21T10:15:30Z"
                },
                "conversationHistory": [],
                "metadata": {"channel": "SMS", "language": "English", "locale": "IN"}
            }
        }


def verify_key(x_api_key: str = Header(...)):
    if x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API key")


# --- Helper: normalize timestamp field ---
def normalize_timestamp_field(payload: EventPayload) -> None:
    """
    Convert numeric timestamps in payload.message.timestamp to ISO-8601 (UTC, ending with Z).
    If it's already a string, attempt to canonicalize to ISO-8601 (if parseable), else leave it.
    Mutates payload in-place.
    """
    ts = payload.message.timestamp
    if ts is None:
        return

    # If numeric (int), heuristically treat as ms or seconds and convert to UTC ISO string
    if isinstance(ts, int):
        try:
            # heuristic for ms vs s (use ms when large)
            if ts > 10**12:
                dt = datetime.fromtimestamp(ts / 1000.0, tz=timezone.utc)
            elif ts > 10**9:
                # likely ms as well
                dt = datetime.fromtimestamp(ts / 1000.0, tz=timezone.utc)
            else:
                # seconds
                dt = datetime.fromtimestamp(ts, tz=timezone.utc)
            payload.message.timestamp = dt.isoformat().replace("+00:00", "Z")
        except Exception:
            # fallback: convert to str
            payload.message.timestamp = str(ts)
        return

    # If it's a string, try to parse to canonical ISO format (best effort)
    if isinstance(ts, str):
        try:
            # datetime.fromisoformat doesn't accept trailing Z so replace with +00:00
            dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
            payload.message.timestamp = dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
        except Exception:
            # leave as-is if parsing fails
            pass

@app.post("/event", summary="Handle incoming conversation event")
async def handle_event(request: Request, background: BackgroundTasks, x_api_key: str = Header(...)):
    """
    Robust handler that:
      - logs headers + raw body for debugging
      - normalizes numeric timestamps to ISO-8601 strings
      - attempts to parse JSON manually (works even if tester uses slightly different Content-Type)
      - validates with EventPayload
      - persists ALL messages (scam & non-scam) to keep session memory consistent
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
        
        # Log headers with API key masked
        safe_headers = mask_headers(raw_headers)
        log.info(f"Incoming /event headers: {safe_headers}")
        
        # Log body: verbose if enabled, else show sanitized preview
        if LOG_RAW_BODY:
            log.info(f"Incoming /event raw body: {raw_body_text}")
        else:
            try:
                j = json.loads(raw_body_text) if raw_body_text else {}
                msg = j.get("message", {}) if isinstance(j, dict) else {}
                preview = sanitize_text_for_log(msg.get("text", ""))
                log.info(f"Incoming /event body preview: sessionId={j.get('sessionId')}, message_preview={preview}")
            except Exception:
                log.info("Incoming /event body: <unparsable or empty>")

        # 3) try parse JSON safely
        try:
            payload_json = await request.json()
        except Exception as e:
            log.warning(f"Failed to parse JSON automatically: {e}")
            try:
                payload_json = json.loads(raw_body_text) if raw_body_text else {}
            except Exception as e2:
                log.error(f"Manual JSON parse also failed: {e2}")
                raise HTTPException(status_code=422, detail="Invalid or missing JSON body")

        # 4) Normalize numeric timestamps BEFORE Pydantic validation
        if "message" in payload_json and isinstance(payload_json["message"], dict):
            ts = payload_json["message"].get("timestamp")
            if isinstance(ts, (int, float)):
                ts_seconds = ts / 1000 if ts > 10**11 else ts
                from datetime import datetime, timezone
                normalized = datetime.fromtimestamp(ts_seconds, tz=timezone.utc).isoformat().replace("+00:00", "Z")
                payload_json["message"]["timestamp"] = normalized
                log.info(f"Normalized numeric timestamp {ts} → {normalized}")

        # 5) validate with Pydantic (EventPayload)
        try:
            if hasattr(EventPayload, "model_validate"):
                # pydantic v2
                payload = EventPayload.model_validate(payload_json)
            else:
                # fallback (pydantic v1 compatible)
                payload = EventPayload.parse_obj(payload_json)
        except PydanticValidationError as ve:
            # structured validation errors
            try:
                errs = ve.errors()
            except Exception:
                errs = str(ve)
            log.error("EventPayload validation errors: %s", errs)
            raise HTTPException(status_code=422, detail={"validation_errors": errs})
        except Exception as e:
            log.exception("Unexpected error during payload validation: %s", e)
            raise HTTPException(status_code=422, detail=str(e))

        # 6) proceed with original logic using 'payload'
        session_id = payload.sessionId
        msg = payload.message
        raw_text = msg.text or ""

        extracted = extract_all(raw_text)
        log.info(f"[{session_id}] Extracted intelligence: {extracted}")

        det = predict(raw_text)
        log.info(f"[{session_id}] Detection result: scamDetected={det['scamDetected']}, reason={det.get('reason')}, score={det.get('score')}")

        # Load an existing session or blank default (session_store.add_incoming_message will create & persist)
        session_state = session_store.get_session(session_id) or {}

        # Persist incoming message & merge extracted intelligence (always do this)
        session_state = session_store.add_incoming_message(
            session_id,
            {"sender": msg.sender, "text": raw_text, "timestamp": msg.timestamp},
            extracted
        )

        # Now use merged intelligence for API response and for agent decisions
        merged_intel = session_state.get("extracted_intelligence", extracted)

        out = {
            "sessionId": session_id,
            "scamDetected": det["scamDetected"],
            "detectionScore": det.get("score"),
            "detectionReason": det.get("reason"),
            "agentReply": None,
            "extractedIntelligence": merged_intel,
            "finalized": False
        }

        if det["scamDetected"]:
            # choose llm generate callable if configured
            llm_instance = None
            llm_generate = None
            try:
                llm_instance = llm_module.get_llm()
                llm_generate = getattr(llm_instance, "generate", None)
            except Exception:
                llm_generate = None

            # Provide "llm" mode so generate_agent_reply will rephrase the selected template if available
            agent_out = generate_agent_reply(
                session_state=session_state,
                last_message={"text": raw_text, "sender": msg.sender},
                extracted=merged_intel,
                mode="llm" if llm_generate else "template",
                llm_generate=llm_generate
            )

            # Update session state returned by agent (it may modify stage/trust)
            session_state = agent_out.get("session_state", session_state)

            # Append agent reply into session_state (both message_history and short_memory) and save
            agent_entry = {
                "sender": "agent",
                "text": agent_out["reply"],
                "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
            }
            session_state.setdefault("message_history", []).append(agent_entry)
            short = session_state.get("short_memory", [])
            short.append(agent_entry)
            short = short[-session_store.SHORT_MEMORY_LIMIT:]
            session_state["short_memory"] = short

            # persist
            session_store.save_session(session_id, session_state)

            # Normalize agent reply for clean output (fix encoding issues)
            normalized_reply = normalize_output_text(agent_out["reply"])
            out["agentReply"] = {
                "reply": normalized_reply,
                "intent": agent_out["intent"]
            }

            out["reply"] = agent_out["reply"]

            # reflect merged intelligence in the response
            out["extractedIntelligence"] = session_state.get("extracted_intelligence", merged_intel)

            # finalization logic must use merged intelligence (not only current message)
            merged_intel = session_state.get("extracted_intelligence", merged_intel)
            intel_count = sum(len(v) for v in merged_intel.values())
            total_messages = len(session_state.get("message_history", []))
            has_payment_info = bool(merged_intel.get("upiIds") or merged_intel.get("phoneNumbers") or merged_intel.get("phishingLinks"))
            if has_payment_info and total_messages >= 3:
                out["finalized"] = True
                log.info(f"[{session_id}] Auto-finalizing: intel_count={intel_count}, messages={total_messages}")
                agent_notes = f"auto-finalized by agent. extracted={merged_intel}, messages={total_messages}"
                background.add_task(send_final_result, session_id, True, total_messages, merged_intel, agent_notes)

        session_store.save_session(session_id, session_state)
        return out

    except HTTPException:
        raise
    except Exception as e:
        log.exception("Error in handle_event (unexpected): %s", e)
        raise HTTPException(status_code=500, detail="internal_server_error")


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



