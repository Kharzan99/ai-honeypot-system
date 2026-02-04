# app/session_store.py
import json
import os
from typing import Dict, Any, List, Optional
from datetime import datetime

_SESSIONS_PATH = os.path.join(os.path.dirname(__file__), "..", "sessions.json")
_SESSIONS_PATH = os.path.abspath(_SESSIONS_PATH)

# config for memory manager
SHORT_MEMORY_LIMIT = 6         # last N messages kept verbatim
SUMMARY_TRIGGER_COUNT = 4      # summarize after this many incoming messages
SUMMARY_LENGTH = 3             # number of summary bullets to keep

def _read_all() -> Dict[str, Any]:
    try:
        if os.path.exists(_SESSIONS_PATH):
            with open(_SESSIONS_PATH, "r", encoding="utf-8") as f:
                return json.load(f)
    except Exception:
        return {}
    return {}

def _write_all(d: Dict[str, Any]) -> None:
    try:
        os.makedirs(os.path.dirname(_SESSIONS_PATH), exist_ok=True)
        with open(_SESSIONS_PATH, "w", encoding="utf-8") as f:
            json.dump(d, f, indent=2, ensure_ascii=False)
    except Exception:
        pass

def _default_session() -> Dict[str, Any]:
    return {
        "trust_score": 0,
        "messages_count": 0,
        "short_memory": [],        # list of {"sender","text","timestamp"}
        "long_summary": "",        # compressed summary bullets (string)
        "stage": "initial",
        "extracted_intelligence": {
            "bankAccounts": [],
            "upiIds": [],
            "phishingLinks": [],
            "phoneNumbers": [],
            "suspiciousKeywords": []
        },
        "message_history": []      # full history for inspection (kept, but short_memory used for prompts)
    }

def get_session(session_id: str) -> Dict[str, Any]:
    all_sessions = _read_all()
    return all_sessions.get(session_id, _default_session()).copy()

def save_session(session_id: str, state: Dict[str, Any]) -> None:
    all_sessions = _read_all()
    all_sessions[session_id] = state
    _write_all(all_sessions)

def delete_session(session_id: str) -> None:
    all_sessions = _read_all()
    if session_id in all_sessions:
        del all_sessions[session_id]
        _write_all(all_sessions)

# ---------- memory helpers ----------

def _prune_short_memory(short_memory: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return short_memory[-SHORT_MEMORY_LIMIT:]

def _merge_extracted(prev: Dict[str, Any], new: Dict[str, Any]) -> Dict[str, Any]:
    """Merge lists while keeping uniqueness and order."""
    out = {}
    for k in prev.keys():
        combined = (prev.get(k) or []) + (new.get(k) or [])
        seen = set()
        uniq = []
        for item in combined:
            if item and item not in seen:
                seen.add(item)
                uniq.append(item)
        out[k] = uniq
    return out

def _cheap_summarize(session_state: Dict[str, Any]) -> str:
    """
    Produce a short summary (few bullets) from extracted_intelligence + recent messages.
    This is intentionally lightweight and deterministic.
    """
    parts = []
    ei = session_state.get("extracted_intelligence", {})
    if ei:
        if ei.get("phishingLinks"):
            parts.append("Contains phishing links")
        if ei.get("upiIds"):
            parts.append("UPI IDs seen")
        if ei.get("phoneNumbers"):
            parts.append("Phone numbers seen")
        if ei.get("bankAccounts"):
            parts.append("Bank account numbers seen")
        kws = ei.get("suspiciousKeywords") or []
        if kws:
            parts.append("Keywords: " + ", ".join(kws[:5]))

    # examine last messages for patterns:
    short = session_state.get("short_memory", [])[-3:]
    for m in short:
        s = m.get("text", "")
        if "blocked" in s.lower():
            parts.append("Claims account will be blocked")
            break
    # fallback note about trust
    parts.append(f"Trust={session_state.get('trust_score',0)}")
    # reduce length:
    # keep first SUMMARY_LENGTH unique bullets
    uniq = []
    for p in parts:
        if p not in uniq:
            uniq.append(p)
        if len(uniq) >= SUMMARY_LENGTH:
            break
    return " • ".join(uniq)

def add_incoming_message(session_id: str, incoming: Dict[str, Any], extracted: Dict[str, Any]) -> Dict[str, Any]:
    """
    incoming: {"sender": str, "text": str, "timestamp": str|None}
    extracted: result of intelligence.extract_all(raw_text)
    Returns updated session_state.
    """
    all_sessions = _read_all()
    state = all_sessions.get(session_id, _default_session())

    # merge extracted intelligence
    state["extracted_intelligence"] = _merge_extracted(state.get("extracted_intelligence", {}), extracted)

    # append to full message_history (for inspection / debugging)
    entry = {
        "sender": incoming.get("sender"),
        "text": incoming.get("text"),
        "timestamp": incoming.get("timestamp") or datetime.utcnow().isoformat() + "Z"
    }
    state.setdefault("message_history", []).append(entry)

    # short memory (pruned)
    short = state.get("short_memory", [])
    short.append(entry)
    short = _prune_short_memory(short)
    state["short_memory"] = short

    # increment message counter
    state["messages_count"] = int(state.get("messages_count", 0)) + 1

    # update long summary periodically
    if state["messages_count"] % SUMMARY_TRIGGER_COUNT == 0:
        state["long_summary"] = _cheap_summarize(state)

    # persist
    all_sessions[session_id] = state
    _write_all(all_sessions)
    return state.copy()

# convenience to reset session entirely
def reset_session(session_id: str) -> None:
    all_sessions = _read_all()
    all_sessions[session_id] = _default_session()
    _write_all(all_sessions)
