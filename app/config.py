# app/config.py
import os
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()

BASE_DIR = Path(__file__).resolve().parent.parent

API_KEY = os.environ.get("AH_API_KEY", "super12345")

DETECTOR_PIPELINE_PATH = os.environ.get(
    "DETECTOR_PIPELINE_PATH",
    str(BASE_DIR / "detector_pipeline_final.pkl")
)
RULES_CONFIG_PATH = os.environ.get(
    "RULES_CONFIG_PATH",
    str(BASE_DIR / "rules_config.json")
)

LLM_MODE = os.environ.get("LLM_MODE", "dummy")  # options: dummy | subprocess
MODEL_PATH = os.environ.get("LOCAL_GGUF_PATH", str(BASE_DIR / "models" / "mistral-7b-instruct-q4.gguf"))

# LLAMA subprocess command template.
# Must contain {model} and {prompt}. Optionally {max_tokens}.
# NOTE: SubprocessLLM treats the {prompt} placeholder as a single argument.
# Example: build/bin/llama-simple-chat -m {model} -p {prompt} --n_predict {max_tokens}
LLAMA_SUBPROCESS_CMD_TEMPLATE = os.environ.get(
    "LLAMA_CMD",
    "build/bin/llama-simple-chat -m {model} -p {prompt} --n_predict {max_tokens}"
)

RULE_THRESHOLD = float(os.environ.get("RULE_THRESHOLD", 2.0))
ML_PROB_THRESHOLD = float(os.environ.get("ML_PROB_THRESHOLD", 0.475))

GUVI_CALLBACK_URL = os.environ.get("GUVI_CALLBACK_URL", "https://hackathon.guvi.in/api/updateHoneyPotFinalResult")
HTTP_TIMEOUT = int(os.environ.get("HTTP_TIMEOUT", "5"))
