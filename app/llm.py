# app/llm.py
import subprocess
import logging
from typing import Optional, List
from .config import LLM_MODE, MODEL_PATH, LLAMA_SUBPROCESS_CMD_TEMPLATE

log = logging.getLogger(__name__)

class BaseLLM:
    def generate(self, prompt: str, max_tokens: int = 256, temperature: float = 0.2) -> str:
        raise NotImplementedError()

class DummyLLM(BaseLLM):
    """
    Deterministic filler for offline testing. Sounds more natural/Indian.
    """
    def generate(self, prompt: str, max_tokens: int = 256, temperature: float = 0.2) -> str:
        up = prompt.upper()
        if "UPI" in up or "ASK_FOR_UPI" in up:
            return "Okay, I understand. Which UPI ID should I use? Please share the UPI ID or phone number."
        if "BLOCK" in up or "WHY" in up or "ASK_REASON" in up:
            return "Why is my account being blocked? Please explain what's wrong so I can check."
        if "LINK" in up:
            return "Can you send the link again? I want to check it first."
        if "BANK" in up:
            return "Which bank account do you mean? Please tell me the account or branch name."
        # default fallback
        return "I am not sure I understand, can you explain in short?"

class SubprocessLLM(BaseLLM):
    """
    Uses a local llama.cpp CLI (or similar) to generate text.
    We build an argv list to avoid shell quoting issues.
    The config LLAMA_SUBPROCESS_CMD_TEMPLATE must contain placeholders {model} and {prompt} and optionally {max_tokens}.
    Example template: "build/bin/llama-simple-chat -m {model} -p {prompt} --n_predict {max_tokens}"
    """
    def __init__(self, cmd_template: Optional[str] = None, model_path: Optional[str] = None):
        self.cmd_template = cmd_template or LLAMA_SUBPROCESS_CMD_TEMPLATE
        self.model_path = model_path or MODEL_PATH
        if "{model}" not in self.cmd_template or "{prompt}" not in self.cmd_template:
            raise ValueError("LLAMA cmd template must contain {model} and {prompt} placeholders")

    def _build_argv(self, prompt: str, max_tokens: int) -> List[str]:
        # naive but effective: replace placeholders then split on spaces, but keep prompt as single arg
        # approach: split template into two parts: pre and post prompt; replace {model} then insert prompt arg
        template = self.cmd_template
        # replace model and max_tokens placeholders first
        template = template.replace("{model}", str(self.model_path))
        template = template.replace("{max_tokens}", str(max_tokens))
        # find where "{prompt}" occurs
        if "{prompt}" not in self.cmd_template:
            # fallback: simple split
            return template.split()
        pre, post = template.split("{prompt}", 1)
        argv = []
        argv.extend(pre.strip().split())
        argv.append(prompt)   # pass prompt as single argument
        if post.strip():
            argv.extend(post.strip().split())
        return argv

    def generate(self, prompt: str, max_tokens: int = 256, temperature: float = 0.2) -> str:
        argv = self._build_argv(prompt, max_tokens)
        log.debug("Running LLM command argv: %s", argv[:8])
        try:
            proc = subprocess.run(argv, capture_output=True, text=True, timeout=60)
        except subprocess.SubprocessError as e:
            log.exception("LLM subprocess failed")
            return f"[LLM ERROR] {e}"
        out = (proc.stdout or "").strip()
        if not out:
            out = (proc.stderr or "").strip()
        # sometimes CLI prints banner + answer; try to return only last paragraph
        if out:
            # heuristics: split by double newlines and take last non-empty chunk
            chunks = [c.strip() for c in out.split("\n\n") if c.strip()]
            if chunks:
                return chunks[-1]
        return out or "[LLM produced no output]"

def get_llm():
    if LLM_MODE == "subprocess":
        return SubprocessLLM()
    return DummyLLM()
