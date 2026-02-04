"""
Run LLM-assisted symbolic-execution prompts and normalize the JSON solutions output.
"""

import asyncio
import json
import os
import re

from llm_utils import get_default_client
from llm_utils.taint.taint_llm_calls import chat_text_with_retries


_FENCE_RE = re.compile(r"```(?:json)?\s*([\s\S]*?)\s*```", flags=re.IGNORECASE)


def _ensure_dir(p: str) -> None:
    if not p:
        return
    try:
        os.makedirs(p, exist_ok=True)
    except Exception:
        return


def _read_text(path: str) -> str:
    if not isinstance(path, str) or not path:
        return ""
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            return f.read()
    except Exception:
        return ""


def _write_text(path: str, text: str) -> None:
    _ensure_dir(os.path.dirname(os.path.abspath(path)))
    with open(path, "w", encoding="utf-8") as f:
        f.write(text or "")


def _extract_json_text(text: str) -> str | None:
    if not isinstance(text, str):
        return None
    t = text.strip()
    if not t:
        return None
    m = _FENCE_RE.search(t)
    if m:
        inner = (m.group(1) or "").strip()
        if inner.startswith("{") and inner.endswith("}"):
            return inner
    i = t.find("{")
    j = t.rfind("}")
    if i >= 0 and j >= 0 and j > i:
        return t[i : j + 1]
    return None


def _normalize_solutions(obj) -> list[dict]:
    if obj is None:
        return []
    if isinstance(obj, list):
        out = []
        for x in obj:
            if isinstance(x, dict):
                out.append(x)
        return out
    if isinstance(obj, dict):
        sols = obj.get("solutions")
        if isinstance(sols, list):
            out = []
            for x in sols:
                if isinstance(x, dict):
                    out.append(x)
            return out
        return [obj] if obj else []
    return []


def parse_symbolic_response(text: str) -> list[dict]:
    if not isinstance(text, str) or not text.strip():
        return []
    try:
        obj = json.loads(text)
    except Exception:
        js = _extract_json_text(text)
        if not js:
            return []
        try:
            obj = json.loads(js)
        except Exception:
            return []
    return _normalize_solutions(obj)


def build_symbolic_response_example() -> str:
    lines = []
    lines.append("{")
    lines.append('  "solutions": [')
    lines.append("    {")
    lines.append('      "POST": {')
    lines.append('        "username": "new_admin",')
    lines.append('        "status": "active"')
    lines.append("      },")
    lines.append('      "COOKIE": {')
    lines.append('        "session_id": "updated_session_12345",')
    lines.append('        "user_token": "new_token_abc"')
    lines.append("      }")
    lines.append("    },")
    lines.append("    {")
    lines.append('      "ENV": {')
    lines.append('        "METHOD": "GET"')
    lines.append("      }")
    lines.append("    }")
    lines.append("  ]")
    lines.append("}")
    return "\n".join(lines).rstrip() + "\n"


def write_symbolic_prompt(prompt_text: str, *, run_dir: str, seq: int) -> str:
    prompt_dir = os.path.join(run_dir, "symbolic", "prompts")
    _ensure_dir(prompt_dir)
    path = os.path.join(prompt_dir, f"symbolic_prompt_{int(seq)}.txt")
    _write_text(path, prompt_text)
    return path


def write_symbolic_response(text: str, *, run_dir: str, seq: int) -> tuple[str, str]:
    resp_dir = os.path.join(run_dir, "symbolic", "responses")
    _ensure_dir(resp_dir)
    raw_path = os.path.join(resp_dir, f"symbolic_response_{int(seq)}.txt")
    json_path = os.path.join(resp_dir, f"symbolic_response_{int(seq)}.json")
    _write_text(raw_path, text)
    solutions = parse_symbolic_response(text)
    try:
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump({"solutions": solutions}, f, ensure_ascii=False, indent=2)
    except Exception:
        _write_text(json_path, "{\n  \"solutions\": []\n}\n")
    return raw_path, json_path


# Summary: Execute a symbolic-execution prompt (or reuse offline outputs) and persist prompt/response artifacts.
def run_symbolic_prompt(
    prompt_text: str,
    *,
    run_dir: str,
    seq: int,
    llm_offline: bool = False,
    logger=None,
) -> dict:
    prompt_path = write_symbolic_prompt(prompt_text, run_dir=run_dir, seq=int(seq))
    resp_dir = os.path.join(run_dir, "symbolic", "responses")
    raw_resp_path = os.path.join(resp_dir, f"symbolic_response_{int(seq)}.txt")
    json_resp_path = os.path.join(resp_dir, f"symbolic_response_{int(seq)}.json")

    if llm_offline:
        solutions = []
        if os.path.exists(json_resp_path):
            try:
                obj2 = json.loads(_read_text(json_resp_path))
                solutions = _normalize_solutions(obj2)
            except Exception:
                solutions = []
        return {
            "prompt_path": prompt_path,
            "response_path": raw_resp_path if os.path.exists(raw_resp_path) else "",
            "response_json_path": json_resp_path if os.path.exists(json_resp_path) else "",
            "response_obj": solutions,
            "llm_offline": True,
        }

    client = None
    try:
        client = get_default_client()
    except Exception:
        client = None
    if client is None:
        raise RuntimeError("llm_client_init_failed")

    max_attempts = 3
    try:
        mr = getattr(client, "max_retries", None)
        if mr is not None:
            max_attempts = max(1, int(mr))
    except Exception:
        max_attempts = 3

    async def _call():
        return await chat_text_with_retries(
            client=client,
            prompt=prompt_text,
            system=None,
            logger=logger,
            max_attempts=max_attempts,
            call_index=1,
        )

    response_text = asyncio.run(_call())
    raw_path, json_path = write_symbolic_response(response_text, run_dir=run_dir, seq=int(seq))
    return {
        "prompt_path": prompt_path,
        "response_path": raw_path,
        "response_json_path": json_path,
        "response_obj": parse_symbolic_response(response_text),
        "llm_offline": False,
    }
