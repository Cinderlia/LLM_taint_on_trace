"""
Run LLM-assisted symbolic-execution prompts and normalize the JSON solutions output.
"""

import asyncio
import json
import os
import re

from common.app_config import load_app_config
from llm_utils import get_default_client
from llm_utils.taint.taint_llm_calls import chat_text_with_retries


_FENCE_RE = re.compile(r"```(?:json)?\s*([\s\S]*?)\s*```", flags=re.IGNORECASE)


def _load_symbolic_llm_temperature() -> float:
    try:
        cfg = load_app_config()
        raw = cfg.raw if hasattr(cfg, "raw") else {}
    except Exception:
        raw = {}
    sec = raw.get("symbolic_prompt")
    if not isinstance(sec, dict):
        sec = {}
    v = sec.get("llm_temperature")
    try:
        return float(v) if v is not None else 0.2
    except Exception:
        return 0.2


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


def symbolic_response_has_valid_json(text: str) -> bool:
    if not isinstance(text, str) or not text.strip():
        return False
    try:
        obj = json.loads(text)
    except Exception:
        js = _extract_json_text(text)
        if not js:
            return False
        try:
            obj = json.loads(js)
        except Exception:
            return False
    return isinstance(obj, (dict, list))


def _stringify_value(v) -> str:
    if v is None:
        return ""
    if isinstance(v, (dict, list)):
        try:
            return json.dumps(v, ensure_ascii=False)
        except Exception:
            return str(v)
    return str(v)


def _split_query_pairs(text: str) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    s = (text or "").strip()
    if not s:
        return out
    for part in s.split("&"):
        part_s = (part or "").strip()
        if not part_s:
            continue
        if "=" in part_s:
            k, v = part_s.split("=", 1)
            out.append((k, v))
        else:
            out.append((part_s, ""))
    return out


def _pairs_to_query(pairs: list[tuple[str, str]]) -> str:
    buf = []
    for k, v in pairs:
        ks = (k or "").strip()
        vs = _stringify_value(v)
        if not ks and not vs:
            continue
        buf.append(f"{ks}={vs}")
    return "&".join(buf)


def _normalize_export_line(line: str) -> str:
    v = (line or "").strip()
    if not v:
        return ""
    if v.startswith("export "):
        return v
    return "export " + v


def _parse_env_kv(line: str) -> tuple[str, str] | None:
    v = (line or "").strip()
    if not v:
        return None
    if v.startswith("export "):
        v = (v[len("export ") :] or "").strip()
    if "=" not in v:
        return None
    k, val = v.split("=", 1)
    k = (k or "").strip()
    if not k:
        return None
    return k, val


def _merge_env_lines(base_lines: list[str], override_lines: list[str]) -> list[str]:
    if not base_lines and not override_lines:
        return []
    out: list[str] = []
    index: dict[str, int] = {}
    for line in base_lines or []:
        kv = _parse_env_kv(line)
        if not kv:
            continue
        k, v = kv
        index[k] = len(out)
        out.append(_normalize_export_line(f"{k}={v}"))
    for line in override_lines or []:
        kv = _parse_env_kv(line)
        if not kv:
            continue
        k, v = kv
        norm_line = _normalize_export_line(f"{k}={v}")
        if k in index:
            out[index[k]] = norm_line
        else:
            index[k] = len(out)
            out.append(norm_line)
    return out


def _normalize_env_lines(env_obj, *, defaults: list[str] | None = None, use_default: bool = False) -> list[str]:
    if use_default:
        return list(defaults or [])
    if env_obj is None:
        return []
    if isinstance(env_obj, dict):
        return [_normalize_export_line(f"{k}={_stringify_value(v)}") for k, v in env_obj.items()]
    if isinstance(env_obj, (list, tuple)):
        out = []
        for it in env_obj:
            if isinstance(it, dict):
                out.extend([_normalize_export_line(f"{k}={_stringify_value(v)}") for k, v in it.items()])
                continue
            if isinstance(it, (list, tuple)) and len(it) >= 2:
                out.append(_normalize_export_line(f"{it[0]}={_stringify_value(it[1])}"))
                continue
            if isinstance(it, str):
                v = it.strip()
                if v:
                    out.append(_normalize_export_line(v))
                continue
        return [x for x in out if x]
    if isinstance(env_obj, str):
        out = []
        for line in env_obj.splitlines():
            v = line.strip()
            if v:
                out.append(_normalize_export_line(v))
        return [x for x in out if x]
    return []


def _normalize_request_field(field_obj, *, default_value: str, use_default: bool) -> str:
    if use_default:
        return (default_value or "").strip()
    if field_obj is None:
        return ""
    if isinstance(field_obj, dict):
        pairs = [(k, _stringify_value(v)) for k, v in field_obj.items()]
        return _pairs_to_query(pairs).strip()
    if isinstance(field_obj, (list, tuple)):
        pairs: list[tuple[str, str]] = []
        for it in field_obj:
            if isinstance(it, dict):
                for k, v in it.items():
                    pairs.append((k, _stringify_value(v)))
                continue
            if isinstance(it, (list, tuple)) and len(it) >= 2:
                pairs.append((it[0], _stringify_value(it[1])))
                continue
            if isinstance(it, str):
                pairs.extend(_split_query_pairs(it))
                continue
        if pairs:
            return _pairs_to_query(pairs).strip()
        return ""
    if isinstance(field_obj, str):
        return field_obj.strip()
    return _stringify_value(field_obj).strip()


def _parse_test_command_text(text: str) -> dict:
    env_lines: list[str] = []
    cookie_value = ""
    get_value = ""
    post_value = ""
    if not isinstance(text, str) or not text.strip():
        return {"env_lines": env_lines, "COOKIE": cookie_value, "GET": get_value, "POST": post_value}
    for raw in text.splitlines() or []:
        line = (raw or "").strip()
        if not line:
            continue
        if line.startswith("export "):
            rest = (line[len("export ") :] or "").strip()
            if rest:
                env_lines.append(_normalize_export_line(rest))
            continue
        if line.startswith("COOKIE:"):
            cookie_value = (line.split("COOKIE:", 1)[1] or "").strip()
            continue
        if line.startswith("GET:"):
            get_value = (line.split("GET:", 1)[1] or "").strip()
            continue
        if line.startswith("POST:"):
            post_value = (line.split("POST:", 1)[1] or "").strip()
            continue
    return {"env_lines": env_lines, "COOKIE": cookie_value, "GET": get_value, "POST": post_value}


def load_symbolic_solution_defaults(test_command_path: str) -> dict:
    return _parse_test_command_text(_read_text(test_command_path))


def format_symbolic_solution_text(solution: dict, *, defaults: dict | None = None) -> str:
    sol = solution if isinstance(solution, dict) else {}
    norm: dict[str, object] = {}
    for k, v in sol.items():
        if not isinstance(k, str):
            continue
        norm[k.strip().upper()] = v
    defaults = defaults if isinstance(defaults, dict) else {}
    env_defaults = defaults.get("env_lines") if isinstance(defaults.get("env_lines"), list) else []
    if "ENV" in norm:
        llm_env_lines = _normalize_env_lines(norm.get("ENV"), defaults=env_defaults, use_default=False)
        if len(llm_env_lines) < 3:
            env_lines = _merge_env_lines(env_defaults, llm_env_lines)
        else:
            env_lines = llm_env_lines
    else:
        env_lines = list(env_defaults)
    cookie_value = _normalize_request_field(
        norm.get("COOKIE"),
        default_value=str(defaults.get("COOKIE") or ""),
        use_default=("COOKIE" not in norm),
    )
    get_value = _normalize_request_field(
        norm.get("GET"),
        default_value=str(defaults.get("GET") or ""),
        use_default=("GET" not in norm),
    )
    post_value = _normalize_request_field(
        norm.get("POST"),
        default_value=str(defaults.get("POST") or ""),
        use_default=("POST" not in norm),
    )
    lines: list[str] = []
    if env_lines:
        lines.extend(env_lines)
        lines.append("")
    lines.append("COOKIE:" + (cookie_value or ""))
    lines.append("GET:" + (get_value or ""))
    lines.append("POST:" + (post_value or ""))
    return "\n".join(lines).rstrip() + "\n"


def write_symbolic_solution_outputs(
    solutions: list[dict],
    *,
    output_root: str,
    seq: int | None = None,
    defaults: dict | None = None,
) -> list[str]:
    if not isinstance(output_root, str) or not output_root.strip():
        return []
    if not solutions:
        return []
    solution_dir = os.path.join(output_root, "solution")
    out_paths: list[str] = []
    ensured = False
    for i, sol in enumerate(solutions or [], 1):
        if not isinstance(sol, dict):
            continue
        if not ensured:
            _ensure_dir(solution_dir)
            ensured = True
        name = f"solution_{int(seq)}_{i}.txt" if seq is not None else f"solution_{i}.txt"
        path = os.path.join(solution_dir, name)
        text = format_symbolic_solution_text(sol, defaults=defaults)
        _write_text(path, text)
        out_paths.append(path)
    return out_paths


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
            temperature=_load_symbolic_llm_temperature(),
            logger=logger,
            max_attempts=max_attempts,
            call_index=1,
            response_validator=symbolic_response_has_valid_json,
            response_validator_name='symbolic_response_has_valid_json',
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
