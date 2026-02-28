"""
Run LLM-assisted symbolic-execution prompts and normalize the JSON solutions output.
"""

import asyncio
import json
import os
import re
from urllib.parse import parse_qsl, urlsplit, urlunsplit

from common.app_config import load_app_config
from llm_utils import get_default_client
from llm_utils.session_validator import validate_and_fix_php_session_text
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


def _extract_db_query_from_obj(obj) -> str:
    keys = ("DB_QUERY", "db_query", "DBQUERY", "QUERY", "SQL")
    if isinstance(obj, dict):
        for k in keys:
            if k in obj:
                v = obj.get(k)
                if isinstance(v, str) and v.strip():
                    return v.strip()
        sols = obj.get("solutions")
        if isinstance(sols, list):
            for s in sols:
                if isinstance(s, dict):
                    for k in keys:
                        v = s.get(k)
                        if isinstance(v, str) and v.strip():
                            return v.strip()
    if isinstance(obj, list):
        for s in obj:
            if isinstance(s, dict):
                for k in keys:
                    v = s.get(k)
                    if isinstance(v, str) and v.strip():
                        return v.strip()
    return ""


def _extract_db_query_from_text(text: str) -> str:
    if not isinstance(text, str) or not text.strip():
        return ""
    try:
        obj = json.loads(text)
    except Exception:
        js = _extract_json_text(text)
        if not js:
            return ""
        try:
            obj = json.loads(js)
        except Exception:
            return ""
    return _extract_db_query_from_obj(obj)


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


def _parse_url_text(text: str) -> dict:
    env_lines: list[str] = []
    cookie_value = ""
    get_value = ""
    post_value = ""
    url_value = ""
    if not isinstance(text, str) or not text.strip():
        return {"env_lines": env_lines, "COOKIE": cookie_value, "GET": get_value, "POST": post_value, "URL": url_value, "MODE": "URL"}
    for raw in text.splitlines() or []:
        line = (raw or "").strip()
        if not line:
            continue
        m_cookie = re.search(r"\bCookie\s*:\s*(.*)$", line, flags=re.IGNORECASE)
        if m_cookie and not cookie_value:
            cookie_value = (m_cookie.group(1) or "").strip()
            continue
        if line.startswith("COOKIE:") and not cookie_value:
            cookie_value = (line.split("COOKIE:", 1)[1] or "").strip()
            continue
        if line.startswith("GET:") and not get_value:
            get_value = (line.split("GET:", 1)[1] or "").strip()
            continue
        if line.startswith("POST:") and not post_value:
            post_value = (line.split("POST:", 1)[1] or "").strip()
            continue
        if not url_value:
            m_url = re.search(r"(https?://[^\s\"']+)", line)
            if m_url:
                url_value = (m_url.group(1) or "").strip()
                continue
    if not url_value:
        m_url = re.search(r"(https?://[^\s\"']+)", text or "")
        if m_url:
            url_value = (m_url.group(1) or "").strip()
    if url_value and not get_value:
        try:
            qs = urlsplit(url_value).query or ""
            if qs:
                pairs = parse_qsl(qs, keep_blank_values=True)
                get_value = _pairs_to_query([(k, v) for k, v in pairs])
        except Exception:
            get_value = get_value
    return {"env_lines": env_lines, "COOKIE": cookie_value, "GET": get_value, "POST": post_value, "URL": url_value, "MODE": "URL"}


def load_symbolic_solution_defaults(test_command_path: str) -> dict:
    if isinstance(test_command_path, str) and os.path.exists(test_command_path):
        return _parse_test_command_text(_read_text(test_command_path))
    url_path = ""
    if isinstance(test_command_path, str) and test_command_path:
        base_dir = os.path.dirname(test_command_path)
        url_path = os.path.join(base_dir, "url.txt")
        if not os.path.exists(url_path):
            url_path = ""
    if not url_path:
        url_path = os.path.join(os.getcwd(), "input", "url.txt")
    if url_path and os.path.exists(url_path):
        return _parse_url_text(_read_text(url_path))
    return _parse_test_command_text("")


def format_symbolic_solution_text(solution: dict, *, defaults: dict | None = None, seq: int | None = None) -> str:
    sol = solution if isinstance(solution, dict) else {}
    norm: dict[str, object] = {}
    for k, v in sol.items():
        if not isinstance(k, str):
            continue
        norm[k.strip().upper()] = v
    defaults = defaults if isinstance(defaults, dict) else {}
    env_defaults = defaults.get("env_lines") if isinstance(defaults.get("env_lines"), list) else []
    hidden_keys = {"OPCODE_TRACE", "SCRIPT_FILENAME", "LOGIN_COOKIE", "SCRIPT_NAME"}
    def _shell_single_quote(v: str) -> str:
        s = v if isinstance(v, str) else ""
        return "'" + s.replace("'", "'\\''") + "'"

    def _cookie_parts_from_text(text: str) -> list[tuple[str, str | None]]:
        out: list[tuple[str, str | None]] = []
        s = (text or "").strip()
        if not s:
            return out
        for raw in re.split(r"[;&]", s):
            part = (raw or "").strip()
            if not part:
                continue
            if "=" in part:
                k, v = part.split("=", 1)
                k2 = (k or "").strip()
                v2 = (v or "").strip()
                if k2:
                    out.append((k2, v2))
                continue
            out.append((part, None))
        return out

    def _cookie_parts_from_obj(obj) -> list[tuple[str, str | None]]:
        if obj is None:
            return []
        if isinstance(obj, dict):
            out: list[tuple[str, str | None]] = []
            for k, v in obj.items():
                ks = (k or "").strip() if isinstance(k, str) else ""
                if not ks:
                    continue
                if v is None:
                    out.append((ks, None))
                    continue
                vs = (v if isinstance(v, str) else _stringify_value(v)).strip()
                out.append((ks, None if vs == "" else vs))
            return out
        if isinstance(obj, (list, tuple)):
            out: list[tuple[str, str | None]] = []
            for it in obj:
                if isinstance(it, dict):
                    out.extend(_cookie_parts_from_obj(it))
                    continue
                if isinstance(it, (list, tuple)) and len(it) >= 2:
                    k = it[0]
                    v = it[1]
                    ks = (k or "").strip() if isinstance(k, str) else ""
                    if not ks:
                        continue
                    if v is None:
                        out.append((ks, None))
                        continue
                    vs = (v if isinstance(v, str) else _stringify_value(v)).strip()
                    out.append((ks, None if vs == "" else vs))
                    continue
                if isinstance(it, str):
                    out.extend(_cookie_parts_from_text(it))
                    continue
            return out
        if isinstance(obj, str):
            return _cookie_parts_from_text(obj)
        return _cookie_parts_from_text(_stringify_value(obj))

    def _cookie_parts_to_text(parts: list[tuple[str, str | None]]) -> str:
        buf: list[str] = []
        for k, v in parts or []:
            ks = (k or "").strip()
            if not ks:
                continue
            if v is None:
                buf.append(ks)
            else:
                buf.append(f"{ks}={v}")
        return "&".join(buf).strip("&")

    def _normalize_cookie_field(field_obj, *, default_value: str, use_default: bool) -> str:
        if use_default:
            return _cookie_parts_to_text(_cookie_parts_from_text(default_value))
        return _cookie_parts_to_text(_cookie_parts_from_obj(field_obj))

    def _inject_phpsessid(cookie_value: str, session_id: str) -> str:
        parts = _cookie_parts_from_text(cookie_value or "")
        out: list[tuple[str, str | None]] = [("PHPSESSID", session_id)]
        for k, v in parts:
            if (k or "").strip().upper() == "PHPSESSID":
                continue
            out.append((k, v))
        return _cookie_parts_to_text(out)

    def _stringify_session(v: object) -> str:
        if v is None:
            return ""
        if isinstance(v, str):
            return v
        try:
            return json.dumps(v, ensure_ascii=False)
        except Exception:
            return str(v)

    def _parse_env_pairs(lines: list[str]) -> dict[str, str]:
        out: dict[str, str] = {}
        for raw in lines or []:
            s = (raw or "").strip()
            if not s:
                continue
            k = (s.split("=", 1)[0] or "").strip().upper()
            v = (s.split("=", 1)[1] if "=" in s else "")
            if k:
                out[k] = v
        return out
    if "ENV" in norm:
        llm_env_lines = _normalize_env_lines(norm.get("ENV"), defaults=env_defaults, use_default=False)
        base_lines = _merge_env_lines(env_defaults, llm_env_lines)
        env_map = _parse_env_pairs(base_lines)
        def_map = _parse_env_pairs(env_defaults)
        for hk in hidden_keys:
            if hk in def_map and hk not in env_map:
                base_lines.append(f"{hk}={def_map.get(hk) or ''}")
        env_lines = base_lines
    else:
        env_map = _parse_env_pairs(env_defaults)
        base_lines = list(env_defaults)
        for hk in hidden_keys:
            if hk in env_map and hk not in { (x.split('=',1)[0] or '').strip().upper() for x in base_lines }:
                base_lines.append(f"{hk}={env_map.get(hk) or ''}")
        env_lines = base_lines
    cookie_value = _normalize_cookie_field(
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
    sess_content = ""
    if "SESSION" in norm and seq is not None:
        sess_content = _stringify_session(norm.get("SESSION")).strip()
        if sess_content:
            session_id = f"sym-{int(seq)}"
            cookie_value = _inject_phpsessid(cookie_value or "", session_id)
    is_url_mode = bool((defaults or {}).get("MODE") == "URL" or (defaults or {}).get("URL"))
    lines: list[str] = []
    if is_url_mode:
        if "ENV" in norm and env_lines:
            lines.extend(env_lines)
        url_value = str((defaults or {}).get("URL") or "").strip()
        url_out = url_value
        if url_value:
            try:
                u = urlsplit(url_value)
                url_out = urlunsplit((u.scheme, u.netloc, u.path, get_value or "", u.fragment))
            except Exception:
                url_out = url_value
        if sess_content and seq is not None:
            sess_path = f"/tmp/php_sessions/sess_sym-{int(seq)}"
            lines.append(f"echo -n {_shell_single_quote(sess_content)} > {sess_path}")
            lines.append(f"chown www-data {sess_path}")
        cookie_parts = _cookie_parts_from_text(cookie_value or "")
        post_parts = _split_query_pairs(post_value or "")
        cmd_parts = ["curl"]
        for k, v in cookie_parts:
            ks = (k or "").strip()
            if not ks:
                continue
            if v is None:
                cmd_parts.extend(["-b", _shell_single_quote(ks)])
            else:
                cmd_parts.extend(["-b", _shell_single_quote(f"{ks}={v}")])
        for k, v in post_parts:
            ks = (k or "").strip()
            if not ks:
                continue
            cmd_parts.extend(["-d", _shell_single_quote(f"{ks}={v}")])
        if url_out:
            cmd_parts.append(_shell_single_quote(url_out))
        lines.append(" ".join(cmd_parts))
        return "\n".join(lines).rstrip() + "\n"
    if env_lines:
        lines.extend(env_lines)
        lines.append("")
    seed_cmd = (
        "printf '%s\\0%s\\0%s' "
        + _shell_single_quote(cookie_value or "")
        + " "
        + _shell_single_quote(get_value or "")
        + " "
        + _shell_single_quote(post_value or "")
        + " > seed"
    )
    lines.append(seed_cmd)
    if sess_content and seq is not None:
        sess_path = f"/tmp/php_sessions/sess_sym-{int(seq)}"
        lines.append(f"echo -n {_shell_single_quote(sess_content)} > {sess_path}")
        lines.append(f"chown www-data {sess_path}")
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
        text = format_symbolic_solution_text(sol, defaults=defaults, seq=seq)
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
    db_query = _extract_db_query_from_text(text)
    session_ok = True
    fixed_any = False
    for sol in solutions or []:
        if not isinstance(sol, dict):
            continue
        if db_query and not sol.get("DB_QUERY"):
            sol["DB_QUERY"] = db_query
        sess = sol.get("SESSION")
        if sess is None:
            continue
        sess_s = (sess if isinstance(sess, str) else str(sess)).strip()
        if not sess_s:
            continue
        vr = validate_and_fix_php_session_text(sess_s)
        if not vr.ok:
            session_ok = False
            continue
        if vr.changed:
            fixed_any = True
        sol["SESSION"] = vr.fixed_text
    try:
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump({"solutions": solutions, "session_ok": session_ok, "session_fixed": fixed_any}, f, ensure_ascii=False, indent=2)
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
    resp_obj = parse_symbolic_response(response_text)
    try:
        if os.path.exists(json_path):
            with open(json_path, "r", encoding="utf-8", errors="replace") as f:
                obj = json.load(f)
            if isinstance(obj, dict) and isinstance(obj.get("solutions"), list):
                resp_obj = obj.get("solutions") or []
    except Exception:
        resp_obj = resp_obj
    return {
        "prompt_path": prompt_path,
        "response_path": raw_path,
        "response_json_path": json_path,
        "response_obj": resp_obj,
        "llm_offline": False,
    }
