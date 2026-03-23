"""
Generate plain-text prompts for LLM-assisted symbolic execution.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from urllib.parse import parse_qsl, urlsplit
from typing import Any


DEFAULT_TEST_COMMAND_PATH = os.path.join("input", "测试命令.txt")
DEFAULT_URL_PATH = os.path.join("input", "url.txt")


def _read_text(path: str) -> str:
    if not isinstance(path, str) or not path:
        return ""
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            return f.read()
    except Exception:
        return ""


def _extract_test_command_fields(test_command_text: str) -> tuple[list[str], dict[str, str]]:
    env_lines: list[str] = []
    cookie_value = ""
    get_value = ""
    post_value = ""
    seed_value = ""
    if not isinstance(test_command_text, str) or not test_command_text.strip():
        return env_lines, {"COOKIE": cookie_value, "GET": get_value, "POST": post_value, "SEED": seed_value}

    for raw in (test_command_text.splitlines() or []):
        line = (raw or "").strip()
        if not line:
            continue
        if line.startswith("export "):
            rest = (line[len("export ") :] or "").strip()
            if rest:
                env_lines.append(rest)
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
        if line.startswith("seed:"):
            seed_value = (line.split("seed:", 1)[1] or "").strip()
            continue
        if "seed:" in line:
            after = line.split("seed:", 1)[1]
            seed_value = (after or "").strip()
            continue

    return env_lines, {"COOKIE": cookie_value, "GET": get_value, "POST": post_value, "SEED": seed_value}


def _split_env_lines(env_lines: list[str]) -> dict[str, str]:
    out: dict[str, str] = {}
    for line in env_lines or []:
        if not isinstance(line, str):
            continue
        s = line.strip()
        if not s or "=" not in s:
            continue
        k, v = s.split("=", 1)
        k = (k or "").strip()
        if not k:
            continue
        out[k] = (v or "").strip()
    return out


def _parse_url_query(query: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for k, v in parse_qsl(query or "", keep_blank_values=True):
        k = (k or "").strip()
        if not k:
            continue
        out[k] = (v or "").strip()
    return out


def _parse_url_input(url_text: str) -> dict[str, str]:
    url_text = (url_text or "").strip()
    if not url_text:
        return {"GET": "", "POST": "", "COOKIE": ""}
    try:
        parts = urlsplit(url_text)
    except Exception:
        return {"GET": "", "POST": "", "COOKIE": ""}
    query = _parse_url_query(parts.query)
    if not query:
        return {"GET": "", "POST": "", "COOKIE": ""}
    qs = "&".join([f"{k}={v}" for k, v in query.items()])
    return {"GET": qs, "POST": "", "COOKIE": ""}


def _normalize_key_case(obj: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for k, v in (obj or {}).items():
        if not isinstance(k, str):
            continue
        ks = k.strip().upper()
        if not ks:
            continue
        out[ks] = v
    return out


def _get_inputs_from_files(test_command_path: str, url_path: str) -> dict[str, str]:
    env_lines, base = _extract_test_command_fields(_read_text(test_command_path))
    env_map = _split_env_lines(env_lines)
    url_map = _parse_url_input(_read_text(url_path))
    out: dict[str, str] = {}
    out.update(base)
    out.update(url_map)
    for k in ("GET", "POST", "COOKIE", "SEED"):
        if not out.get(k):
            out[k] = ""
    out["ENV"] = "\n".join([f"{k}={v}" for k, v in env_map.items()])
    return out


def _load_result_set(result_set_or_path):
    if isinstance(result_set_or_path, (list, tuple)):
        return list(result_set_or_path)
    if not isinstance(result_set_or_path, str) or not result_set_or_path:
        return []
    if not os.path.exists(result_set_or_path):
        return []
    try:
        with open(result_set_or_path, "r", encoding="utf-8", errors="replace") as f:
            obj = json.load(f)
        if isinstance(obj, dict):
            return obj.get("result_set") or obj.get("result") or []
        if isinstance(obj, list):
            return obj
        return []
    except Exception:
        return []


def _load_analysis_obj(result_set_or_path):
    if not isinstance(result_set_or_path, str) or not result_set_or_path:
        return None
    if not os.path.exists(result_set_or_path):
        return None
    try:
        with open(result_set_or_path, "r", encoding="utf-8", errors="replace") as f:
            obj = json.load(f)
        return obj if isinstance(obj, dict) else None
    except Exception:
        return None


def _resolve_existing_path(path: str, fallback: str) -> str:
    if path and os.path.exists(path):
        return path
    if fallback and os.path.exists(fallback):
        return fallback
    return path or fallback


def _import_prompt_utils():
    try:
        from llm_utils.prompts.prompt_utils import map_result_set_to_source_lines
    except Exception:
        map_result_set_to_source_lines = None
    return map_result_set_to_source_lines


def _import_if_branch_utils():
    try:
        from if_branch_coverage import infer_if_directions_for_seqs
    except Exception:
        infer_if_directions_for_seqs = None
    try:
        from utils.trace_utils.trace_edges import load_trace_index_records
    except Exception:
        load_trace_index_records = None
    return infer_if_directions_for_seqs, load_trace_index_records


def _import_call_scope_utils():
    try:
        from taint_handlers.handlers.call.ast_method_call import partition_function_scope_for_call
    except Exception:
        partition_function_scope_for_call = None
    return partition_function_scope_for_call


def _loc_key(path: str, line: int) -> tuple[str, int] | None:
    if not path or line is None:
        return None
    try:
        ln = int(line)
    except Exception:
        return None
    return str(path), ln


def _strip_app_prefix(p: str) -> str:
    p = (p or "").strip()
    if p.startswith("/app/"):
        p = p[5:]
    if p.startswith("/"):
        p = p[1:]
    return p


def _parse_loc(loc: str):
    if not loc or ":" not in loc:
        return None
    p, ln_s = loc.rsplit(":", 1)
    try:
        ln = int(ln_s)
    except Exception:
        return None
    p = _strip_app_prefix(p).replace("\\", "/")
    return p, ln


def _match_loc(loc: str, path: str, line: int) -> bool:
    if not loc or not path or line is None:
        return False
    pr = _parse_loc(loc)
    if not pr:
        return False
    p, ln = pr
    try:
        ln_i = int(ln)
    except Exception:
        return False
    return p == _strip_app_prefix(path).replace("\\", "/") and ln_i == int(line)


def _merge_initial_seq_into_result_set(result_set, *, input_seq: int | None, input_path: str | None, input_line: int | None):
    if input_seq is None or not input_path or input_line is None:
        return result_set
    out = list(result_set or [])
    for it in out:
        if not isinstance(it, dict):
            continue
        if it.get("seq") == input_seq:
            return out
    out.append({"seq": int(input_seq), "path": input_path, "line": int(input_line), "loc": f"{input_path}:{int(input_line)}"})
    return out


def _build_seq_to_branch(if_dirs: list) -> dict[int, str]:
    out: dict[int, str] = {}
    for d in if_dirs or []:
        try:
            s = int(getattr(d, "if_seq"))
        except Exception:
            continue
        direction = getattr(d, "direction", None)
        direction_s = (str(direction) if direction is not None else "").strip()
        if not direction_s:
            continue
        if s not in out:
            out[s] = direction_s
    return out


def _normalize_dir_name(s: str) -> str:
    if not isinstance(s, str):
        return ""
    v = s.strip().lower()
    if v in ("t", "true", "1", "yes"):
        return "true"
    if v in ("f", "false", "0", "no"):
        return "false"
    return v


def _format_if_direction(dir_s: str) -> str:
    v = _normalize_dir_name(dir_s)
    if not v:
        return ""
    if v in ("true", "t", "yes", "1"):
        return "true"
    if v in ("false", "f", "no", "0"):
        return "false"
    return v


def _merge_dir_into_code(code: str, dir_s: str) -> str:
    d = _format_if_direction(dir_s)
    if not d:
        return code
    return f"{code}    # 当前分支方向: {d}"


def _build_loc_to_func_impl_tags(
    mapped: list[dict],
    *,
    trace_index_records: list[dict],
    trace_seq_to_index: dict[int, int],
    nodes: dict[int, dict],
    parent_of: dict[int, int],
    children_of: dict[int, list[int]],
    top_id_to_file: dict[int, str],
) -> dict[str, list[str]]:
    partition_function_scope_for_call = _import_call_scope_utils()

    mapped_locs: set[str] = set()
    for it in mapped or []:
        if not isinstance(it, dict):
            continue
        loc = (it.get("loc") or "").strip()
        if not loc:
            p = (it.get("path") or "").strip()
            ln = it.get("line")
            if p and ln is not None:
                try:
                    loc = f"{p}:{int(ln)}"
                except Exception:
                    loc = ""
        if loc:
            mapped_locs.add(loc)

    callsites: list[dict] = []
    seen_calls: set[tuple[int, int]] = set()
    for it in mapped or []:
        if not isinstance(it, dict):
            continue
        seq = it.get("seq")
        it_code = it.get("code")
        it_code_s = (it_code if isinstance(it_code, str) else "").strip()
        try:
            seq_i = int(seq) if seq is not None else None
        except Exception:
            seq_i = None
        if seq_i is None:
            continue
        rec_idx = trace_seq_to_index.get(int(seq_i))
        if rec_idx is None or rec_idx < 0 or rec_idx >= len(trace_index_records):
            continue
        rec = trace_index_records[rec_idx] or {}
        node_ids = rec.get("node_ids") or []
        call_id = None
        for nid in node_ids:
            try:
                ni = int(nid)
            except Exception:
                continue
            nt = ((nodes.get(int(ni)) or {}).get("type") or "").strip()
            if nt in ("AST_METHOD_CALL", "AST_CALL", "AST_STATIC_CALL"):
                call_id = int(ni)
                break
        if call_id is None:
            continue
        callsites.append({"call_id": call_id, "call_seq": seq_i, "code": it_code_s})

    callsites.sort(key=lambda x: int(x.get("call_seq") or 0))
    loc_to_tags: dict[str, list[str]] = {}
    seen_call_tags: set[str] = set()
    for call in callsites:
        call_id_i = call.get("call_id")
        call_seq_i = call.get("call_seq")
        if call_id_i is None or call_seq_i is None:
            continue
        key = (int(call_id_i), int(call_seq_i))
        if key in seen_calls:
            continue
        seen_calls.add(key)
        try:
            scope = partition_function_scope_for_call(int(call_id_i), int(call_seq_i), {
                "nodes": nodes,
                "children_of": children_of,
                "parent_of": parent_of,
                "top_id_to_file": top_id_to_file,
                "trace_index_records": trace_index_records,
                "trace_seq_to_index": trace_seq_to_index,
                "calls_edges_union": None,
            })
        except Exception:
            scope = None
        if not scope:
            continue
        scope_start = scope.get("scope_start_seq")
        scope_end = scope.get("scope_end_seq")
        if scope_start is None or scope_end is None:
            continue
        scope_locs = scope.get("scope") or []
        scope_loc_set = set()
        for it in scope_locs:
            if not isinstance(it, dict):
                continue
            loc = it.get("loc")
            if not loc:
                p = it.get("path")
                ln = it.get("line")
                if p and ln is not None:
                    loc = f"{p}:{ln}"
            if loc:
                scope_loc_set.add(loc)

        call_name = call.get("code")
        tag = call_name or f"call_id={call_id_i}"
        if tag in seen_call_tags:
            continue
        seen_call_tags.add(tag)
        for it in mapped or []:
            if not isinstance(it, dict):
                continue
            seq = it.get("seq")
            p = (it.get("path") or "").strip()
            ln = it.get("line")
            if not p or ln is None or seq is None:
                continue
            try:
                seq_i = int(seq)
                ln_i = int(ln)
            except Exception:
                continue
            if int(seq_i) <= int(call_seq_i):
                continue
            if int(seq_i) < int(scope_start) or int(seq_i) > int(scope_end):
                continue
            loc = f"{p}:{ln_i}"
            if loc not in scope_loc_set:
                continue
            if loc not in mapped_locs:
                continue
            lst = loc_to_tags.get(loc)
            if lst is None:
                loc_to_tags[loc] = [tag]
            else:
                if tag not in lst:
                    lst.append(tag)
    return loc_to_tags


def generate_symbolic_execution_prompt(
    result_set_or_path,
    *,
    input_seq: int | None = None,
    input_path: str | None = None,
    input_line: int | None = None,
    scope_root: str = "/app",
    trace_index_path: str = os.path.join("tmp", "trace_index.json"),
    windows_root: str = r"D:\files\witcher\app",
    base_prompt: str | None = None,
    nodes_path: str = os.path.join("input", "nodes.csv"),
    rels_path: str = os.path.join("input", "rels.csv"),
) -> str:
    map_result_set_to_source_lines = _import_prompt_utils()
    trace_index_path2 = _resolve_existing_path(
        trace_index_path,
        fallback=os.path.join(os.getcwd(), "tmp", os.path.basename(trace_index_path or "trace_index.json")),
    )
    rs = _load_result_set(result_set_or_path)
    analysis_obj = _load_analysis_obj(result_set_or_path)
    if analysis_obj is not None:
        if input_seq is None:
            try:
                input_seq = int(analysis_obj.get("input_seq"))
            except Exception:
                input_seq = None
        if not input_path:
            input_path = analysis_obj.get("path")
        if input_line is None:
            try:
                input_line = int(analysis_obj.get("line"))
            except Exception:
                input_line = None
    if (not input_path or input_line is None) and input_seq is not None and trace_index_path2 and os.path.exists(trace_index_path2):
        _infer_if_directions_for_seqs, load_trace_index_records = _import_if_branch_utils()
        try:
            trace_index_records0 = load_trace_index_records(trace_index_path2)
        except Exception:
            trace_index_records0 = []
        try:
            input_seq_i = int(input_seq)
        except Exception:
            input_seq_i = None
        if input_seq_i is not None:
            for r in trace_index_records0 or []:
                if not isinstance(r, dict):
                    continue
                hit = False
                for s in r.get("seqs") or []:
                    try:
                        if int(s) == input_seq_i:
                            hit = True
                            break
                    except Exception:
                        continue
                if not hit:
                    continue
                if not input_path:
                    input_path = r.get("path")
                if input_line is None:
                    try:
                        input_line = int(r.get("line"))
                    except Exception:
                        input_line = None
                break
    rs = _merge_initial_seq_into_result_set(rs, input_seq=input_seq, input_path=input_path, input_line=input_line)
    mapped = map_result_set_to_source_lines(
        scope_root,
        rs,
        trace_index_path=trace_index_path2,
        windows_root=windows_root,
    )

    infer_if_directions_for_seqs, load_trace_index_records = _import_if_branch_utils()
    trace_index_records = load_trace_index_records(trace_index_path2) if load_trace_index_records else []
    trace_seq_to_index = {}
    for rec in trace_index_records or []:
        idx = rec.get("index")
        for s in rec.get("seqs") or []:
            try:
                si = int(s)
            except Exception:
                continue
            if si not in trace_seq_to_index:
                trace_seq_to_index[si] = int(idx) if idx is not None else 0

    nodes = {}
    parent_of = {}
    children_of = {}
    top_id_to_file = {}
    try:
        from utils.cpg_utils.graph_mapping import load_nodes, load_ast_edges
        nodes, top_id_to_file = load_nodes(nodes_path)
        parent_of, children_of = load_ast_edges(rels_path)
    except Exception:
        nodes = {}
        parent_of = {}
        children_of = {}
        top_id_to_file = {}

    loc_to_tags = _build_loc_to_func_impl_tags(
        mapped,
        trace_index_records=trace_index_records,
        trace_seq_to_index=trace_seq_to_index,
        nodes=nodes,
        parent_of=parent_of,
        children_of=children_of,
        top_id_to_file=top_id_to_file,
    )

    env_block = ""
    cookie_block = ""
    get_block = ""
    post_block = ""
    seed_block = ""
    if base_prompt is None:
        test_command_text = _read_text(DEFAULT_TEST_COMMAND_PATH)
        env_lines, base_inputs = _extract_test_command_fields(test_command_text)
        env_block = "\n".join(env_lines)
        cookie_block = base_inputs.get("COOKIE") or ""
        get_block = base_inputs.get("GET") or ""
        post_block = base_inputs.get("POST") or ""
        seed_block = base_inputs.get("SEED") or ""
    else:
        base_prompt = (base_prompt or "").strip()
        if base_prompt:
            return base_prompt

    if_dirs = infer_if_directions_for_seqs(list({int(x.get("seq")) for x in (mapped or []) if isinstance(x, dict) and x.get("seq") is not None})) if infer_if_directions_for_seqs else []
    seq_to_dir = _build_seq_to_branch(if_dirs or [])

    lines = []
    if input_seq is not None:
        seq_display = f"{int(input_seq)}"
    else:
        seq_display = "?"
    lines.append("你是一个专业的代码分析助手，任务是帮助Web Fuzzer发现SQL注入漏洞。")
    lines.append("")
    lines.append(
        "将"+ seq_display
        + "行的SQL语句的查询表达式符号化，使用外部输入的表达式来表示，形成符号执行中的约束。然后求解这些约束表达式，请修改环境变量和输入，给我一个能够破坏该SQL语句语义结构的外部输入（环境变量、COOKIE、POST、GET、SESSION）。"
    )
    lines.append("注意：目标不是利用漏洞，而是构造输入让数据库产生 SQL syntax error，以便触发 fuzz 工具的错误检测机制。")
    lines.append("优先制造语法错误，优先使用短payload。")

    lines.append("本次执行的环境变量是：")
    if env_block:
        lines.append(env_block)
    lines.append("")
    lines.append("本次执行的输入是：")
    lines.append("COOKIE:" + cookie_block)
    lines.append("GET:" + get_block)
    lines.append("POST:" + post_block)
    lines.append("SESSION:")
    if seed_block and (not cookie_block and not get_block and not post_block):
        lines.append("SEED:")
        lines.append(seed_block)
    lines.append("")
    lines.append("代码上下文（每行：seq | path:line | code）：")
    for it in mapped or []:
        if not isinstance(it, dict):
            continue
        seq = it.get("seq")
        seq_i = None
        try:
            seq_i = int(seq) if seq is not None else None
        except Exception:
            seq_i = None
        path = (it.get("path") or "").strip()
        ln = it.get("line")
        try:
            ln_i = int(ln)
        except Exception:
            ln_i = ln
        loc = f"{path}:{ln_i}"
        code = it.get("code")
        code_s = (code if isinstance(code, str) else "").rstrip("\n")
        if not code_s.strip():
            code_s = "<SOURCE_NOT_FOUND>"
        if seq_i is not None:
            if seq_to_dir.get(seq_i):
                code_s = _merge_dir_into_code(code_s, seq_to_dir.get(seq_i) or "")
        tags = loc_to_tags.get(loc) or []
        if tags:
            code_s = f"{code_s}    # {', '.join(tags)}"
        lines.append(f"{seq} | {loc} | {code_s}")

    lines.append("")
    lines.append("允许使用通用工程先验（如数据库 NOT NULL、INSERT 失败条件、协议规范）来推断哪些修改“在现实系统中高度可能”影响SQL语句的执行结果，但不允许假设具体 schema、字段长度或隐藏代码")
    lines.append("如果有多个方案，都可以实现注入，仅输出其中一个。如果你不能确定该方案是否有效，可以输出多个方案。")
    lines.append("如果决定该SQL语句方向的变量不是来自上述五种输入（环境变量、COOKIE、POST、GET、SESSION），则认为无法修改。")
    lines.append("如果你需要查询数据库获取额外信息时，请直接输出查询语句，不输出解决方案。")
    lines.append("如果你认为，仅靠目前提供的信息和你的先验知识，不足以注入该SQL语句，或者该SQL语句的条件表达式无法符号化，请输出空JSON。")
    lines.append("请输出一个JSON文件，示例：")
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
    lines.append("    },")
    lines.append("    {")
    lines.append('      "SESSION": "is_admin|b:1;user_id|i:1;"')
    lines.append("    },")
    lines.append("    {")
    lines.append('      "DB_QUERY": "SELECT user_id FROM users WHERE username = \\"admin\\" LIMIT 1;"')
    lines.append("    }")
    lines.append("  ]")
    lines.append("}")
    return "\n".join(lines).rstrip() + "\n"


def _load_prompt_text(path: str) -> str:
    if not isinstance(path, str) or not path:
        return ""
    if not os.path.exists(path):
        return ""
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            return f.read()
    except Exception:
        return ""


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("result_set", nargs="?", default="")
    ap.add_argument("--prompt", default="")
    ap.add_argument("--input-seq", type=int, default=None)
    ap.add_argument("--input-path", type=str, default=None)
    ap.add_argument("--input-line", type=int, default=None)
    ap.add_argument("--scope-root", type=str, default="/app")
    ap.add_argument("--trace-index", type=str, default=os.path.join("tmp", "trace_index.json"))
    ap.add_argument("--windows-root", type=str, default=r"D:\files\witcher\app")
    ap.add_argument("--nodes", type=str, default=os.path.join("input", "nodes.csv"))
    ap.add_argument("--rels", type=str, default=os.path.join("input", "rels.csv"))
    args = ap.parse_args()

    base_prompt = _load_prompt_text(args.prompt) if args.prompt else None
    txt = generate_symbolic_execution_prompt(
        args.result_set,
        input_seq=args.input_seq,
        input_path=args.input_path,
        input_line=args.input_line,
        scope_root=args.scope_root,
        trace_index_path=args.trace_index,
        windows_root=args.windows_root,
        base_prompt=base_prompt,
        nodes_path=args.nodes,
        rels_path=args.rels,
    )
    sys.stdout.write(txt or "")


if __name__ == "__main__":
    main()
