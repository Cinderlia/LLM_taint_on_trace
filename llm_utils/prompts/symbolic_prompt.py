"""
Generate plain-text prompts for LLM-assisted symbolic execution.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Any


DEFAULT_TEST_COMMAND_PATH = os.path.join("input", "测试命令.txt")


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


def _import_prompt_utils():
    try:
        from llm_utils.prompts.prompt_utils import map_result_set_to_source_lines
        return map_result_set_to_source_lines
    except Exception:
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        if root not in sys.path:
            sys.path.insert(0, root)
        from llm_utils.prompts.prompt_utils import map_result_set_to_source_lines
        return map_result_set_to_source_lines


def _import_if_branch_utils():
    try:
        from llm_utils.branch.if_branch import infer_if_directions_for_seqs, load_trace_index_records
        return infer_if_directions_for_seqs, load_trace_index_records
    except Exception:
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        if root not in sys.path:
            sys.path.insert(0, root)
        from llm_utils.branch.if_branch import infer_if_directions_for_seqs, load_trace_index_records
        return infer_if_directions_for_seqs, load_trace_index_records


def _import_switch_branch_utils():
    try:
        from llm_utils.branch.switch_branch import (
            build_seq_to_case_label,
            build_switch_case_result_set_for_seq,
            infer_switch_choices_for_seqs,
            insert_mapped_items_after_seq,
        )
        return infer_switch_choices_for_seqs, build_seq_to_case_label, build_switch_case_result_set_for_seq, insert_mapped_items_after_seq
    except Exception:
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        if root not in sys.path:
            sys.path.insert(0, root)
        from llm_utils.branch.switch_branch import (
            build_seq_to_case_label,
            build_switch_case_result_set_for_seq,
            infer_switch_choices_for_seqs,
            insert_mapped_items_after_seq,
        )
        return infer_switch_choices_for_seqs, build_seq_to_case_label, build_switch_case_result_set_for_seq, insert_mapped_items_after_seq


def _import_graph_mapping():
    try:
        from cpg_utils.graph_mapping import load_ast_edges, load_nodes
        return load_nodes, load_ast_edges
    except Exception:
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        if root not in sys.path:
            sys.path.insert(0, root)
        from cpg_utils.graph_mapping import load_ast_edges, load_nodes
        return load_nodes, load_ast_edges


def _import_call_scope_utils():
    try:
        from taint_handlers.handlers.call.ast_method_call import partition_function_scope_for_call
        return partition_function_scope_for_call
    except Exception:
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        if root not in sys.path:
            sys.path.insert(0, root)
        from taint_handlers.handlers.call.ast_method_call import partition_function_scope_for_call
        return partition_function_scope_for_call


def _load_result_set(result_set_or_path):
    if isinstance(result_set_or_path, str) and os.path.exists(result_set_or_path):
        with open(result_set_or_path, "r", encoding="utf-8", errors="replace") as f:
            obj = json.load(f)
        if isinstance(obj, dict):
            return obj.get("result_set") or []
        return []
    return result_set_or_path or []

def _load_analysis_obj(result_set_or_path) -> dict | None:
    if isinstance(result_set_or_path, str) and os.path.exists(result_set_or_path):
        with open(result_set_or_path, "r", encoding="utf-8", errors="replace") as f:
            obj = json.load(f)
        return obj if isinstance(obj, dict) else None
    return result_set_or_path if isinstance(result_set_or_path, dict) else None


def _merge_initial_seq_into_result_set(
    result_set,
    *,
    input_seq: int | None,
    input_path: str | None,
    input_line: int | None,
) -> list:
    if not result_set:
        result_set = []
    if input_seq is None:
        return list(result_set)
    try:
        seq_i = int(input_seq)
    except Exception:
        return list(result_set)

    for it in result_set or []:
        if not isinstance(it, dict):
            continue
        s = it.get("seq")
        try:
            if int(s) == seq_i:
                return list(result_set)
        except Exception:
            continue

    added = {"seq": seq_i}
    p = (str(input_path).strip() if isinstance(input_path, str) else "").strip()
    if p and input_line is not None:
        try:
            ln_i = int(input_line)
        except Exception:
            ln_i = None
        if ln_i is not None:
            added["path"] = p
            added["line"] = ln_i
            added["loc"] = f"{p}:{ln_i}"

    out = list(result_set) + [added]
    keyed = []
    for idx, it in enumerate(out):
        if isinstance(it, dict):
            s = it.get("seq")
            try:
                si = int(s) if s is not None else None
            except Exception:
                si = None
            if si is not None:
                keyed.append((0, si, idx, it))
                continue
        keyed.append((1, 0, idx, it))
    keyed.sort(key=lambda x: (x[0], x[1], x[2]))
    return [it for _, _, _, it in keyed]


def _resolve_existing_path(path: str, *, fallback: str | None = None) -> str:
    if path and os.path.exists(path):
        return path
    if fallback and os.path.exists(fallback):
        return fallback
    return path


def _extract_int_seqs(mapped_items: list[dict]) -> list[int]:
    out: set[int] = set()
    for it in mapped_items or []:
        if not isinstance(it, dict):
            continue
        s = it.get("seq")
        try:
            si = int(s)
        except Exception:
            continue
        out.add(int(si))
    return sorted(out)


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


def _build_trace_seq_to_index(trace_index_records: list[dict]) -> dict[int, int]:
    out: dict[int, int] = {}
    for r in trace_index_records or []:
        if not isinstance(r, dict):
            continue
        idx = r.get("index")
        try:
            idx_i = int(idx) if idx is not None else None
        except Exception:
            idx_i = None
        if idx_i is None:
            continue
        for s in r.get("seqs") or []:
            try:
                si = int(s)
            except Exception:
                continue
            if si not in out:
                out[si] = int(idx_i)
    return out


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
        rec = trace_index_records[int(rec_idx)] or {}
        for nid in rec.get("node_ids") or []:
            try:
                nid_i = int(nid)
            except Exception:
                continue
            nt = ((nodes.get(nid_i) or {}).get("type") or "").strip()
            if nt not in ("AST_METHOD_CALL", "AST_CALL"):
                continue
            key = (int(nid_i), int(seq_i))
            if key in seen_calls:
                continue
            seen_calls.add(key)
            call_name = ((nodes.get(nid_i) or {}).get("name") or (nodes.get(nid_i) or {}).get("code") or "").strip()
            if it_code_s:
                call_name = it_code_s
            callsites.append({"call_id": int(nid_i), "call_seq": int(seq_i), "call_name": call_name})

    if not callsites:
        return {}

    scope_ctx = {
        "nodes": nodes,
        "parent_of": parent_of,
        "children_of": children_of,
        "top_id_to_file": top_id_to_file,
        "trace_index_records": trace_index_records,
        "trace_seq_to_index": trace_seq_to_index,
    }

    loc_to_tags: dict[str, list[str]] = {}
    for cs in callsites:
        call_id = cs.get("call_id")
        call_seq = cs.get("call_seq")
        call_name = (cs.get("call_name") or "").strip()
        if call_id is None or call_seq is None:
            continue
        try:
            call_id_i = int(call_id)
            call_seq_i = int(call_seq)
        except Exception:
            continue
        if not call_name:
            for it in mapped or []:
                if not isinstance(it, dict):
                    continue
                s2 = it.get("seq")
                try:
                    s2i = int(s2) if s2 is not None else None
                except Exception:
                    s2i = None
                if s2i is None or int(s2i) != int(call_seq_i):
                    continue
                code2 = it.get("code")
                code2s = (code2 if isinstance(code2, str) else "").strip()
                if code2s:
                    call_name = code2s
                break
        scope_info = partition_function_scope_for_call(int(call_id_i), int(call_seq_i), scope_ctx)
        if not isinstance(scope_info, dict):
            continue
        scope_rows = scope_info.get("scope") or []
        scope_loc_set: set[str] = set()
        for row in scope_rows:
            if not isinstance(row, dict):
                continue
            rp = (row.get("path") or "").strip()
            rl = row.get("line")
            if not rp or rl is None:
                continue
            try:
                rl_i = int(rl)
            except Exception:
                continue
            scope_loc_set.add(f"{rp}:{rl_i}")
        if not scope_loc_set:
            continue
        try:
            scope_start = int(scope_info.get("scope_start_seq"))
            scope_end = int(scope_info.get("scope_end_seq"))
        except Exception:
            continue

        tag = call_name or f"call_id={call_id_i}"
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
    infer_switch_choices_for_seqs, build_seq_to_case_label, build_switch_case_result_set_for_seq, insert_mapped_items_after_seq = _import_switch_branch_utils()
    load_nodes, load_ast_edges = _import_graph_mapping()
    nodes_path2 = _resolve_existing_path(nodes_path)
    rels_path2 = _resolve_existing_path(rels_path)
    if_seqs = _extract_int_seqs(mapped or [])
    trace_index_records: list[dict] = []
    nodes: dict[int, dict] = {}
    children_of: dict[int, list[int]] = {}
    have_graph = bool(
        if_seqs
        and trace_index_path2
        and os.path.exists(trace_index_path2)
        and os.path.exists(nodes_path2)
        and os.path.exists(rels_path2)
    )
    if have_graph:
        try:
            trace_index_records = load_trace_index_records(trace_index_path2)
            nodes, top_id_to_file = load_nodes(nodes_path2)
            parent_of, children_of = load_ast_edges(rels_path2)
            if_dirs = infer_if_directions_for_seqs(
                if_seqs,
                trace_index_records=trace_index_records,
                nodes=nodes,
                children_of=children_of,
            )
            switch_choices = infer_switch_choices_for_seqs(
                if_seqs,
                trace_index_records=trace_index_records,
                nodes=nodes,
                children_of=children_of,
            )
        except Exception:
            if_dirs = []
            switch_choices = []
    else:
        if_dirs = []
        switch_choices = []
    seq_to_branch = _build_seq_to_branch(if_dirs)
    seq_to_switch_case = build_seq_to_case_label(switch_choices)
    loc_to_impl_tags: dict[str, list[str]] = {}
    if have_graph and trace_index_records and nodes:
        try:
            trace_seq_to_index = _build_trace_seq_to_index(trace_index_records)
            loc_to_impl_tags = _build_loc_to_func_impl_tags(
                mapped or [],
                trace_index_records=trace_index_records,
                trace_seq_to_index=trace_seq_to_index,
                nodes=nodes,
                parent_of=parent_of if isinstance(parent_of, dict) else {},
                children_of=children_of if isinstance(children_of, dict) else {},
                top_id_to_file=top_id_to_file if isinstance(top_id_to_file, dict) else {},
            )
        except Exception:
            loc_to_impl_tags = {}

    input_seq_i = None
    try:
        input_seq_i = int(input_seq) if input_seq is not None else None
    except Exception:
        input_seq_i = None
    if have_graph and input_seq_i is not None:
        case_rs = build_switch_case_result_set_for_seq(
            int(input_seq_i),
            trace_index_records=trace_index_records,
            nodes=nodes,
            children_of=children_of,
        )
        if case_rs:
            mapped_cases = map_result_set_to_source_lines(
                scope_root,
                case_rs,
                trace_index_path=trace_index_path2,
                windows_root=windows_root,
            )
            mapped = insert_mapped_items_after_seq(mapped or [], after_seq=int(input_seq_i), insert_items=mapped_cases or [])

    test_command_path = _resolve_existing_path(
        os.path.join(os.getcwd(), DEFAULT_TEST_COMMAND_PATH),
        fallback=os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), DEFAULT_TEST_COMMAND_PATH),
    )
    test_command_text = _read_text(test_command_path)
    env_lines, req_fields = _extract_test_command_fields(test_command_text)
    env_block = "\n".join(env_lines).strip()
    cookie_block = ((req_fields.get("COOKIE") or "").strip() if isinstance(req_fields, dict) else "")
    get_block = ((req_fields.get("GET") or "").strip() if isinstance(req_fields, dict) else "")
    post_block = ((req_fields.get("POST") or "").strip() if isinstance(req_fields, dict) else "")
    seed_block = ((req_fields.get("SEED") or "").strip() if isinstance(req_fields, dict) else "")

    seq_display = ""
    if input_seq_i is not None:
        seq_display = str(int(input_seq_i))
    else:
        seq_display = "?"

    lines: list[str] = []
    lines.append(
        "请你根据代码上下文，严格按照符号执行的一般流程，将"
        + seq_display
        + "行的if语句和它之前所有相关的if语句的条件表达式符号化，使用外部输入的表达式来表示，形成符号执行中的约束。然后求解这些约束表达式，请修改环境变量和输入，给我一个能够让代码走向if语句另一个方向的外部输入。"
    )
    lines.append("")
    lines.append("本次执行的环境变量是：")
    if env_block:
        lines.append(env_block)
    lines.append("")
    lines.append("本次执行的输入是：")
    lines.append("COOKIE:" + cookie_block)
    lines.append("GET:" + get_block)
    lines.append("POST:" + post_block)
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
        seq_s = str(seq) if seq is not None else "?"
        branch_tag = ""
        if seq_i is not None:
            branch_tag = (seq_to_branch.get(int(seq_i)) or "").strip()
        if branch_tag and code_s.lstrip().startswith("if"):
            code_s = f"[{branch_tag}] {code_s}"
        lines.append(f"{seq_s} | {loc} | {code_s}")
    lines.append("")
    lines.append("只输出JSON，不要输出任何解释性文字或Markdown。")
    lines.append("请根据需求修改PHP请求的环境变量、POST、COOKIE或GET参数。可以修改一个或多个部分，但请直接返回修改之后的完整字段，不仅仅是你想修改的部分，不需要修改的部分请尽可能保持原样。")
    lines.append("仅基于给出的代码和 if 语句进行符号化， 不允许引入任何未在代码中出现的条件、比较、隐含判断。")
    lines.append("允许使用通用工程先验（如数据库 NOT NULL、INSERT 失败条件、协议规范）来推断哪些修改“在现实系统中高度可能”影响分支结果，但不允许假设具体 schema、字段长度或隐藏代码")
    lines.append("如果有多个方案，都可以实现反转，仅输出其中一个。如果你不能确定该方案是否有效，可以输出多个方案。")
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
    lines.append("    }")
    lines.append("  ]")
    lines.append("}")
    return "\n".join(lines).rstrip() + "\n"


def write_symbolic_execution_prompt_from_analysis(
    analysis_output_path: str,
    *,
    out_path: str | None = None,
    scope_root: str = "/app",
    trace_index_path: str = "trace_index.json",
    windows_root: str = r"D:\files\witcher\app",
    base_prompt: str | None = None,
    nodes_path: str = "nodes.csv",
    rels_path: str = "rels.csv",
) -> str:
    prompt = generate_symbolic_execution_prompt(
        analysis_output_path,
        scope_root=scope_root,
        trace_index_path=trace_index_path,
        windows_root=windows_root,
        base_prompt=base_prompt,
        nodes_path=nodes_path,
        rels_path=rels_path,
    )
    if not out_path:
        out_dir = os.path.dirname(os.path.abspath(analysis_output_path))
        try:
            with open(analysis_output_path, "r", encoding="utf-8", errors="replace") as f:
                obj: Any = json.load(f)
        except Exception:
            obj = {}
        seq = obj.get("input_seq") if isinstance(obj, dict) else None
        name = f"symbolic_prompt_{seq}.txt" if seq is not None else "symbolic_prompt.txt"
        out_path = os.path.join(out_dir, name)
    os.makedirs(os.path.dirname(os.path.abspath(out_path)), exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(prompt)
    return out_path


def _build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser()
    p.add_argument("analysis_output", help="analyze_if_line.py 输出的 JSON 文件路径，或直接输入 seq（例如 52564）")
    p.add_argument("--out", dest="out_path", default="", help="输出 prompt 文本文件路径")
    p.add_argument("--scope-root", dest="scope_root", default="/app")
    p.add_argument("--trace-index", dest="trace_index_path", default=os.path.join("tmp", "trace_index.json"))
    p.add_argument("--windows-root", dest="windows_root", default=r"D:\files\witcher\app")
    p.add_argument("--base-prompt", dest="base_prompt", default="")
    p.add_argument("--nodes", dest="nodes_path", default=os.path.join("input", "nodes.csv"))
    p.add_argument("--rels", dest="rels_path", default=os.path.join("input", "rels.csv"))
    return p


def main(argv=None) -> int:
    args = _build_arg_parser().parse_args(argv)
    analysis_output_path = args.analysis_output
    if isinstance(analysis_output_path, str) and analysis_output_path.isdigit() and not os.path.exists(analysis_output_path):
        analysis_output_path = os.path.join(
            os.getcwd(),
            "test",
            f"seq_{analysis_output_path}",
            f"analysis_output_{analysis_output_path}.json",
        )
    out = write_symbolic_execution_prompt_from_analysis(
        analysis_output_path,
        out_path=(args.out_path or None),
        scope_root=args.scope_root,
        trace_index_path=args.trace_index_path,
        windows_root=args.windows_root,
        base_prompt=(args.base_prompt or None),
        nodes_path=args.nodes_path,
        rels_path=args.rels_path,
    )
    sys.stdout.write(out + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

