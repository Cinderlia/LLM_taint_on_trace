"""
Run the branch-selection pipeline: build prompt sections from trace traces, ask an LLM to pick branches,
and trigger per-seq analysis runs.
"""

import asyncio
import json
import os
import sys
import shutil
from typing import Iterable

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from common.logger import Logger
from common.app_config import load_app_config

from llm_utils import get_default_client
from llm_utils.taint.taint_llm_calls import LLMCallFailure, chat_text_with_retries

from branch_selector.core.buffer import PromptBuffer
from branch_selector.core.config import load_config
from branch_selector.core.scope_folding import ScopeSubsetFolder
from branch_selector.prompt.llm_response import parse_llm_response
from branch_selector.prompt.prompt_builder import build_prompt, format_section
from branch_selector.trace.if_scope_expand import expand_if_seq_groups
from branch_selector.sim.test_simulator import simulate_response, write_prompt_text, write_response_json
from branch_selector.trace.trace_extract import (
    build_loc_for_seq,
    build_seq_to_index,
    collect_if_switch_seqs,
    ensure_trace_index,
    load_nodes_and_edges,
)
from llm_utils.prompts.prompt_utils import map_result_set_to_source_lines
from if_branch_coverage import check_if_branch_coverage
from utils.cpg_utils.graph_mapping import safe_int


def _safe_rmtree(p: str) -> None:
    if not p:
        return
    if not os.path.exists(p):
        return
    try:
        shutil.rmtree(p)
    except Exception:
        return


def _clear_branch_selector_logs(base_dir: str) -> None:
    _safe_rmtree(os.path.join(base_dir, "branch_selector", "logs"))


def _clear_branch_selector_dir(base_dir: str) -> None:
    _safe_rmtree(os.path.join(base_dir, "branch_selector"))


def _clear_seq_dirs(base_dir: str) -> None:
    if not os.path.isdir(base_dir):
        return
    for name in os.listdir(base_dir):
        if not name.startswith("seq_"):
            continue
        seq_dir = os.path.join(base_dir, name)
        if not os.path.isdir(seq_dir):
            continue
        _safe_rmtree(seq_dir)


def _collect_if_ids_in_record(record: dict, nodes: dict, parent_of: dict[int, int]) -> list[int]:
    if not isinstance(record, dict):
        return []
    out: set[int] = set()
    for nid in record.get("node_ids") or []:
        ni = safe_int(nid)
        if ni is None:
            continue
        tt = ((nodes.get(int(ni)) or {}).get("type") or "").strip()
        if tt == "AST_IF":
            out.add(int(ni))
            continue
        if tt == "AST_IF_ELEM":
            cur = parent_of.get(int(ni))
            steps = 0
            while cur is not None and steps < 8:
                ct = ((nodes.get(int(cur)) or {}).get("type") or "").strip()
                if ct == "AST_IF":
                    out.add(int(cur))
                    break
                cur = parent_of.get(int(cur))
                steps += 1
    return sorted(out)


# Summary: Yield per-seq prompt sections by expanding/merging trace-derived IF/SWITCH neighborhoods.
def _iter_if_switch_sections(
    *,
    trace_index_records: list[dict],
    nodes: dict,
    parent_of: dict,
    children_of: dict,
    seq_limit: int,
    scope_root: str,
    trace_index_path: str,
    windows_root: str,
    nearest_seq_count: int,
    farthest_seq_count: int,
    trace_path: str,
    logger: Logger | None = None,
) -> Iterable[dict]:
    seq_to_index = build_seq_to_index(trace_index_records)
    seq_groups = collect_if_switch_seqs(trace_index_records=trace_index_records, nodes=nodes, seq_limit=seq_limit, logger=logger)
    seq_groups = expand_if_seq_groups(
        seq_groups=seq_groups,
        trace_index_records=trace_index_records,
        nodes=nodes,
        parent_of=parent_of,
        children_of=children_of,
        trace_path=trace_path,
        scope_root=scope_root,
        windows_root=windows_root,
        nearest_seq_count=nearest_seq_count,
        farthest_seq_count=farthest_seq_count,
    )
    if logger is not None:
        logger.info("section_iter_start", seqs=len(seq_groups))
    for seq in sorted(seq_groups.keys()):
        rec = None
        idx = seq_to_index.get(int(seq))
        if idx is not None and 0 <= idx < len(trace_index_records):
            rec = trace_index_records[idx]
        if rec is None:
            for r in trace_index_records or []:
                if int(seq) in (r.get("seqs") or []):
                    rec = r
                    break
        if isinstance(rec, dict):
            if_ids = _collect_if_ids_in_record(rec, nodes, parent_of)
            if if_ids:
                if logger is not None:
                    logger.info("if_coverage_check_start", seq=int(seq), if_ids=[int(x) for x in if_ids])
                all_covered = True
                for if_id in if_ids:
                    covered = check_if_branch_coverage(int(if_id))
                    if logger is not None:
                        logger.info("if_coverage_check_item", seq=int(seq), if_id=int(if_id), covered=bool(covered))
                    if not covered:
                        all_covered = False
                if all_covered:
                    if logger is not None:
                        logger.info("if_coverage_skip", seq=int(seq), if_ids=[int(x) for x in if_ids])
                    continue
        rel_seqs = seq_groups.get(seq) or []
        locs = []
        for s in rel_seqs or []:
            loc = build_loc_for_seq(int(s), trace_index_records, seq_to_index)
            if loc:
                locs.append(loc)
        lines = map_result_set_to_source_lines(scope_root, locs, trace_index_path=trace_index_path, windows_root=windows_root)
        sig_items = []
        sig_set = set()
        for it in lines or []:
            if not isinstance(it, dict):
                continue
            p = it.get("path")
            ln = it.get("line")
            if not p or ln is None:
                continue
            key = f"{p}:{int(ln)}"
            if key in sig_set:
                continue
            sig_set.add(key)
            sig_items.append(key)
        sig_items.sort()
        sig = tuple(sig_items) if sig_items else None
        yield {"seq": int(seq), "lines": lines, "sig": sig, "scope_seqs": list(rel_seqs or [])}


async def _run_analyze_seq(seq: int, *, sem: asyncio.Semaphore, llm_test_mode: bool, logger: Logger | None = None):
    async with sem:
        args = [sys.executable, os.path.join(os.getcwd(), "analyze_if_line.py"), str(int(seq))]
        if llm_test_mode:
            args.extend(["--llm-test", "--debug", "--prompt"])
        else:
            args.append("--llm")
        proc = await asyncio.create_subprocess_exec(*args, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        await proc.communicate()
        if logger is not None:
            logger.info("analyze_if_line_done", seq=int(seq), returncode=proc.returncode)


async def _handle_llm_response(seqs_groups: list[list[int]], *, llm_test_mode: bool, sem: asyncio.Semaphore, logger: Logger | None = None):
    tasks = []
    seen = set()
    total = 0
    for group in seqs_groups or []:
        for s in group or []:
            try:
                si = int(s)
            except Exception:
                continue
            if si in seen:
                continue
            seen.add(si)
            total += 1
            tasks.append(asyncio.create_task(_run_analyze_seq(si, sem=sem, llm_test_mode=llm_test_mode, logger=logger)))
    if logger is not None:
        logger.info("analyze_if_line_schedule", count=total, llm_test_mode=llm_test_mode)
    if tasks:
        await asyncio.gather(*tasks)


# Summary: Flush buffered sections to a prompt, get/simulate an LLM response, and schedule per-seq analysis.
async def _flush_buffer(
    *,
    sections: list[dict],
    separator: str,
    test_mode: bool,
    analyze_llm_test_mode: bool,
    base_prompt: str,
    prompt_out_dir: str,
    response_out_dir: str,
    llm_client,
    llm_call_index: int,
    analyze_sem: asyncio.Semaphore,
    logger: Logger | None = None,
):
    prompt_text = build_prompt(sections=sections, separator=separator, base_prompt=base_prompt, logger=logger)
    if logger is not None:
        logger.info("buffer_flush_start", prompt_index=llm_call_index, sections=len(sections))
    ppath = write_prompt_text(prompt_out_dir, f"prompt_{llm_call_index}.txt", prompt_text, logger=logger)
    if test_mode:
        rpath = os.path.join(response_out_dir, f"response_{llm_call_index}.json")
        resp = None
        if os.path.exists(rpath):
            try:
                with open(rpath, "r", encoding="utf-8", errors="replace") as f:
                    resp = json.load(f)
            except Exception:
                resp = None
            if logger is not None:
                logger.info("response_reused", path=rpath)
        if resp is None:
            resp = simulate_response(sections, pick_count=5, logger=logger)
            _ = write_response_json(response_out_dir, f"response_{llm_call_index}.json", resp, logger=logger)
        _ = ppath
        resp_groups = parse_llm_response(json.dumps(resp, ensure_ascii=False), logger=logger)
        await _handle_llm_response(resp_groups, llm_test_mode=analyze_llm_test_mode, sem=analyze_sem, logger=logger)
        return
    rpath = os.path.join(response_out_dir, f"response_{llm_call_index}.json")
    if os.path.exists(rpath):
        try:
            with open(rpath, "r", encoding="utf-8", errors="replace") as f:
                resp_payload = json.load(f)
        except Exception:
            resp_payload = None
        if resp_payload is not None:
            if logger is not None:
                logger.info("response_reused", path=rpath)
            resp_groups = parse_llm_response(json.dumps(resp_payload, ensure_ascii=False), logger=logger)
            await _handle_llm_response(resp_groups, llm_test_mode=analyze_llm_test_mode, sem=analyze_sem, logger=logger)
            return
    try:
        max_attempts = int(cfg.llm_max_attempts) if int(cfg.llm_max_attempts) > 0 else 1
    except Exception:
        max_attempts = 1
    try:
        txt = await chat_text_with_retries(client=llm_client, prompt=prompt_text, system=None, max_attempts=max_attempts, call_timeout_s=getattr(llm_client, "timeout_s", None) if llm_client else None, call_index=llm_call_index)
    except LLMCallFailure:
        if logger is not None:
            logger.warning("llm_call_failed", prompt_index=llm_call_index)
        return
    try:
        resp_payload = json.loads(txt)
    except Exception:
        resp_payload = {"raw": txt}
    rpath = write_response_json(response_out_dir, f"response_{llm_call_index}.json", resp_payload, logger=logger)
    _ = ppath, rpath
    resp_groups = parse_llm_response(txt, logger=logger)
    await _handle_llm_response(resp_groups, llm_test_mode=analyze_llm_test_mode, sem=analyze_sem, logger=logger)


# Summary: Orchestrate config loading, section production, buffering, LLM calls, and analysis execution.
async def run_pipeline(config_path: str | None = None):
    cfg = load_config(config_path)
    app_cfg = load_app_config(argv=sys.argv[1:])
    base = app_cfg.base_dir
    test_root = app_cfg.test_dir
    tmp_root = app_cfg.tmp_dir
    _clear_branch_selector_dir(test_root)
    if cfg.test_mode:
        _clear_seq_dirs(test_root)

    def _rewrite_rooted_relative(p: str, root_name: str, root_abs: str) -> str:
        if not p:
            return p
        if os.path.isabs(p):
            return p
        norm = p.replace("/", os.sep).replace("\\", os.sep)
        parts = [x for x in norm.split(os.sep) if x]
        if parts and parts[0].lower() == root_name.lower():
            return os.path.join(root_abs, *parts[1:])
        return os.path.join(base, norm)

    prompt_out_dir = _rewrite_rooted_relative(cfg.prompt_out_dir, "test", test_root)
    response_out_dir = _rewrite_rooted_relative(cfg.response_out_dir, "test", test_root)
    trace_index_path = _rewrite_rooted_relative(cfg.trace_index_path, "tmp", tmp_root)

    log_dir = os.path.join(test_root, "branch_selector")
    logger = Logger(base_dir=log_dir, min_level="INFO", name="branch_selector", also_console=True)
    logger.info("pipeline_start", config_path=(config_path or "config.json"), test_mode=cfg.test_mode)
    trace_path = app_cfg.find_input_file("trace.log")
    nodes_path = app_cfg.find_input_file("nodes.csv")
    rels_path = app_cfg.find_input_file("rels.csv")
    trace_index_records = ensure_trace_index(trace_index_path, trace_path, nodes_path, cfg.seq_limit, logger=logger)
    nodes, parent_of, children_of, top_id_to_file = load_nodes_and_edges(nodes_path, rels_path)
    _ = top_id_to_file
    if cfg.test_mode:
        llm_client = None
    else:
        try:
            llm_client = get_default_client()
        except Exception:
            llm_client = None
    if llm_client is None and not cfg.test_mode:
        logger.warning("llm_client_missing")
    analyze_sem = asyncio.Semaphore(int(cfg.max_analyze_concurrency))

    sections_queue: asyncio.Queue = asyncio.Queue()
    done_sentinel = object()

    async def producer():
        for item in _iter_if_switch_sections(
            trace_index_records=trace_index_records,
            nodes=nodes,
            parent_of=parent_of,
            children_of=children_of,
            seq_limit=cfg.seq_limit,
            scope_root=cfg.scope_root,
            trace_index_path=trace_index_path,
            windows_root=cfg.windows_root,
            nearest_seq_count=cfg.nearest_seq_count,
            farthest_seq_count=cfg.farthest_seq_count,
            trace_path=trace_path,
            logger=logger,
        ):
            await sections_queue.put(item)
        for _ in range(int(cfg.buffer_count)):
            await sections_queue.put(done_sentinel)

    async def worker(worker_id: int):
        buffer_sections: list[dict] = []
        buffer = PromptBuffer(token_limit=cfg.buffer_token_limit)
        flush_index = 0
        last_sig = None
        folder = ScopeSubsetFolder()
        while True:
            item = await sections_queue.get()
            if item is done_sentinel:
                for emit in folder.flush():
                    sec = format_section(int(emit.get("seq")), emit.get("lines") or [], mark_seqs=emit.get("mark_seqs"), logger=logger)
                    buffer_sections.append(sec)
                    buffer.add(sec, build_prompt(sections=[sec], separator="====", base_prompt=cfg.base_prompt, logger=logger))
                if buffer_sections:
                    flush_index += 1
                    await _flush_buffer(
                        sections=buffer_sections,
                        separator="====",
                        test_mode=cfg.test_mode,
                        analyze_llm_test_mode=cfg.analyze_llm_test_mode,
                        base_prompt=cfg.base_prompt,
                        prompt_out_dir=prompt_out_dir,
                        response_out_dir=response_out_dir,
                        llm_client=llm_client,
                        llm_call_index=(worker_id * 100000 + flush_index),
                        analyze_sem=analyze_sem,
                        logger=logger,
                    )
                    buffer.clear()
                break
            sig = item.get("sig")
            if sig is None:
                last_sig = None
            else:
                if last_sig is not None and sig == last_sig:
                    continue
                last_sig = sig
            item["mark_seqs"] = [item.get("seq")]
            emits = folder.push(item)
            for emit in emits:
                sec = format_section(int(emit.get("seq")), emit.get("lines") or [], mark_seqs=emit.get("mark_seqs"), logger=logger)
                sec_text = build_prompt(sections=[sec], separator="====", base_prompt=cfg.base_prompt, logger=logger)
                if not buffer.can_add(sec_text) and buffer_sections:
                    flush_index += 1
                    await _flush_buffer(
                        sections=buffer_sections,
                        separator="====",
                        test_mode=cfg.test_mode,
                        analyze_llm_test_mode=cfg.analyze_llm_test_mode,
                        base_prompt=cfg.base_prompt,
                        prompt_out_dir=prompt_out_dir,
                        response_out_dir=response_out_dir,
                        llm_client=llm_client,
                        llm_call_index=(worker_id * 100000 + flush_index),
                        analyze_sem=analyze_sem,
                        logger=logger,
                    )
                    buffer_sections = []
                    buffer.clear()
                buffer_sections.append(sec)
                buffer.add(sec, sec_text)

    await asyncio.gather(producer(), *(worker(i + 1) for i in range(int(cfg.buffer_count))))
    logger.info("pipeline_done")


def main():
    cfg_path = None
    if len(sys.argv) > 1:
        cfg_path = sys.argv[1]
    asyncio.run(run_pipeline(cfg_path))


if __name__ == "__main__":
    main()
