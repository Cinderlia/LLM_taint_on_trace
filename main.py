import asyncio
import json
import os
import sys
import shutil

from branch_selector.core.config import load_config
from branch_selector.pipeline import run_pipeline
from branch_selector.trace.trace_extract import ensure_trace_index
from common.app_config import load_app_config
from utils.extractors.if_extract import load_ast_edges, load_nodes
from utils.trace_utils import trace_edges as trace_edges_mod


def _load_stats_enabled(cfg) -> bool:
    raw = cfg.raw if hasattr(cfg, "raw") else {}
    stats = raw.get("stats") if isinstance(raw, dict) else {}
    enabled = True
    if isinstance(stats, dict) and "enabled" in stats:
        v = stats.get("enabled")
        if isinstance(v, bool):
            enabled = v
        elif isinstance(v, str):
            enabled = v.strip().lower() in ("1", "true", "yes", "on")
        else:
            enabled = bool(v)
    return enabled


def _safe_int(v, default=0) -> int:
    try:
        return int(v)
    except Exception:
        return default


def _read_log_fields(line: str) -> dict | None:
    if not isinstance(line, str):
        return None
    idx = line.rfind(" {")
    if idx < 0:
        return None
    payload = line[idx + 1 :].strip()
    if not payload.startswith("{"):
        return None
    try:
        return json.loads(payload)
    except Exception:
        return None


def _count_if_records(trace_index_records, nodes, parent_of) -> int:
    seen = set()
    for rec in trace_index_records or []:
        node_ids = rec.get("node_ids") or []
        for nid in node_ids:
            try:
                ni = int(nid)
            except Exception:
                continue
            tt = ((nodes.get(int(ni)) or {}).get("type") or "").strip()
            if tt == "AST_IF":
                seen.add(int(ni))
                continue
            if tt == "AST_IF_ELEM":
                cur = parent_of.get(int(ni))
                steps = 0
                while cur is not None and steps < 8:
                    ct = ((nodes.get(int(cur)) or {}).get("type") or "").strip()
                    if ct == "AST_IF":
                        seen.add(int(cur))
                        break
                    cur = parent_of.get(int(cur))
                    steps += 1
    return len(seen)


def _collect_branch_selector_stats(log_path: str) -> dict:
    stats = {
        "coverage_skipped_seqs": set(),
        "submitted_to_llm": 0,
        "selected_for_analyze": 0,
    }
    if not os.path.exists(log_path):
        return stats
    with open(log_path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            if "if_coverage_skip" in line:
                fields = _read_log_fields(line)
                if isinstance(fields, dict):
                    seq = fields.get("seq")
                    if seq is not None:
                        stats["coverage_skipped_seqs"].add(_safe_int(seq))
                continue
            if "buffer_flush_start" in line:
                fields = _read_log_fields(line)
                if isinstance(fields, dict):
                    stats["submitted_to_llm"] += _safe_int(fields.get("sections"))
                continue
            if "analyze_if_line_schedule" in line:
                fields = _read_log_fields(line)
                if isinstance(fields, dict):
                    stats["selected_for_analyze"] += _safe_int(fields.get("count"))
                continue
    return stats


def _collect_symbolic_solution_stats(test_root: str) -> dict:
    seq_count = 0
    solution_total = 0
    seq_root = os.path.join(test_root, "seqs")
    if not os.path.isdir(seq_root):
        return {"solution_if_count": 0, "solution_total": 0}
    for name in os.listdir(seq_root):
        if not name.startswith("seq_"):
            continue
        log_path = os.path.join(seq_root, name, "logs", "info.log")
        if not os.path.exists(log_path):
            continue
        max_count = 0
        with open(log_path, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                if "write_symbolic_solutions" not in line:
                    continue
                fields = _read_log_fields(line)
                if isinstance(fields, dict):
                    max_count = max(max_count, _safe_int(fields.get("count")))
        if max_count > 0:
            seq_count += 1
            solution_total += max_count
    return {"solution_if_count": seq_count, "solution_total": solution_total}


def _write_stats(output_dir: str, stats: dict) -> str:
    os.makedirs(output_dir, exist_ok=True)
    path = os.path.join(output_dir, "branch_selector_stats.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(stats, f, ensure_ascii=False, indent=2)
    return path


def _parse_arg_flag(argv: list[str], key: str) -> bool:
    if not argv:
        return False
    return any(x == key for x in argv if isinstance(x, str))


def _clear_test_root(test_root: str) -> None:
    if not test_root or not os.path.isdir(test_root):
        return
    for name in os.listdir(test_root):
        path = os.path.join(test_root, name)
        try:
            if os.path.isdir(path):
                shutil.rmtree(path)
            else:
                os.remove(path)
        except Exception:
            continue


def _clear_output_root(output_root: str) -> None:
    if not output_root or not os.path.isdir(output_root):
        return
    for name in os.listdir(output_root):
        path = os.path.join(output_root, name)
        try:
            if os.path.isdir(path):
                shutil.rmtree(path)
            else:
                os.remove(path)
        except Exception:
            continue


def main():
    cfg_path = None
    argv = list(sys.argv[1:])
    if argv and not argv[0].startswith("--"):
        cfg_path = argv[0]
        argv = argv[1:]
    app_cfg = load_app_config(argv=sys.argv[1:])
    stats_enabled = _load_stats_enabled(app_cfg)
    trace_edges_path = app_cfg.tmp_path("trace_edges.csv")
    trace_index_path = app_cfg.tmp_path("trace_index.json")
    if not os.path.exists(trace_edges_path):
        trace_edges_mod.main()
    cfg = load_config(cfg_path)
    trace_path = app_cfg.find_input_file("trace.log")
    nodes_path = app_cfg.find_input_file("nodes.csv")
    if not os.path.exists(trace_index_path):
        ensure_trace_index(trace_index_path, trace_path, nodes_path, cfg.seq_limit)
    test_mode_override = True if _parse_arg_flag(argv, "--test-mode") else None
    analyze_llm_test_mode_override = True if _parse_arg_flag(argv, "--analyze-llm-test") else None
    effective_analyze_llm_test_mode = cfg.analyze_llm_test_mode if analyze_llm_test_mode_override is None else bool(analyze_llm_test_mode_override)
    if not effective_analyze_llm_test_mode:
        _clear_test_root(app_cfg.test_dir)
        _clear_output_root(app_cfg.output_dir)
    asyncio.run(
        run_pipeline(
            cfg_path,
            test_mode_override=test_mode_override,
            analyze_llm_test_mode_override=analyze_llm_test_mode_override,
        )
    )
    if not stats_enabled:
        return
    trace_index_records = ensure_trace_index(trace_index_path, trace_path, nodes_path, cfg.seq_limit)
    nodes, _ = load_nodes(nodes_path)
    parent_of, _ = load_ast_edges(app_cfg.find_input_file("rels.csv"))
    if_count = _count_if_records(trace_index_records, nodes, parent_of)
    branch_log = os.path.join(app_cfg.test_dir, "branch_selector", "logs", "info.log")
    branch_stats = _collect_branch_selector_stats(branch_log)
    symbolic_stats = _collect_symbolic_solution_stats(app_cfg.test_dir)
    stats = {
        "trace_if_count": if_count,
        "coverage_skipped_if_count": len(branch_stats.get("coverage_skipped_seqs") or []),
        "submitted_to_llm_count": branch_stats.get("submitted_to_llm", 0),
        "llm_selected_if_count": branch_stats.get("selected_for_analyze", 0),
        "symbolic_solution_if_count": symbolic_stats.get("solution_if_count", 0),
        "symbolic_solution_total": symbolic_stats.get("solution_total", 0),
    }
    _write_stats(app_cfg.output_dir, stats)


if __name__ == "__main__":
    main()
