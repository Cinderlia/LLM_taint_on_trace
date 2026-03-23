import os

from utils.trace_utils.trace_edges import build_trace_index_records, load_trace_index_records, save_trace_index_records


def _read_trace_loc(seq: int, trace_path: str) -> tuple[str, int] | None:
    if not trace_path or not os.path.exists(trace_path):
        return None
    try:
        seq_i = int(seq)
    except Exception:
        return None
    with open(trace_path, "r", encoding="utf-8", errors="replace") as f:
        for i, line in enumerate(f, start=1):
            if i != seq_i:
                continue
            s = (line or "").strip()
            if not s:
                return None
            prefix = s.split(" | ", 1)[0]
            if ":" not in prefix:
                return None
            p, ln_s = prefix.rsplit(":", 1)
            try:
                ln = int(ln_s)
            except Exception:
                return None
            return str(p), int(ln)
    return None


def _build_seq_to_index(recs: list[dict]) -> dict[int, int]:
    out: dict[int, int] = {}
    for rec in recs or []:
        idx = rec.get("index")
        for s in rec.get("seqs") or []:
            try:
                si = int(s)
            except Exception:
                continue
            if si not in out:
                out[si] = int(idx) if idx is not None else 0
    return out


def _record_for_seq(seq: int, recs: list[dict], seq_to_index: dict[int, int]) -> dict | None:
    idx = seq_to_index.get(int(seq))
    if isinstance(idx, int) and 0 <= idx < len(recs):
        return recs[idx]
    for r in recs or []:
        if seq in (r.get("seqs") or []):
            return r
    return None


def ensure_trace_index_records_for_seq(
    *,
    seq: int,
    trace_path: str,
    nodes_path: str,
    trace_index_path: str,
    logger=None,
) -> tuple[list[dict], dict[int, int]]:
    recs = load_trace_index_records(trace_index_path)
    recs = recs if isinstance(recs, list) else []
    seq_to_index = _build_seq_to_index(recs)
    loc = _read_trace_loc(int(seq), trace_path)
    if loc is None:
        return recs, seq_to_index
    rec = _record_for_seq(int(seq), recs, seq_to_index) if recs else None
    if rec is None or rec.get("path") != loc[0] or int(rec.get("line") or -1) != int(loc[1]):
        recs = build_trace_index_records(trace_path, nodes_path, None)
        os.makedirs(os.path.dirname(trace_index_path) or ".", exist_ok=True)
        save_trace_index_records(trace_index_path, recs, {"trace_path": os.path.basename(trace_path), "nodes_path": os.path.basename(nodes_path)})
        if logger is not None:
            try:
                logger.info("trace_index_rebuilt", path=trace_index_path, seq=int(seq))
            except Exception:
                pass
        seq_to_index = _build_seq_to_index(recs)
    return recs, seq_to_index
