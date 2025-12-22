import os
from if_extract import norm_trace_path, resolve_top_id
from .ast_var import record_taint_source

def parse_trace_prefix(line):
    line = (line or '').strip()
    if not line:
        return None
    prefix = line.split(' | ', 1)[0]
    if ':' not in prefix:
        return None
    path_part, line_part = prefix.rsplit(':', 1)
    try:
        ln = int(line_part)
    except:
        return None
    return norm_trace_path(path_part), ln

def read_calls_edges(base):
    def read_edges(path):
        m = {}
        if not os.path.exists(path):
            return m
        with open(path, 'r', encoding='utf-8', errors='replace') as f:
            for raw in f:
                raw = raw.strip()
                if not raw or '\t' not in raw:
                    continue
                parts = raw.split('\t')
                if len(parts) < 3:
                    continue
                try:
                    s = int(parts[0]); e = int(parts[1])
                except:
                    continue
                t = parts[2].strip()
                if t != 'CALLS':
                    continue
                st = m.get(s)
                if st is None:
                    st = set()
                    m[s] = st
                st.add(e)
        return m

    out = {}
    for p in (os.path.join(base, 'cpg_edges.csv'), os.path.join(base, 'trace_edges.csv')):
        edges = read_edges(p)
        for s, dsts in edges.items():
            cur = out.get(s)
            if cur is None:
                out[s] = set(dsts)
            else:
                cur |= dsts
    return out

def resolve_node_file_line(nid, ctx):
    nodes = ctx.get('nodes') or {}
    parent_of = ctx.get('parent_of') or {}
    top_id_to_file = ctx.get('top_id_to_file') or {}
    nx = nodes.get(nid) or {}
    ln = nx.get('lineno')
    top = resolve_top_id(nid, parent_of, nodes, top_id_to_file)
    if top is None:
        return None
    p = top_id_to_file.get(top)
    if not p or ln is None:
        return None
    return p, ln

def find_seq_for_file_line(start_seq, target_path, target_line, trace_path):
    with open(trace_path, 'r', encoding='utf-8', errors='replace') as f:
        i = 0
        for raw in f:
            i += 1
            if i < start_seq:
                continue
            pr = parse_trace_prefix(raw)
            if not pr:
                continue
            p, ln = pr
            if p == target_path and ln == target_line:
                return i
    return None

def collect_trace_pairs(start_seq, stop_pair, trace_path):
    out = []
    prev = None
    with open(trace_path, 'r', encoding='utf-8', errors='replace') as f:
        i = 0
        for raw in f:
            i += 1
            if i < start_seq:
                continue
            pr = parse_trace_prefix(raw)
            if not pr:
                continue
            if pr == prev:
                continue
            if pr == stop_pair and i != start_seq:
                break
            prev = pr
            out.append({'seq': i, 'path': pr[0], 'line': pr[1]})
    return out

def build_first_node_index(targets, ctx):
    target_lines_by_path = {}
    target_paths = set()
    for t in targets:
        p = t.get('path')
        ln = t.get('line')
        if not p or ln is None:
            continue
        target_paths.add(p)
        s = target_lines_by_path.get(p)
        if s is None:
            s = set()
            target_lines_by_path[p] = s
        s.add(ln)
    nodes = ctx.get('nodes') or {}
    parent_of = ctx.get('parent_of') or {}
    top_id_to_file = ctx.get('top_id_to_file') or {}
    all_target_lines = set()
    for s in target_lines_by_path.values():
        all_target_lines |= s
    out = {}
    for nid, nx in nodes.items():
        ln = nx.get('lineno')
        if ln is None or ln not in all_target_lines:
            continue
        top = resolve_top_id(nid, parent_of, nodes, top_id_to_file)
        if top is None:
            continue
        p = top_id_to_file.get(top)
        if not p or p not in target_paths:
            continue
        if ln not in (target_lines_by_path.get(p) or set()):
            continue
        k = (p, ln)
        cur = out.get(k)
        if cur is None or nid < cur:
            out[k] = nid
    return out

def compress_consecutive(items):
    out = []
    prev = None
    for it in items:
        if it == prev:
            continue
        out.append(it)
        prev = it
    return out

def pick_method_id(call_seq, candidate_ids, ctx, trace_path):
    if not candidate_ids:
        return None
    if len(candidate_ids) == 1:
        return candidate_ids[0]
    cand_pairs = {}
    target_pairs = set()
    for mid in candidate_ids:
        pr = resolve_node_file_line(mid, ctx)
        if not pr:
            continue
        cand_pairs[mid] = pr
        target_pairs.add(pr)
    if not target_pairs:
        return candidate_ids[0]
    with open(trace_path, 'r', encoding='utf-8', errors='replace') as f:
        i = 0
        prev = None
        for raw in f:
            i += 1
            if i < call_seq:
                continue
            pr = parse_trace_prefix(raw)
            if not pr:
                continue
            if pr == prev:
                continue
            prev = pr
            if pr in target_pairs:
                for mid, mpr in cand_pairs.items():
                    if mpr == pr:
                        return mid
    return next(iter(cand_pairs.keys()), candidate_ids[0])

def process_call_like(taint, ctx, *, debug_key: str = 'ast_method_call'):
    base = os.getcwd()
    trace_path = os.path.join(base, 'trace.log')
    call_id = taint.get('id')
    call_seq = taint.get('seq')
    if call_id is None or call_seq is None:
        return []
    if isinstance(ctx, dict):
        ctx['_llm_scope_prefer'] = 'forward'

    dbg_ctx = ctx.get('debug')
    dbg = None
    if isinstance(dbg_ctx, dict):
        dbg = dbg_ctx.setdefault(debug_key, [])
    step = {'call_id': call_id, 'call_seq': call_seq}
    def early(status):
        step['status'] = status
        if dbg is not None:
            dbg.append(step)
        return []
    calls_edges = ctx.get('calls_edges_union')
    if calls_edges is None:
        calls_edges = read_calls_edges(base)
        ctx['calls_edges_union'] = calls_edges
    cands = list(calls_edges.get(call_id) or [])
    if not cands:
        return early('no_calls_candidates')
    step['calls_candidates'] = cands
    step['candidates_file_line'] = {str(mid): resolve_node_file_line(mid, ctx) for mid in cands}
    method_id = pick_method_id(call_seq, cands, ctx, trace_path)
    if method_id is None:
        return early('pick_method_id_failed')
    step['picked_method_id'] = method_id

    b_file_line = resolve_node_file_line(method_id, ctx)
    if not b_file_line:
        return early('resolve_picked_method_file_line_failed')
    b_path, b_line = b_file_line
    step['picked_method_file_line'] = [b_path, b_line]

    a_pr = None
    with open(trace_path, 'r', encoding='utf-8', errors='replace') as f:
        i = 0
        for raw in f:
            i += 1
            if i == call_seq:
                a_pr = parse_trace_prefix(raw)
                break
    if not a_pr:
        return early('resolve_call_trace_file_line_failed')
    step['call_trace_file_line'] = [a_pr[0], a_pr[1]]

    b_seq = find_seq_for_file_line(call_seq, b_path, b_line, trace_path)
    if b_seq is None:
        seq_to_idx = ctx.get('trace_seq_to_index') or {}
        trace_index_records = ctx.get('trace_index_records') or []
        call_idx = seq_to_idx.get(call_seq)
        step['find_method_seq_retry'] = {'call_idx': call_idx}
        if isinstance(call_idx, int) and 0 <= call_idx < len(trace_index_records):
            max_scan = 2000
            stop_i = max(call_idx - max_scan, -1)
            for i in range(call_idx - 1, stop_i, -1):
                rec = trace_index_records[i]
                if rec.get('path') != a_pr[0] or rec.get('line') != a_pr[1]:
                    continue
                cand_seqs = rec.get('seqs') or []
                cand_seq = cand_seqs[-1] if cand_seqs else None
                if cand_seq is None:
                    continue
                trial = find_seq_for_file_line(cand_seq, b_path, b_line, trace_path)
                if trial is not None:
                    step['find_method_seq_retry']['adjusted_call_idx'] = i
                    step['find_method_seq_retry']['adjusted_call_seq'] = cand_seq
                    b_seq = trial
                    break
        if b_seq is None:
            return early('find_method_seq_failed')
    step['method_seq'] = b_seq

    targets = collect_trace_pairs(b_seq, a_pr, trace_path)
    idx = build_first_node_index(targets, ctx)
    step['scan_targets_count'] = len(targets)

    nodes = ctx.get('nodes') or {}
    results = []
    loc_taints = []
    for t in targets:
        k = (t['path'], t['line'])
        nid = idx.get(k)
        if nid is None:
            continue
        fx = (nodes.get(nid) or {}).get('funcid')
        if fx != method_id and nid != method_id:
            continue
        loc = f"{t['path']}:{t['line']}"
        results.append(loc)
        loc_taints.append({'type': 'TRACE_LOC', 'seq': t['seq'], 'path': t['path'], 'line': t['line'], 'funcid': fx})

    results = compress_consecutive(results)
    step['results_count'] = len(results)
    step['results_preview'] = results[:30]
    if dbg is not None:
        dbg.append(step)
    ctx.setdefault('result_set', [])
    ctx['result_set'].extend(results)
    return [loc_taints] if loc_taints else []


def process(taint, ctx):
    record_taint_source(taint, ctx)
    return process_call_like(taint, ctx, debug_key='ast_method_call')
