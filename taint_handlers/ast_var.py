import os
from trace_edges import build_trace_index_records

def record_taint_source(taint, ctx):
    if not isinstance(ctx, dict) or not isinstance(taint, dict):
        return
    tt = (taint.get('type') or '').strip()
    if not tt:
        return
    this_obj = (taint.get('_this_obj') or '').strip()
    if this_obj.startswith('$'):
        this_obj = this_obj[1:]
    def rewrite_this(s: str) -> str:
        if not this_obj:
            return (s or '').strip()
        v = (s or '').strip()
        if not v:
            return v
        if v == 'this':
            return this_obj
        if v.startswith('this->'):
            return this_obj + v[4:]
        if v.startswith('this['):
            return this_obj + v[4:]
        return v
    src = ''
    if tt == 'AST_VAR':
        src = rewrite_this(taint.get('name') or '')
    elif tt == 'AST_PROP':
        base = rewrite_this(taint.get('base') or '')
        prop = (taint.get('prop') or '').strip()
        if base and prop:
            src = f"{base}->{prop}"
        else:
            nm = rewrite_this(taint.get('name') or '')
            src = nm.replace('.', '->') if nm and '->' not in nm else nm
    elif tt == 'AST_DIM':
        base = rewrite_this(taint.get('base') or '')
        key = (taint.get('key') or '').strip()
        if base and key:
            src = f"{base}[{key}]"
        else:
            src = rewrite_this(taint.get('name') or '')
    elif tt == 'AST_METHOD_CALL':
        recv = rewrite_this(taint.get('recv') or '')
        name = (taint.get('name') or '').strip()
        if name.endswith('()'):
            name = name[:-2]
        if recv and name:
            src = f"{recv}->{name}()"
        elif name:
            src = name if name.endswith('()') else f"{name}()"
    elif tt == 'AST_CALL':
        name = (taint.get('name') or '').strip()
        if name:
            src = name if name.endswith('()') else f"{name}()"
    else:
        src = rewrite_this(taint.get('name') or '')
    if not src:
        return
    seen = ctx.setdefault('_taint_sources_seen', set())
    key = (tt, src)
    if key in seen:
        return
    seen.add(key)
    ctx.setdefault('taint_sources', []).append({'type': tt, 'source': src})

def build_seq_to_index(trace_index_records):
    m = {}
    for rec in trace_index_records:
        idx = rec.get('index')
        for s in rec.get('seqs') or []:
            if s not in m:
                m[s] = idx
    return m

def ensure_trace_index(ctx):
    recs = ctx.get('trace_index_records')
    if recs is not None:
        return recs
    base = os.getcwd()
    trace_path = os.path.join(base, 'trace.log')
    nodes_path = os.path.join(base, 'nodes.csv')
    recs = build_trace_index_records(trace_path, nodes_path, None)
    ctx['trace_index_records'] = recs
    ctx['trace_seq_to_index'] = build_seq_to_index(recs)
    return recs

def compress_consecutive(items):
    out = []
    prev = None
    for it in items:
        if it == prev:
            continue
        out.append(it)
        prev = it
    return out

def find_toplevel_stop_id(funcid, nodes):
    fn = nodes.get(funcid) or {}
    if fn.get('lineno') != 1:
        return None
    best = None
    best_line = None
    for nid, nx in nodes.items():
        if nx.get('funcid') != funcid:
            continue
        ln = nx.get('lineno')
        if ln is None or ln == 1:
            continue
        if best is None or ln < best_line or (ln == best_line and nid < best):
            best = nid
            best_line = ln
    return best

def process(taint, ctx):
    nid = taint.get('id')
    seq = taint.get('seq')
    if nid is None or seq is None:
        return []
    if isinstance(ctx, dict):
        ctx['_llm_scope_prefer'] = 'backward'
    record_taint_source(taint, ctx)

    nodes = ctx.get('nodes') or {}
    funcid = (nodes.get(nid) or {}).get('funcid')
    if funcid is None:
        return []

    stop_id = find_toplevel_stop_id(funcid, nodes)

    ensure_trace_index(ctx)
    recs = ctx.get('trace_index_records') or []
    seq_to_idx = ctx.get('trace_seq_to_index') or {}
    start_idx = seq_to_idx.get(seq)
    if start_idx is None:
        return []

    dbg = ctx.get('debug')
    step = {'id': nid, 'seq': seq, 'funcid': funcid, 'start_index': start_idx}
    if stop_id is not None:
        step['stop_id_c'] = stop_id
        step['stop_id_c_line'] = (nodes.get(stop_id) or {}).get('lineno')

    results = []
    for i in range(start_idx, -1, -1):
        rec = recs[i]
        node_ids = rec.get('node_ids') or []
        cur_id = node_ids[0] if node_ids else None
        cur_funcid = (nodes.get(cur_id) or {}).get('funcid') if cur_id is not None else None
        item = {
            'index': rec.get('index'),
            'path': rec.get('path'),
            'line': rec.get('line'),
            'seqs': rec.get('seqs'),
            'node_id': cur_id,
            'node_funcid': cur_funcid
        }
        if cur_funcid == funcid:
            item['kept'] = True
            results.append(f"{rec.get('path')}:{rec.get('line')}")
        if cur_id is not None and (cur_id == funcid or (stop_id is not None and cur_id == stop_id)):
            item['stop'] = True
            step.setdefault('walk', []).append(item)
            break
        step.setdefault('walk', []).append(item)

    results = compress_consecutive(results)
    step['results_count'] = len(results)
    step['results_preview'] = results
    if isinstance(dbg, dict):
        dbg.setdefault('ast_var', []).append(step)
    ctx.setdefault('result_set', [])
    ctx['result_set'].extend(results)
    return []
