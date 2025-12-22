import os
import sys
import json
import bisect
import shutil
from logger import Logger
from if_extract import norm_trace_path, collect_descendants, load_nodes, load_ast_edges, get_string_children, get_all_string_descendants, find_first_var_string
from taint_handlers import REGISTRY
from taint_handlers.llm_process import process_taints_llm
from trace_edges import build_trace_index_records, load_trace_index_records, save_trace_index_records

def _safe_rmtree(p: str) -> None:
    if not p:
        return
    if not os.path.exists(p):
        return
    try:
        shutil.rmtree(p)
    except Exception:
        return


def clean_previous_test_outputs(test_dir: str, seq: int | None = None) -> None:
    if not test_dir:
        return
    _safe_rmtree(os.path.join(test_dir, 'logs'))
    _safe_rmtree(os.path.join(test_dir, 'llm', 'prompts'))
    _safe_rmtree(os.path.join(test_dir, 'llm', 'responses'))
    _safe_rmtree(os.path.join(test_dir, 'rounds'))
    if seq is not None:
        try:
            out_path = os.path.join(test_dir, f"analysis_output_{int(seq)}.json")
        except Exception:
            out_path = ''
        if out_path and os.path.exists(out_path):
            try:
                os.remove(out_path)
            except Exception:
                pass

def read_trace_line(n):
    p = os.path.join(os.getcwd(), 'trace.log')
    with open(p, 'r', encoding='utf-8', errors='replace') as f:
        i = 0
        for line in f:
            i += 1
            if i == n:
                line = line.strip()
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
                return f"{path_part}:{ln}"
    return None

def node_display(nid, nodes, children_of):
    nx = nodes.get(nid) or {}
    t = nx.get('type') or ''
    if t == 'AST_VAR':
        ss = get_string_children(nid, children_of, nodes)
        return t, (ss[0][1] if ss else '')
    if t == 'AST_METHOD_CALL':
        ss = get_string_children(nid, children_of, nodes)
        return t, (ss[0][1] if ss else (nx.get('code') or nx.get('name') or ''))
    if t == 'AST_CALL':
        ss = get_all_string_descendants(nid, children_of, nodes)
        return t, (ss[0][1] if ss else (nx.get('code') or nx.get('name') or ''))
    if t == 'AST_PROP':
        base = find_first_var_string(nid, children_of, nodes)
        ss = get_string_children(nid, children_of, nodes)
        prop = ss[0][1] if ss else ''
        nm = (base or '') + ('.' + prop if prop else '')
        return t, nm
    if t == 'AST_DIM':
        base = find_first_var_string(nid, children_of, nodes)
        ss = get_string_children(nid, children_of, nodes)
        key = ss[0][1] if ss else ''
        nm = (base or '') + ('[' + key + ']' if key else '')
        return t, nm
    if t in ('AST_CONST', 'AST_NAME', 'string', 'integer', 'double'):
        ss = get_all_string_descendants(nid, children_of, nodes)
        if ss:
            return t, ss[0][1]
        return t, (nx.get('code') or nx.get('name') or '')
    return t, (nx.get('code') or nx.get('name') or '')

def dim_index_roots(dim_id, nodes, children_of):
    ch = list(children_of.get(dim_id, []) or [])
    if len(ch) < 2:
        return []
    ch.sort(key=lambda x: (nodes.get(x) or {}).get('childnum') if (nodes.get(x) or {}).get('childnum') is not None else 10**9)
    return ch[1:]

def collect_index_taints(dim_id, nodes, children_of):
    roots = dim_index_roots(dim_id, nodes, children_of)
    if not roots:
        return []
    allowed = {'AST_VAR', 'AST_PROP', 'AST_DIM', 'AST_METHOD_CALL', 'AST_CALL'}
    out = []
    seen = set()
    q = list(roots)
    while q:
        x = q.pop()
        if x in seen:
            continue
        seen.add(x)
        t, nm = node_display(x, nodes, children_of)
        if t in allowed:
            rec = {'id': x, 'type': t}
            if nm:
                rec['name'] = nm
            out.append(rec)
        for c in children_of.get(x, []) or []:
            q.append(c)
    return out

def build_initial_taints(st, nodes, children_of):
    r = st['result']
    taints = []
    seen = set()
    init_seq = st.get('seq')
    allowed = {'AST_VAR', 'AST_PROP', 'AST_DIM', 'AST_METHOD_CALL', 'AST_CALL'}
    def collect_receiver_related_ids(recv_id):
        if recv_id is None:
            return set()
        out = set()
        q = [recv_id]
        seen_local = set()
        while q:
            x = q.pop()
            if x in seen_local:
                continue
            seen_local.add(x)
            nx = nodes.get(x) or {}
            t = nx.get('type') or ''
            if t in ('AST_VAR', 'AST_PROP', 'AST_DIM'):
                out.add(x)
            for c in children_of.get(x, []) or []:
                q.append(c)
        return out
    def filter_method_call_receivers(initial_taints):
        recv_roots = []
        for c in r.get('calls') or []:
            if c.get('kind') == 'method_call':
                rid = c.get('recv_id')
                if rid is not None:
                    recv_roots.append(rid)
        if not recv_roots:
            return initial_taints
        drop_ids = set()
        for rid in recv_roots:
            drop_ids.update(collect_receiver_related_ids(rid))
        if not drop_ids:
            return initial_taints
        return [t for t in initial_taints if t.get('id') not in drop_ids]
    def add(rec):
        tid = rec.get('id')
        ttype = rec.get('type')
        if tid is None or tid in seen:
            return
        if ttype not in allowed:
            return
        if init_seq is not None and 'seq' not in rec:
            rec['seq'] = init_seq
        seen.add(tid)
        taints.append(rec)
    for v in r.get('vars') or []:
        add({'id': v['id'], 'type': 'AST_VAR', 'name': v.get('name', '')})
    for p in r.get('props') or []:
        add({'id': p['id'], 'type': 'AST_PROP', 'base': p.get('base', ''), 'prop': p.get('prop', '')})
    for d in r.get('dims') or []:
        add({'id': d['id'], 'type': 'AST_DIM', 'base': d.get('base', ''), 'key': d.get('key', '')})
        for it in collect_index_taints(d['id'], nodes, children_of):
            add(it)
    for c in r.get('calls') or []:
        if c.get('kind') == 'method_call':
            raw_args = c.get('args') or []
            kept_args = []
            for a in raw_args:
                if not isinstance(a, dict):
                    continue
                at = a.get('type') or ''
                if at in allowed:
                    kept_args.append(a)
            add({'id': c['id'], 'type': 'AST_METHOD_CALL', 'name': c.get('name', ''), 'recv': c.get('recv', ''), 'args': kept_args})
            for a in c.get('args') or []:
                if not isinstance(a, dict):
                    continue
                aid = a.get('id')
                at = a.get('type') or ''
                anm = a.get('name', '')
                if aid is None or not at:
                    continue
                if at not in allowed:
                    continue
                add({'id': aid, 'type': at, 'name': anm})
                if at == 'AST_DIM':
                    for it in collect_index_taints(aid, nodes, children_of):
                        add(it)
        elif c.get('kind') == 'call':
            raw_args = c.get('args') or []
            kept_args = []
            for a in raw_args:
                if not isinstance(a, dict):
                    continue
                at = a.get('type') or ''
                if at in allowed:
                    kept_args.append(a)
            add({'id': c['id'], 'type': 'AST_CALL', 'name': c.get('name', ''), 'args': kept_args})
            for a in c.get('args') or []:
                if not isinstance(a, dict):
                    continue
                aid = a.get('id')
                at = a.get('type') or ''
                anm = a.get('name', '')
                if aid is None or not at:
                    continue
                if at not in allowed:
                    continue
                add({'id': aid, 'type': at, 'name': anm})
                if at == 'AST_DIM':
                    for it in collect_index_taints(aid, nodes, children_of):
                        add(it)
    return filter_method_call_receivers(taints)

def extract_if_elements_fast(arg, seq, nodes, children_of, trace_index_records, seq_to_index):
    pth, ln_s = arg.rsplit(':', 1)
    line = int(ln_s)
    path = norm_trace_path(pth)

    rec = None
    idx = seq_to_index.get(seq)
    if idx is not None and 0 <= idx < len(trace_index_records):
        rec = trace_index_records[idx]
    if rec is None:
        for r in trace_index_records:
            if r.get('path') != path or r.get('line') != line:
                continue
            if seq in (r.get('seqs') or []):
                rec = r
                break

    candidates = rec.get('node_ids') if isinstance(rec, dict) else []
    targets = []
    for nid in candidates or []:
        nx = nodes.get(nid) or {}
        if nx.get('type') == 'AST_IF_ELEM':
            targets.append(nid)

    result = {
        'vars': [],
        'dims': [],
        'props': [],
        'consts': [],
        'calls': [],
        'isset': [],
        'empty': [],
        'class_consts': [],
        'static_props': [],
        'instanceof': [],
        'conditional': [],
        'binary_ops': [],
        'unary_ops': []
    }

    for root in targets:
        desc = collect_descendants(root, children_of, nodes, line)
        for x in desc:
            nx = nodes.get(x) or {}
            t = nx.get('type') or ''
            if t == 'AST_VAR':
                ss = get_string_children(x, children_of, nodes)
                name = ss[0][1] if ss else ''
                result['vars'].append({'id': x, 'name': name})
            elif t == 'AST_DIM':
                parts = [v for _, v in get_string_children(x, children_of, nodes)]
                base_nm = find_first_var_string(x, children_of, nodes)
                key = parts[0] if parts else ''
                result['dims'].append({'id': x, 'base': base_nm, 'key': key})
            elif t == 'AST_PROP':
                parts = [v for _, v in get_string_children(x, children_of, nodes)]
                base_nm = find_first_var_string(x, children_of, nodes)
                prop = parts[0] if parts else ''
                result['props'].append({'id': x, 'base': base_nm, 'prop': prop})
            elif t == 'AST_CONST':
                parts = [v for _, v in get_all_string_descendants(x, children_of, nodes)]
                result['consts'].append({'id': x, 'type': 'AST_CONST', 'name': parts[0] if parts else ''})
            elif t == 'AST_NAME':
                parts = [v for _, v in get_all_string_descendants(x, children_of, nodes)]
                v = parts[0] if parts else (nx.get('code') or nx.get('name') or '')
                result['consts'].append({'id': x, 'type': 'AST_NAME', 'name': v})
            elif t == 'AST_METHOD_CALL':
                fn = ''
                recv = ''
                recv_id = None
                for c in children_of.get(x, []) or []:
                    nc = nodes.get(c) or {}
                    if nc.get('type') == 'AST_VAR':
                        ssc = get_string_children(c, children_of, nodes)
                        recv = ssc[0][1] if ssc else ''
                        if recv_id is None:
                            recv_id = c
                    if nc.get('labels') == 'string' or nc.get('type') == 'string':
                        vv = nc.get('code') or nc.get('name') or ''
                        if vv:
                            fn = vv
                    if recv_id is None and nc.get('type') != 'AST_ARG_LIST' and nc.get('labels') != 'string' and nc.get('type') != 'string':
                        recv_id = c
                        _, recv_nm = node_display(c, nodes, children_of)
                        recv = recv_nm
                arg_list_id = None
                args = []
                for c in children_of.get(x, []) or []:
                    nc = nodes.get(c) or {}
                    if nc.get('type') == 'AST_ARG_LIST':
                        arg_list_id = c
                        for ac in children_of.get(c, []) or []:
                            anc = nodes.get(ac) or {}
                            if anc.get('labels') == 'string' or anc.get('type') == 'string':
                                vv = anc.get('code') or anc.get('name') or ''
                                if vv:
                                    args.append({'id': ac, 'type': 'string', 'name': vv})
                            elif anc.get('type') == 'AST_VAR':
                                ssc = get_string_children(ac, children_of, nodes)
                                vv = ssc[0][1] if ssc else ''
                                if vv:
                                    args.append({'id': ac, 'type': 'AST_VAR', 'name': vv})
                            elif anc.get('type') in ('AST_PROP', 'AST_DIM'):
                                ssc = get_all_string_descendants(ac, children_of, nodes)
                                vv = ssc[0][1] if ssc else ''
                                if vv:
                                    args.append({'id': ac, 'type': anc.get('type'), 'name': vv})
                result['calls'].append({'id': x, 'kind': 'method_call', 'name': fn, 'recv': recv, 'recv_id': recv_id, 'arg_list_id': arg_list_id, 'args': args})
            elif t == 'AST_CALL':
                fn = ''
                for c in children_of.get(x, []) or []:
                    nc = nodes.get(c) or {}
                    if nc.get('labels') == 'string' or nc.get('type') == 'string':
                        vv = nc.get('code') or nc.get('name') or ''
                        if vv:
                            fn = vv
                    if nc.get('type') == 'AST_NAME':
                        ssc = get_string_children(c, children_of, nodes)
                        if ssc:
                            fn = ssc[0][1]
                arg_list_id = None
                args = []
                for c in children_of.get(x, []) or []:
                    nc = nodes.get(c) or {}
                    if nc.get('type') == 'AST_ARG_LIST':
                        arg_list_id = c
                        for ac in children_of.get(c, []) or []:
                            anc = nodes.get(ac) or {}
                            if anc.get('labels') == 'string' or anc.get('type') == 'string':
                                vv = anc.get('code') or anc.get('name') or ''
                                if vv:
                                    args.append({'id': ac, 'type': 'string', 'name': vv})
                            elif anc.get('type') == 'AST_VAR':
                                ssc = get_string_children(ac, children_of, nodes)
                                vv = ssc[0][1] if ssc else ''
                                if vv:
                                    args.append({'id': ac, 'type': 'AST_VAR', 'name': vv})
                            elif anc.get('type') in ('AST_PROP', 'AST_DIM'):
                                ssc = get_all_string_descendants(ac, children_of, nodes)
                                vv = ssc[0][1] if ssc else ''
                                if vv:
                                    args.append({'id': ac, 'type': anc.get('type'), 'name': vv})
                result['calls'].append({'id': x, 'kind': 'call', 'name': fn, 'arg_list_id': arg_list_id, 'args': args})

    return {'arg': arg, 'path': path, 'line': line, 'targets': targets, 'result': result}

def process_taints(initial, ctx):
    if ctx.get('llm_enabled'):
        return process_taints_llm(initial, ctx)
    preA = list(initial)
    preB = []
    useA = True
    while preA or preB:
        active = preA if useA else preB
        if not active:
            useA = not useA
            continue
        nxt = []
        for t in list(active):
            fn = REGISTRY.get(t.get('type') or '')
            if fn:
                res_sets = fn(t, ctx) or []
                for s in res_sets:
                    if isinstance(s, (list, tuple)):
                        for x in s:
                            nxt.append(x)
                    elif isinstance(s, dict):
                        nxt.append(s)
            active.pop(0)
        if useA:
            preA = nxt
            useA = False
        else:
            preB = nxt
            useA = True
    return []

def parse_loc(loc):
    if not loc or ':' not in loc:
        return None
    p, ln_s = loc.rsplit(':', 1)
    try:
        ln = int(ln_s)
    except:
        return None
    return norm_trace_path(p), ln

def build_seq_index(trace_index_records):
    m = {}
    for rec in trace_index_records or []:
        p = rec.get('path')
        ln = rec.get('line')
        if not p or ln is None:
            continue
        seqs = rec.get('seqs') or []
        if not seqs:
            continue
        buf = m.get((p, ln))
        if buf is None:
            buf = []
            m[(p, ln)] = buf
        for x in seqs:
            try:
                buf.append(int(x))
            except:
                continue
    for k, buf in list(m.items()):
        if not buf:
            m.pop(k, None)
            continue
        buf.sort()
        uniq = []
        last = None
        for x in buf:
            if last is None or x != last:
                uniq.append(x)
                last = x
        m[k] = uniq
    return m

def _pick_seq_near(seqs, ref_seq: int | None, prefer: str):
    if not seqs:
        return None
    if ref_seq is None:
        return seqs[0]
    r = int(ref_seq)
    if prefer == 'backward':
        i = bisect.bisect_right(seqs, r) - 1
        if i >= 0:
            return seqs[i]
        return seqs[0]
    i = bisect.bisect_left(seqs, r)
    if i < len(seqs):
        return seqs[i]
    return seqs[-1]

def attach_min_seq_to_result_set(result_set, trace_index_records, ref_seq: int | None = None, prefer: str = 'forward'):
    idx = build_seq_index(trace_index_records)
    out = []
    for it in result_set or []:
        if isinstance(it, dict):
            p = it.get('path')
            ln = it.get('line')
            if not p or ln is None:
                pr = parse_loc(it.get('loc') or '')
                if pr:
                    p, ln = pr
            if not p or ln is None:
                continue
            seq = it.get('seq')
            if seq is None:
                seq = _pick_seq_near(idx.get((p, ln)) or [], ref_seq, prefer)
            out.append({'seq': seq, 'path': p, 'line': ln, 'loc': f"{p}:{ln}"})
            continue
        if isinstance(it, str):
            pr = parse_loc(it)
            if not pr:
                continue
            p, ln = pr
            out.append({'seq': _pick_seq_near(idx.get((p, ln)) or [], ref_seq, prefer), 'path': p, 'line': ln, 'loc': f"{p}:{ln}"})
    return out

def sort_dedup_result_set_by_seq(result_set):
    items = [it for it in (result_set or []) if isinstance(it, dict)]
    def key(it):
        s = it.get('seq')
        try:
            s2 = int(s)
        except:
            s2 = 10**18
        return (s2, str(it.get('path') or ''), int(it.get('line') or 0))
    items.sort(key=key)
    seen_seq = set()
    seen_loc = set()
    out = []
    for it in items:
        s = it.get('seq')
        if s is None:
            loc = it.get('loc') or f"{it.get('path') or ''}:{it.get('line') or ''}"
            if loc in seen_loc:
                continue
            seen_loc.add(loc)
            out.append(it)
            continue
        try:
            si = int(s)
        except:
            loc = it.get('loc') or f"{it.get('path') or ''}:{it.get('line') or ''}"
            if loc in seen_loc:
                continue
            seen_loc.add(loc)
            out.append(it)
            continue
        if si in seen_seq:
            continue
        seen_seq.add(si)
        out.append(it)
    return out

def main():
    if len(sys.argv) < 2:
        return
    s = sys.argv[1]
    debug_mode = any(x == '--debug' for x in sys.argv[2:])
    llm_mode = any(x == '--llm' for x in sys.argv[2:])
    llm_max_calls = None
    for i, x in enumerate(sys.argv[2:]):
        if x.startswith('--llm-max='):
            try:
                llm_max_calls = int(x.split('=', 1)[1])
            except:
                llm_max_calls = None
        if x == '--llm-max' and (i + 3) < len(sys.argv):
            try:
                llm_max_calls = int(sys.argv[i + 3])
            except:
                llm_max_calls = None
    try:
        n = int(s)
    except:
        return
    base = os.getcwd()
    test_dir = os.path.join(base, 'test')
    os.makedirs(test_dir, exist_ok=True)
    clean_previous_test_outputs(test_dir, n)
    logger = Logger(base_dir=test_dir, min_level=('DEBUG' if debug_mode else 'INFO'), name=f'analyze_if_line:{n}', also_console=True)
    out_path = os.path.join(test_dir, f"analysis_output_{n}.json")
    def finish(obj):
        with open(out_path, 'w', encoding='utf-8') as f:
            json.dump(obj, f, ensure_ascii=False, indent=2)
        logger.info('write_output', out_path=out_path)
        logger.close()
        return

    arg = read_trace_line(n)
    if not arg:
        return finish({'error': 'trace_log_line_parse_failed'})
    nodes_path = os.path.join(base, 'nodes.csv')
    trace_path = os.path.join(base, 'trace.log')

    trace_index_path = os.path.join(test_dir, 'trace_index.json')
    trace_index_records = load_trace_index_records(trace_index_path)
    if trace_index_records is None:
        trace_index_records = build_trace_index_records(trace_path, nodes_path, None)
        save_trace_index_records(trace_index_path, trace_index_records, {'trace_path': 'trace.log', 'nodes_path': 'nodes.csv'})

    seq_to_index = {}
    for rec in trace_index_records:
        idx = rec.get('index')
        for s in rec.get('seqs') or []:
            if s not in seq_to_index:
                seq_to_index[s] = idx

    nodes, top_id_to_file = load_nodes(nodes_path)
    parent_of, children_of = load_ast_edges(os.path.join(os.getcwd(), 'rels.csv'))
    st = extract_if_elements_fast(arg, n, nodes, children_of, trace_index_records, seq_to_index)
    if not (st.get('targets') or []):
        return finish({'error': 'if_elem_not_found_for_trace_line'})

    st['seq'] = n
    initial = build_initial_taints(st, nodes, children_of)

    ctx = {
        'input_seq': n,
        'path': st['path'],
        'line': st['line'],
        'targets': st['targets'],
        'result': st['result'],
        'nodes': nodes,
        'children_of': children_of,
        'parent_of': parent_of,
        'top_id_to_file': top_id_to_file,
        'trace_index_records': trace_index_records,
        'trace_seq_to_index': seq_to_index,
        'scope_root': '/app',
        'windows_root': r'D:\files\witcher\app',
        'llm_enabled': llm_mode,
        'llm_max_calls': (llm_max_calls if llm_mode else None),
        'debug': None,
        'logger': logger,
        'test_dir': test_dir,
    }
    try:
        process_taints(initial, ctx)
    except Exception:
        logger.exception('analyze_failed')
        try:
            rs = ctx.get('result_set') or []
            rs2 = attach_min_seq_to_result_set(rs, trace_index_records, ref_seq=n, prefer='forward')
            rs2 = sort_dedup_result_set_by_seq(rs2)
        except Exception:
            rs2 = []
        finish({'input_seq': n, 'initial_taints': initial, 'result_set': rs2, 'error': 'analyze_failed'})
        raise SystemExit(1)
    rs = ctx.get('result_set') or []
    rs2 = attach_min_seq_to_result_set(rs, trace_index_records, ref_seq=n, prefer='forward')
    rs2 = sort_dedup_result_set_by_seq(rs2)
    out = {
        'input_seq': n,
        'initial_taints': initial,
        'result_set': rs2,
    }
    return finish(out)

if __name__ == '__main__':
    main()
