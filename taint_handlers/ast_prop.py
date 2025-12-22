from if_extract import get_string_children, find_first_var_string

from . import ast_method_call
from . import ast_var


def _strip_dollar(s: str) -> str:
    v = (s or '').strip()
    if v.startswith('$'):
        return v[1:]
    return v


def _parse_obj_prop(taint) -> tuple[str, str]:
    if not isinstance(taint, dict):
        return '', ''
    this_obj = _strip_dollar((taint.get('_this_obj') or '').strip())
    base = (taint.get('base') or '').strip()
    prop = (taint.get('prop') or '').strip()
    if base and prop:
        b = _strip_dollar(base)
        if this_obj and b in ('this', '$this'):
            b = this_obj
        return b, prop
    nm = (taint.get('name') or '').strip()
    if not nm:
        return '', ''
    nm = nm.replace('.', '->')
    if '->' not in nm:
        b = _strip_dollar(nm)
        if this_obj and b in ('this', '$this'):
            b = this_obj
        return b, ''
    parts = [p for p in nm.split('->') if p]
    if len(parts) < 2:
        b = _strip_dollar(parts[0] if parts else '')
        if this_obj and b in ('this', '$this'):
            b = this_obj
        return b, ''
    b = _strip_dollar(parts[0])
    if this_obj and b in ('this', '$this'):
        b = this_obj
    return b, parts[-1]


def _is_this_rewritten_prop(taint) -> bool:
    if not isinstance(taint, dict):
        return False
    if not (taint.get('_this_obj') or '').strip():
        return False
    s = taint.get('_this_call_seq')
    try:
        return s is not None and int(s) > 0
    except Exception:
        return False


def _start_seq_for_scope(taint) -> int | None:
    if not isinstance(taint, dict):
        return None
    if _is_this_rewritten_prop(taint):
        try:
            return int(taint.get('_this_call_seq'))
        except Exception:
            return None
    try:
        return int(taint.get('seq'))
    except Exception:
        return None


def _method_call_recv_name(call_id: int, nodes, children_of) -> tuple[str, str]:
    def recv_name(expr_id: int) -> str:
        nx = nodes.get(expr_id) or {}
        tt = (nx.get('type') or '').strip()
        if tt == 'AST_VAR':
            ss = get_string_children(expr_id, children_of, nodes)
            v = ss[0][1] if ss else ''
            if v:
                return v
        if tt in ('AST_PROP', 'AST_DIM'):
            v = (find_first_var_string(expr_id, children_of, nodes) or '').strip()
            if v:
                return v
        v = (nx.get('code') or nx.get('name') or '').strip()
        if v.startswith('$'):
            v = v[1:]
        if '->' in v:
            v = v.split('->', 1)[0].strip()
        if '(' in v:
            v = v.split('(', 1)[0].strip()
        return v

    recv = ''
    name = ''
    ch = list(children_of.get(call_id, []) or [])
    ch.sort(key=lambda x: (nodes.get(x) or {}).get('childnum') if (nodes.get(x) or {}).get('childnum') is not None else 10**9)
    for c in ch:
        nx = nodes.get(c) or {}
        if not recv and nx.get('type') not in ('AST_ARG_LIST',) and nx.get('labels') != 'string' and nx.get('type') != 'string':
            recv = recv_name(int(c))
        if not name and (nx.get('labels') == 'string' or nx.get('type') == 'string'):
            v = (nx.get('code') or nx.get('name') or '').strip()
            if v:
                name = v
        if recv and name:
            break
    return _strip_dollar(recv), name


def _prop_base_prop(prop_id: int, nodes, children_of) -> tuple[str, str]:
    base = ''
    prop = ''
    ch = list(children_of.get(prop_id, []) or [])
    ch.sort(key=lambda x: (nodes.get(x) or {}).get('childnum') if (nodes.get(x) or {}).get('childnum') is not None else 10**9)
    for c in ch:
        nx = nodes.get(c) or {}
        if not base and nx.get('type') == 'AST_VAR':
            ss = get_string_children(c, children_of, nodes)
            base = ss[0][1] if ss else ''
        if not prop and (nx.get('labels') == 'string' or nx.get('type') == 'string'):
            v = (nx.get('code') or nx.get('name') or '').strip()
            if v:
                prop = v
        if base and prop:
            break
    return _strip_dollar(base), prop


def _scope_has_this_prop(loc_taints, ctx, *, prop: str) -> bool:
    if not prop:
        return False
    nodes = ctx.get('nodes') or {}
    children_of = ctx.get('children_of') or {}
    recs = ctx.get('trace_index_records') or []
    seq_to_idx = ctx.get('trace_seq_to_index') or {}
    for lt in loc_taints or []:
        try:
            s = int((lt or {}).get('seq'))
        except Exception:
            continue
        idx = seq_to_idx.get(s)
        if not isinstance(idx, int) or idx < 0 or idx >= len(recs):
            continue
        rec = recs[idx] or {}
        for nid in rec.get('node_ids') or []:
            nx = nodes.get(nid) or {}
            if nx.get('type') != 'AST_PROP':
                continue
            b, p = _prop_base_prop(int(nid), nodes, children_of)
            if b == 'this' and p == prop:
                return True
    return False


def process(taint, ctx):
    if not isinstance(taint, dict) or not isinstance(ctx, dict):
        return []
    if isinstance(ctx, dict):
        ctx['_llm_scope_prefer'] = 'backward'

    ast_var.record_taint_source(taint, ctx)

    obj, prop = _parse_obj_prop(taint)

    start_seq = _start_seq_for_scope(taint)
    if start_seq is None:
        return []

    ast_var.ensure_trace_index(ctx)
    recs = ctx.get('trace_index_records') or []
    seq_to_idx = ctx.get('trace_seq_to_index') or {}
    start_idx = seq_to_idx.get(start_seq)
    if start_idx is None:
        return []

    nodes = ctx.get('nodes') or {}
    node_ids0 = (recs[start_idx] or {}).get('node_ids') or []
    cur0 = node_ids0[0] if node_ids0 else None
    funcid = (nodes.get(cur0) or {}).get('funcid') if cur0 is not None else None
    if funcid is None:
        nid = taint.get('id')
        funcid = (nodes.get(nid) or {}).get('funcid') if nid is not None else None
    if funcid is None:
        return []

    stop_id = ast_var.find_toplevel_stop_id(funcid, nodes)

    scope_recs = []
    results = []
    for i in range(int(start_idx), -1, -1):
        rec = recs[i] or {}
        node_ids = rec.get('node_ids') or []
        cur_id = node_ids[0] if node_ids else None
        cur_funcid = (nodes.get(cur_id) or {}).get('funcid') if cur_id is not None else None
        if cur_funcid == funcid:
            scope_recs.append(rec)
            results.append(f"{rec.get('path')}:{rec.get('line')}")
        if cur_id is not None and (cur_id == funcid or (stop_id is not None and cur_id == stop_id)):
            break

    results = ast_var.compress_consecutive(results)
    ctx.setdefault('result_set', [])
    if results:
        ctx.setdefault('_llm_extra_prompt_locs', []).extend(results)
    ctx['result_set'].extend(results)

    if not obj or not prop:
        return []

    children_of = ctx.get('children_of') or {}
    seen_calls = set()
    existing = set(ctx.get('result_set') or [])
    for rec in scope_recs:
        seqs = rec.get('seqs') or []
        call_seq = None
        if seqs:
            try:
                call_seq = int(min(int(x) for x in seqs))
            except Exception:
                call_seq = None
        if call_seq is None:
            continue
        for nid in rec.get('node_ids') or []:
            nx = nodes.get(nid) or {}
            if nx.get('type') != 'AST_METHOD_CALL':
                continue
            try:
                call_id = int(nid)
            except Exception:
                continue
            if call_id in seen_calls:
                continue
            recv, _ = _method_call_recv_name(call_id, nodes, children_of)
            if recv != obj:
                continue

            seen_calls.add(call_id)
            ctx2 = {
                'nodes': nodes,
                'children_of': children_of,
                'parent_of': ctx.get('parent_of') or {},
                'top_id_to_file': ctx.get('top_id_to_file') or {},
                'trace_index_records': recs,
                'trace_seq_to_index': seq_to_idx,
                'calls_edges_union': ctx.get('calls_edges_union'),
                'debug': ctx.get('debug'),
            }
            call_taint = {'id': call_id, 'type': 'AST_METHOD_CALL', 'seq': call_seq}
            call_res = ast_method_call.process_call_like(call_taint, ctx2, debug_key='ast_prop_expand')
            loc_taints = call_res[0] if (isinstance(call_res, list) and call_res and isinstance(call_res[0], list)) else []
            if not _scope_has_this_prop(loc_taints, ctx, prop=prop):
                continue
            function_scope_locs = list(ctx2.get('result_set') or [])
            if function_scope_locs:
                ctx.setdefault('_llm_extra_prompt_locs', []).extend(function_scope_locs)
                ctx.setdefault('_llm_scope_markers', []).append({'kind': 'function_scope', 'start': function_scope_locs[0], 'end': function_scope_locs[-1]})
            added_locs = []
            for loc in ctx2.get('result_set') or []:
                if loc not in existing:
                    existing.add(loc)
                    ctx['result_set'].append(loc)
                    added_locs.append(loc)

    return []
