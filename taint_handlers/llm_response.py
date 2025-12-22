import re

from if_extract import get_all_string_descendants, get_string_children, find_first_var_string


_IDENT_RE = re.compile(r'^[A-Za-z_][A-Za-z0-9_]*$')


def _pick_identifier(x: str) -> str:
    s = (x or '').strip()
    if not s:
        return ''
    if _IDENT_RE.match(s):
        return s
    return ''


def _call_name_from_children(call_id, nodes, children_of) -> str:
    ch = list(children_of.get(call_id, []) or [])
    ch.sort(key=lambda x: (nodes.get(x) or {}).get('childnum') if (nodes.get(x) or {}).get('childnum') is not None else 10**9)
    for c in ch:
        nc = nodes.get(c) or {}
        if (nc.get('type') or '').strip() == 'AST_NAME':
            ss = get_string_children(c, children_of, nodes)
            if ss:
                got = _pick_identifier(ss[0][1])
                if got:
                    return got
    for c in ch:
        nc = nodes.get(c) or {}
        if nc.get('labels') == 'string' or (nc.get('type') or '').strip() == 'string':
            vv = (nc.get('code') or nc.get('name') or '').strip()
            got = _pick_identifier(vv)
            if got:
                return got
    return ''


def _node_display(nid, nodes, children_of):
    nx = nodes.get(nid) or {}
    t = nx.get('type') or ''
    if t == 'AST_VAR':
        ss = get_string_children(nid, children_of, nodes)
        return t, (ss[0][1] if ss else '')
    if t == 'AST_METHOD_CALL':
        nm = _call_name_from_children(nid, nodes, children_of)
        if nm:
            return t, nm
        ss = get_string_children(nid, children_of, nodes)
        return t, (ss[0][1] if ss else (nx.get('code') or nx.get('name') or ''))
    if t == 'AST_CALL':
        nm = _call_name_from_children(nid, nodes, children_of)
        if nm:
            return t, nm
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


def _norm_llm_name(s: str) -> str:
    s = (s or '').strip()
    if not s:
        return ''
    s = s.replace(' ', '').replace('\t', '')
    if s.startswith('$'):
        s = s[1:]
    return s


_DIM_SHAPE_RE = re.compile(r'\[[^\]]*\]')
_PAREN_RE = re.compile(r'\([^)]*\)')


def _shape_name(s: str) -> str:
    v = _norm_llm_name(s)
    if not v:
        return ''
    v = v.replace('$', '')
    v = _DIM_SHAPE_RE.sub('[]', v)
    return v


def _rewrite_this_prefix(name: str, this_obj: str) -> str:
    v = (name or '').strip()
    o = (this_obj or '').strip()
    if not v or not o:
        return v
    if o.startswith('$'):
        o = o[1:]
    if v == 'this':
        return o
    if v.startswith('this->'):
        return o + v[4:]
    if v.startswith('this['):
        return o + v[4:]
    return v


def _llm_item_variants(it):
    if not isinstance(it, dict):
        return []
    try:
        seq = int(it.get('seq'))
    except Exception:
        return []
    tt = (it.get('type') or '').strip()
    nm = (it.get('name') or '').strip()
    if not nm:
        return []
    nm2 = nm.replace('.', '->') if tt in ('AST_PROP', 'AST_METHOD_CALL') else nm
    out = [{'seq': seq, 'type': tt, 'name': nm2}]
    if ('->' not in nm2) and ('[' not in nm2) and (']' not in nm2):
        return out
    parts = [p for p in nm2.split('->') if p]
    if parts:
        out.append({'seq': seq, 'type': 'AST_VAR', 'name': parts[0]})
    if len(parts) >= 2:
        base = parts[0]
        for prop in parts[1:]:
            if not prop:
                continue
            if '(' in prop:
                break
            base = f"{base}->{prop}"
            out.append({'seq': seq, 'type': 'AST_PROP', 'name': base})
    for m in re.finditer(r'\[([^\]]*)\]', nm2):
        inner = (m.group(1) or '').strip()
        if not inner:
            continue
        for tok in re.split(r'[^A-Za-z0-9_$]+', inner):
            tok = tok.strip()
            if not tok:
                continue
            if tok.startswith('$'):
                tok = tok[1:]
            got = _pick_identifier(tok)
            if got:
                out.append({'seq': seq, 'type': 'AST_VAR', 'name': got})
    return out


def _record_for_seq(seq, trace_index_records, seq_to_index):
    idx = seq_to_index.get(seq)
    if idx is not None and 0 <= idx < len(trace_index_records):
        return trace_index_records[idx]
    for r in trace_index_records:
        if seq in (r.get('seqs') or []):
            return r
    return None


def _node_source_str(nid, ntype, nodes, children_of):
    if ntype == 'AST_VAR':
        _, nm = _node_display(nid, nodes, children_of)
        return nm
    if ntype == 'AST_PROP':
        base = find_first_var_string(nid, children_of, nodes)
        ss = get_string_children(nid, children_of, nodes)
        prop = ss[0][1] if ss else ''
        if base and prop:
            return f"{base}->{prop}"
        _, nm = _node_display(nid, nodes, children_of)
        return nm.replace('.', '->')
    if ntype == 'AST_DIM':
        def sorted_children(xid):
            ch = list(children_of.get(xid, []) or [])
            ch.sort(key=lambda x: (nodes.get(x) or {}).get('childnum') if (nodes.get(x) or {}).get('childnum') is not None else 10**9)
            return ch

        def expr_str(xid, depth: int = 0) -> str:
            if xid is None or depth > 6:
                return ''
            nx = nodes.get(xid) or {}
            tt = (nx.get('type') or '').strip()
            if tt in ('AST_VAR', 'AST_PROP', 'AST_CALL', 'AST_METHOD_CALL'):
                return _node_source_str(xid, tt, nodes, children_of) or ''
            if tt == 'AST_DIM':
                ch = sorted_children(xid)
                if len(ch) >= 2:
                    base_s = expr_str(ch[0], depth + 1) or (find_first_var_string(xid, children_of, nodes) or '')
                    key_s = expr_str(ch[1], depth + 1)
                    if not key_s:
                        ss2 = get_string_children(xid, children_of, nodes)
                        key_s = ss2[0][1] if ss2 else ''
                    if base_s and key_s:
                        return f"{base_s}[{key_s}]"
                base = find_first_var_string(xid, children_of, nodes)
                ss3 = get_string_children(xid, children_of, nodes)
                key = ss3[0][1] if ss3 else ''
                if base and key:
                    return f"{base}[{key}]"
                _, nm = _node_display(xid, nodes, children_of)
                return nm
            if tt in ('AST_CONST', 'AST_NAME', 'string', 'integer', 'double'):
                _, nm = _node_display(xid, nodes, children_of)
                return nm
            _, nm = _node_display(xid, nodes, children_of)
            return nm

        s = expr_str(nid, 0)
        if s:
            return s
        _, nm = _node_display(nid, nodes, children_of)
        return nm
    if ntype == 'AST_CALL':
        _, nm = _node_display(nid, nodes, children_of)
        if nm and not nm.endswith('()'):
            nm = f"{nm}()"
        return nm
    if ntype == 'AST_METHOD_CALL':
        fn = _call_name_from_children(nid, nodes, children_of)
        recv = ''
        ch = list(children_of.get(nid, []) or [])
        ch.sort(key=lambda x: (nodes.get(x) or {}).get('childnum') if (nodes.get(x) or {}).get('childnum') is not None else 10**9)
        for c in ch:
            nc = nodes.get(c) or {}
            if not recv and nc.get('type') == 'AST_VAR':
                ss = get_string_children(c, children_of, nodes)
                recv = ss[0][1] if ss else ''
        if fn and not fn.endswith('()'):
            fn = f"{fn}()"
        return f"{recv}->{fn}" if recv else fn
    return ''


def _map_llm_item_to_node(it, ctx):
    nodes = ctx.get('nodes') or {}
    children_of = ctx.get('children_of') or {}
    recs = ctx.get('trace_index_records') or []
    seq_to_idx = ctx.get('trace_seq_to_index') or {}
    allowed = {'AST_VAR', 'AST_PROP', 'AST_DIM', 'AST_METHOD_CALL', 'AST_CALL'}
    lg = ctx.get('logger') if isinstance(ctx, dict) else None
    if not isinstance(it, dict):
        return None
    try:
        seq = int(it.get('seq'))
    except Exception:
        return None
    tt_guess = (it.get('type') or '').strip()
    nm = (it.get('name') or '').strip()
    if not nm:
        return None
    if tt_guess == 'AST_PROP':
        nm = nm.replace('.', '->')
    elif tt_guess == 'AST_METHOD_CALL':
        nm = nm.replace('.', '->')
    nm_n = _norm_llm_name(nm)
    nm_shape = _shape_name(nm)
    if not nm_n:
        return None
    if '(' in nm_n and ')' in nm_n:
        nm_n = _PAREN_RE.sub('()', nm_n)
    if tt_guess in ('AST_CALL', 'AST_METHOD_CALL') and not nm_n.endswith('()'):
        nm_n = f"{nm_n}()"
    rec = _record_for_seq(seq, recs, seq_to_idx)
    node_ids = rec.get('node_ids') if isinstance(rec, dict) else []
    cand_ids = list(node_ids or [])
    if lg is not None:
        lg.debug('llm_map_start', seq=seq, llm_type=tt_guess, llm_name=nm_n, node_ids_count=len(node_ids or []), expanded_ids_count=len(cand_ids or []))
    matches = []
    cand_preview = []
    for nid in cand_ids or []:
        nx = nodes.get(nid) or {}
        nt = (nx.get('type') or '').strip()
        if nt not in allowed:
            continue
        src = _node_source_str(nid, nt, nodes, children_of)
        if not src:
            continue
        src_n = _norm_llm_name(src)
        src_shape = _shape_name(src)
        if not src_n:
            continue
        if len(cand_preview) < 30:
            cand_preview.append({'id': nid, 'type': nt, 'src': src, 'src_n': src_n})
        score = 0
        if src_n == nm_n:
            score = 3
        elif nt == 'AST_METHOD_CALL':
            if src_n.endswith(nm_n) or nm_n.endswith(src_n):
                score = 2
            elif nm_n.endswith('()') and src_n.endswith('->' + nm_n):
                score = 2
        elif nt in ('AST_PROP', 'AST_DIM'):
            if src_shape and nm_shape and (src_shape == nm_shape):
                score = 2
            elif len(src_shape) >= 4 and len(nm_shape) >= 4 and (src_shape in nm_shape or nm_shape in src_shape):
                score = 1
            elif len(src_n) >= 4 and len(nm_n) >= 4 and (src_n in nm_n or nm_n in src_n):
                score = 1
        elif nt == 'AST_CALL':
            if len(src_n) >= 4 and len(nm_n) >= 4 and (src_n in nm_n or nm_n in src_n):
                score = 1
        if score > 0:
            matches.append({'id': nid, 'type': nt, 'seq': seq, 'name': src, '_score': score})
    if not matches:
        if lg is not None:
            lg.log_json('DEBUG', 'llm_map_no_match_candidates', {'seq': seq, 'llm_type': tt_guess, 'llm_name': nm_n, 'candidates': cand_preview})
        return None
    best_score = max(m.get('_score') or 0 for m in matches)
    best = [m for m in matches if (m.get('_score') or 0) == best_score]
    if len(best) == 1:
        picked = best[0]
        if lg is not None:
            lg.debug('llm_map_picked', seq=seq, llm_type=tt_guess, llm_name=nm_n, picked_id=picked.get('id'), picked_type=picked.get('type'), picked_name=picked.get('name'), score=best_score)
        return {'id': picked['id'], 'type': picked['type'], 'seq': picked['seq'], 'name': picked['name']}
    types = set(m.get('type') for m in best if m.get('type'))
    if len(types) > 1 and tt_guess in allowed:
        cand = [m for m in best if m.get('type') == tt_guess]
        if cand:
            picked = cand[0]
            if lg is not None:
                lg.debug('llm_map_picked_by_llm_type', seq=seq, llm_type=tt_guess, llm_name=nm_n, picked_id=picked.get('id'), picked_type=picked.get('type'), picked_name=picked.get('name'), score=best_score)
            return {'id': picked['id'], 'type': picked['type'], 'seq': picked['seq'], 'name': picked['name']}
    preferred = None
    if '->' in nm_n and nm_n.endswith('()'):
        preferred = 'AST_METHOD_CALL'
    elif nm_n.endswith('()'):
        preferred = 'AST_CALL'
    elif '[' in nm_n and ']' in nm_n:
        preferred = 'AST_DIM'
    elif '->' in nm_n:
        preferred = 'AST_PROP'
    else:
        preferred = 'AST_VAR'
    cand2 = [m for m in best if m.get('type') == preferred]
    if not cand2 and preferred != 'AST_VAR':
        cand2 = [m for m in best if m.get('type') == 'AST_VAR']
    if cand2:
        cand2.sort(key=lambda m: int(m.get('id') or 10**18))
        picked = cand2[0]
        return {'id': picked['id'], 'type': picked['type'], 'seq': picked['seq'], 'name': picked['name']}
    best.sort(key=lambda m: int(m.get('id') or 10**18))
    picked = best[0]
    return {'id': picked['id'], 'type': picked['type'], 'seq': picked['seq'], 'name': picked['name']}


def map_llm_taints_to_nodes(llm_taints, ctx):
    out = []
    seen = set()
    for it in llm_taints or []:
        for v in _llm_item_variants(it):
            mapped = _map_llm_item_to_node(v, ctx)
            if not mapped:
                continue
            k = (int(mapped.get('id')), int(mapped.get('seq')))
            if k in seen:
                continue
            seen.add(k)
            out.append(mapped)
    return out


def _expand_var_components(taint_node: dict, ctx) -> list:
    if not isinstance(taint_node, dict) or not isinstance(ctx, dict):
        return []
    nid = taint_node.get('id')
    nseq = taint_node.get('seq')
    if nid is None or nseq is None:
        return []
    try:
        nid_i = int(nid)
        seq_i = int(nseq)
    except Exception:
        return []
    nodes = ctx.get('nodes') or {}
    children_of = ctx.get('children_of') or {}

    def sorted_children(xid: int) -> list:
        ch = list(children_of.get(xid, []) or [])
        ch.sort(key=lambda x: (nodes.get(x) or {}).get('childnum') if (nodes.get(x) or {}).get('childnum') is not None else 10**9)
        return ch

    out = []
    seen_ids = set()
    q = [nid_i]
    cap = 2000
    while q and len(seen_ids) < cap:
        x = q.pop()
        if x in seen_ids:
            continue
        seen_ids.add(x)
        nx = nodes.get(x) or {}
        tt = (nx.get('type') or '').strip()
        if tt in ('AST_VAR', 'AST_PROP', 'AST_DIM'):
            nm = _node_source_str(x, tt, nodes, children_of)
            if nm:
                out.append({'id': x, 'type': tt, 'seq': seq_i, 'name': nm})
        for c in sorted_children(x):
            if c not in seen_ids:
                q.append(c)
    return out


def _map_llm_node_cached(node, cache, ctx):
    if not isinstance(node, dict):
        return None
    nm = (node.get('name') or '').strip()
    if not nm:
        return None
    tt = (node.get('type') or '').strip()
    if tt == 'AST_PROP':
        nm = nm.replace('.', '->')
    elif tt == 'AST_METHOD_CALL':
        nm = nm.replace('.', '->')
    nm_n = _norm_llm_name(nm)
    try:
        seq = int(node.get('seq'))
    except Exception:
        return None
    k = (seq, tt, nm_n)
    if k in cache:
        return cache.get(k)
    out = _map_llm_item_to_node({'seq': seq, 'type': tt, 'name': nm}, ctx)
    cache[k] = out
    return out


def map_llm_edges_to_nodes(llm_edges, ctx):
    cache = ctx.setdefault('_llm_node_map_cache', {})
    out = []
    for e in llm_edges or []:
        if not isinstance(e, dict):
            continue
        src = e.get('src')
        dst = e.get('dst')
        msrc = _map_llm_node_cached(src, cache, ctx)
        mdst = _map_llm_node_cached(dst, cache, ctx)
        if not msrc or not mdst:
            continue
        out.append({'src': msrc, 'dst': mdst})
    return out

