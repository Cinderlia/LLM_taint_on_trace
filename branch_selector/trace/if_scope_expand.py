import os
import sys
from typing import Iterable

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from analyze_if_line import read_trace_line, extract_if_elements_fast, build_initial_taints, parse_loc
from extractors.if_extract import norm_trace_path
from taint_handlers import REGISTRY
from taint_handlers.llm.core.llm_response import _node_source_str_with_this, _norm_llm_name


_ALLOWED_TYPES = {'AST_VAR', 'AST_PROP', 'AST_DIM', 'AST_METHOD_CALL', 'AST_CALL', 'AST_STATIC_CALL'}


def _loc_key(path: str, line: int) -> tuple[str, int] | None:
    if not path or line is None:
        return None
    try:
        ln = int(line)
    except Exception:
        return None
    return norm_trace_path(path), ln


def _loc_to_path_line(loc) -> tuple[str, int] | None:
    if isinstance(loc, dict):
        p = loc.get('path')
        ln = loc.get('line')
        if p and ln is not None:
            return _loc_key(p, ln)
        if loc.get('loc'):
            pr = parse_loc(loc.get('loc'))
            if pr:
                return pr
        return None
    if isinstance(loc, str):
        return parse_loc(loc)
    return None


def _build_loc_to_records(trace_index_records: Iterable[dict]) -> dict[tuple[str, int], list[dict]]:
    out: dict[tuple[str, int], list[dict]] = {}
    for rec in trace_index_records or []:
        p = rec.get('path')
        ln = rec.get('line')
        key = _loc_key(p, ln)
        if not key:
            continue
        out.setdefault(key, []).append(rec)
    return out


def _build_loc_to_min_seq(trace_index_records: Iterable[dict]) -> dict[tuple[str, int], int]:
    out: dict[tuple[str, int], int] = {}
    for rec in trace_index_records or []:
        p = rec.get('path')
        ln = rec.get('line')
        key = _loc_key(p, ln)
        if not key:
            continue
        seqs = []
        for s in rec.get('seqs') or []:
            try:
                seqs.append(int(s))
            except Exception:
                continue
        if not seqs:
            continue
        cur = min(seqs)
        prev = out.get(key)
        if prev is None or cur < prev:
            out[key] = cur
    return out


def _strip_call_parens(name: str) -> str:
    v = (name or '').strip()
    if v.endswith('()'):
        return v[:-2]
    return v


def _normalize_name(name: str) -> str:
    return _norm_llm_name((name or '').replace('.', '->'))


def _split_prop_like(name: str) -> tuple[str, str]:
    v = (name or '').replace('.', '->')
    if '->' not in v:
        return v, ''
    left, right = v.split('->', 1)
    return left, right


def _split_static_call(name: str) -> tuple[str, str]:
    v = (name or '').replace(' ', '').replace('\t', '')
    v = v.replace('$', '')
    if '::' in v:
        left, right = v.split('::', 1)
        return left, right
    if ':' in v:
        left, right = v.split(':', 1)
        return left, right
    return v, ''


def _split_dim_base(name: str) -> str:
    v = (name or '').strip().replace('.', '->')
    if '[' in v:
        v = v.split('[', 1)[0].strip()
    return v


def _split_var_parts(tt: str, name: str) -> list[tuple[str, str]]:
    t = (tt or '').strip()
    v = (name or '').strip()
    if not t or not v:
        return []
    if t == 'AST_VAR':
        nm = _normalize_name(v)
        return [(t, nm)] if nm else []
    if t == 'AST_DIM':
        base = _split_dim_base(v)
        nm = _normalize_name(base)
        return [(t, nm)] if nm else []
    if t == 'AST_PROP':
        left, right = _split_prop_like(v)
        out = []
        left_n = _normalize_name(left)
        right_n = _normalize_name(right)
        if left_n:
            out.append((t, left_n))
        if right_n:
            out.append((t, right_n))
        return out
    if t == 'AST_METHOD_CALL':
        left, right = _split_prop_like(v)
        out = []
        left_n = _normalize_name(left)
        right_n = _normalize_name(_strip_call_parens(right))
        if left_n:
            out.append((t, left_n))
        if right_n:
            out.append((t, right_n))
        if not out:
            nm = _normalize_name(_strip_call_parens(v))
            if nm:
                out.append((t, nm))
        return out
    if t == 'AST_CALL':
        nm = _normalize_name(_strip_call_parens(v))
        return [(t, nm)] if nm else []
    if t == 'AST_STATIC_CALL':
        left, right = _split_static_call(v)
        out = []
        left_n = _normalize_name(left)
        right_n = _normalize_name(_strip_call_parens(right))
        if left_n:
            out.append((t, left_n))
        if right_n:
            out.append((t, right_n))
        return out
    return []


def _taint_name(taint: dict) -> str:
    tt = (taint.get('type') or '').strip()
    if tt == 'AST_PROP':
        base = (taint.get('base') or '').strip()
        prop = (taint.get('prop') or '').strip()
        if base and prop:
            return f"{base}->{prop}"
    if tt == 'AST_DIM':
        base = (taint.get('base') or '').strip()
        if base:
            return base
    if tt == 'AST_METHOD_CALL':
        recv = (taint.get('recv') or '').strip()
        name = (taint.get('name') or '').strip()
        if name and not name.endswith('()'):
            name = f"{name}()"
        if recv and name:
            return f"{recv}->{name}"
        return name
    return (taint.get('name') or '').strip()


def _build_ctx_for_seq(
    *,
    seq: int,
    st: dict,
    nodes: dict,
    parent_of: dict,
    children_of: dict,
    trace_index_records: list[dict],
    seq_to_index: dict[int, int],
    scope_root: str,
    windows_root: str,
) -> dict:
    return {
        'input_seq': int(seq),
        'path': st.get('path'),
        'line': st.get('line'),
        'targets': st.get('targets'),
        'result': st.get('result'),
        'nodes': nodes,
        'children_of': children_of,
        'parent_of': parent_of,
        'trace_index_records': trace_index_records,
        'trace_seq_to_index': seq_to_index,
        'scope_root': scope_root,
        'windows_root': windows_root,
        'llm_enabled': False,
        'llm_scope_debug': False,
        'debug': {},
        'logger': None,
        'result_set': [],
    }


def _collect_scope_locs(taint: dict, base_ctx: dict) -> list:
    tt = (taint.get('type') or '').strip()
    handler = REGISTRY.get(tt)
    if handler is None:
        return []
    ctx = dict(base_ctx)
    ctx['result_set'] = []
    ctx.pop('_llm_extra_prompt_locs', None)
    try:
        handler(taint, ctx)
    except Exception:
        return []
    out = list(ctx.get('result_set') or [])
    extra = ctx.get('_llm_extra_prompt_locs') or []
    if extra:
        out.extend(list(extra))
    return out


def _match_scope_nodes(
    *,
    target_parts: set[tuple[str, str]],
    scope_locs: Iterable,
    nodes: dict,
    children_of: dict,
    loc_to_records: dict[tuple[str, int], list[dict]],
    loc_to_min_seq: dict[tuple[str, int], int],
) -> set[int]:
    out: set[int] = set()
    if not target_parts:
        return out
    for loc in scope_locs or []:
        pr = _loc_to_path_line(loc)
        if not pr:
            continue
        recs = loc_to_records.get(pr) or []
        if not recs:
            continue
        min_seq = loc_to_min_seq.get(pr)
        if min_seq is None:
            continue
        for rec in recs:
            for nid in rec.get('node_ids') or []:
                try:
                    nid_i = int(nid)
                except Exception:
                    continue
                nx = nodes.get(nid_i) or {}
                tt = (nx.get('type') or '').strip()
                if tt not in _ALLOWED_TYPES:
                    continue
                nm = _node_source_str_with_this(nid_i, tt, nodes, children_of, '')
                if not nm:
                    continue
                parts = _split_var_parts(tt, nm)
                if not parts:
                    continue
                if any((p_tt, p_nm) in target_parts for p_tt, p_nm in parts):
                    out.add(int(min_seq))
                    break
            if int(min_seq) in out:
                break
    return out


def _select_near_far(
    seqs: Iterable[int],
    *,
    ref_seq: int,
    near_count: int,
    far_count: int,
) -> list[int]:
    items = []
    for s in seqs or []:
        try:
            items.append(int(s))
        except Exception:
            continue
    if not items:
        return []
    near_n = max(0, int(near_count))
    far_n = max(0, int(far_count))
    if near_n == 0 and far_n == 0:
        return sorted(set(items))
    uniq = sorted(set(items))
    if len(uniq) <= near_n + far_n:
        return uniq
    by_dist = sorted(uniq, key=lambda s: (abs(int(s) - int(ref_seq)), int(s)))
    near_pick = by_dist[:near_n] if near_n > 0 else []
    far_pick = list(reversed(by_dist))[:far_n] if far_n > 0 else []
    return sorted(set(near_pick + far_pick))


def expand_if_seq_groups(
    *,
    seq_groups: dict[int, list[int]],
    trace_index_records: list[dict],
    nodes: dict,
    parent_of: dict,
    children_of: dict,
    trace_path: str,
    scope_root: str,
    windows_root: str,
    nearest_seq_count: int = 3,
    farthest_seq_count: int = 3,
) -> dict[int, list[int]]:
    seq_to_index = {}
    for rec in trace_index_records or []:
        idx = rec.get('index')
        for s in rec.get('seqs') or []:
            try:
                si = int(s)
            except Exception:
                continue
            if si not in seq_to_index:
                seq_to_index[si] = int(idx) if idx is not None else 0
    loc_to_records = _build_loc_to_records(trace_index_records)
    loc_to_min_seq = _build_loc_to_min_seq(trace_index_records)
    out: dict[int, list[int]] = {}
    for seq, rel_seqs in seq_groups.items():
        try:
            seq_i = int(seq)
        except Exception:
            continue
        arg = read_trace_line(seq_i, trace_path)
        if not arg:
            out[seq_i] = list(rel_seqs or []) or [seq_i]
            continue
        st = extract_if_elements_fast(arg, seq_i, nodes, children_of, trace_index_records, seq_to_index)
        if not (st.get('targets') or []):
            out[seq_i] = list(rel_seqs or []) or [seq_i]
            continue
        st['seq'] = seq_i
        taints = build_initial_taints(st, nodes, children_of, parent_of)
        if not taints:
            out[seq_i] = list(rel_seqs or []) or [seq_i]
            continue
        base_ctx = _build_ctx_for_seq(
            seq=seq_i,
            st=st,
            nodes=nodes,
            parent_of=parent_of,
            children_of=children_of,
            trace_index_records=trace_index_records,
            seq_to_index=seq_to_index,
            scope_root=scope_root,
            windows_root=windows_root,
        )
        seq_set = {seq_i}
        for t in taints:
            tt = (t.get('type') or '').strip()
            if tt not in _ALLOWED_TYPES:
                continue
            tn = _taint_name(t)
            target_parts = set(_split_var_parts(tt, tn))
            if not target_parts:
                continue
            scope_locs = _collect_scope_locs(t, base_ctx)
            matches = _match_scope_nodes(
                target_parts=target_parts,
                scope_locs=scope_locs,
                nodes=nodes,
                children_of=children_of,
                loc_to_records=loc_to_records,
                loc_to_min_seq=loc_to_min_seq,
            )
            seq_set.update(matches)
        rest = [x for x in seq_set if x != seq_i]
        picked = _select_near_far(
            rest,
            ref_seq=seq_i,
            near_count=nearest_seq_count,
            far_count=farthest_seq_count,
        )
        out[seq_i] = sorted({seq_i, *picked})
    return out
