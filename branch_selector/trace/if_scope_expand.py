import os
import sys
import bisect
from typing import Iterable

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from analyze_if_line import read_trace_line, extract_if_elements_fast, build_initial_taints, parse_loc
from extractors.if_extract import norm_trace_path
from taint_handlers import REGISTRY
from taint_handlers.llm.core.llm_response import _node_source_str_with_this, _norm_llm_name
from cpg_utils.graph_mapping import get_string_children
from llm_utils.prompts.prompt_utils import build_seqs_by_loc


_ALLOWED_TYPES = {'AST_VAR', 'AST_PROP', 'AST_DIM', 'AST_METHOD_CALL', 'AST_CALL', 'AST_STATIC_CALL', 'AST_PARAM'}


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


def _build_node_to_min_seq(trace_index_records: Iterable[dict]) -> dict[int, int]:
    out: dict[int, int] = {}
    for rec in trace_index_records or []:
        seqs = []
        for s in rec.get('seqs') or []:
            try:
                seqs.append(int(s))
            except Exception:
                continue
        if not seqs:
            continue
        min_seq = min(seqs)
        for nid in rec.get('node_ids') or []:
            try:
                nid_i = int(nid)
            except Exception:
                continue
            prev = out.get(nid_i)
            if prev is None or min_seq < int(prev):
                out[nid_i] = int(min_seq)
    return out


def _build_funcid_to_path(trace_index_records: Iterable[dict], nodes: dict) -> dict[int, str]:
    out: dict[int, str] = {}
    for rec in trace_index_records or []:
        p = (rec.get('path') or '').strip()
        if not p:
            continue
        for nid in rec.get('node_ids') or []:
            try:
                nid_i = int(nid)
            except Exception:
                continue
            nx = nodes.get(nid_i) or {}
            funcid = nx.get('funcid')
            try:
                funcid_i = int(funcid) if funcid is not None else None
            except Exception:
                funcid_i = None
            if funcid_i is not None and funcid_i not in out:
                out[funcid_i] = p
            nt = (nx.get('type') or '').strip()
            if nt in ('AST_METHOD', 'AST_FUNC_DECL') and nid_i not in out:
                out[nid_i] = p
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
    if t == 'AST_PARAM':
        nm = _normalize_name(v)
        return [('AST_VAR', nm)] if nm else []
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
    def _loc_strings(items: list) -> list[str]:
        buf: list[str] = []
        for loc in items or []:
            if isinstance(loc, str):
                if loc.strip():
                    buf.append(loc.strip())
                continue
            if isinstance(loc, dict):
                if loc.get('loc'):
                    s = str(loc.get('loc')).strip()
                    if s:
                        buf.append(s)
                    continue
                p = (loc.get('path') or '').strip()
                ln = loc.get('line')
                if p and ln is not None:
                    try:
                        buf.append(f"{p}:{int(ln)}")
                    except Exception:
                        pass
        return buf

    def _append_unique_str_items(dst: list, items: list[str], *, seen: set[str]) -> None:
        for s in items or []:
            ss = (s or '').strip()
            if not ss or ss in seen:
                continue
            dst.append(ss)
            seen.add(ss)

    def _expand_includes(items: list) -> None:
        locs = _loc_strings(items)
        if not locs:
            return
        try:
            from taint_handlers.handlers.helpers.ast_var_include import expand_includes_in_locs

            extra_includes, _ = expand_includes_in_locs(locs=list(locs), ctx=ctx)
            if extra_includes:
                _append_unique_str_items(items, list(extra_includes), seen=set(locs))
        except Exception:
            return

    def _extend_includers(items: list) -> None:
        locs = _loc_strings(items)
        if not locs:
            return
        nodes = ctx.get('nodes') or {}
        trace_index_records = ctx.get('trace_index_records') or []
        if not nodes or not trace_index_records:
            return
        loc_to_records = _build_loc_to_records(trace_index_records)
        idx_to_pos = {}
        for pos, rec in enumerate(trace_index_records):
            idx = rec.get('index')
            try:
                idx_to_pos[int(idx)] = int(pos)
            except Exception:
                continue
        ref_seq = ctx.get('input_seq')
        try:
            ref_seq_i = int(ref_seq) if ref_seq is not None else None
        except Exception:
            ref_seq_i = None

        def _rec_min_seq(rec: dict) -> int | None:
            seqs = (rec or {}).get('seqs') or []
            if not seqs:
                return None
            try:
                return int(min(int(s) for s in seqs))
            except Exception:
                return None

        def _pick_best_rec(candidates: list[dict]) -> dict | None:
            if not candidates:
                return None
            if ref_seq_i is None:
                keyed = [(int(_rec_min_seq(r) or 10**18), int(r.get('index') or 10**18), r) for r in candidates]
                keyed.sort(key=lambda x: (x[0], x[1]))
                return keyed[0][2] if keyed else None
            before = []
            after = []
            for c in candidates:
                ms = _rec_min_seq(c)
                if ms is None:
                    continue
                if int(ms) <= int(ref_seq_i):
                    before.append((int(ms), int(c.get('index') or 10**18), c))
                else:
                    after.append((int(ms), int(c.get('index') or 10**18), c))
            if before:
                before.sort(key=lambda x: (-x[0], x[1]))
                return before[0][2]
            if after:
                after.sort(key=lambda x: (x[0], x[1]))
                return after[0][2]
            return candidates[0]

        try:
            from taint_handlers.handlers.expr.ast_var import _collect_scope_recs_and_locs_raw, _extend_include_scope_from_file_head
        except Exception:
            return

        seen = set(locs)
        extra_all: list[str] = []
        for loc in locs:
            pr = parse_loc(loc)
            if not pr:
                continue
            recs = loc_to_records.get(pr) or []
            if not recs:
                continue
            rec = _pick_best_rec(recs)
            if not isinstance(rec, dict):
                continue
            idx = rec.get('index')
            try:
                pos = idx_to_pos.get(int(idx)) if idx is not None else None
            except Exception:
                pos = None
            if pos is None or not (0 <= int(pos) < len(trace_index_records)):
                continue
            node_ids = rec.get('node_ids') or []
            nid0 = node_ids[0] if node_ids else None
            try:
                fid = int((nodes.get(int(nid0)) or {}).get('funcid')) if nid0 is not None else None
            except Exception:
                fid = None
            if fid is None:
                continue
            _, _, stop_info = _collect_scope_recs_and_locs_raw(start_idx=int(pos), funcid=int(fid), ctx=ctx)
            stop_by = stop_info.get('stop_by')
            stop_index = stop_info.get('stop_index')
            if stop_by != 'toplevel_stop' or not isinstance(stop_index, int):
                continue
            extra2 = _extend_include_scope_from_file_head(stop_index=int(stop_index), funcid=int(fid), ctx=ctx)
            if extra2:
                for s in extra2:
                    ss = (s or '').strip()
                    if not ss or ss in seen:
                        continue
                    extra_all.append(ss)
                    seen.add(ss)
        if extra_all:
            items.extend(extra_all)

    _expand_includes(out)
    _extend_includers(out)
    _expand_includes(out)
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
        min_seq = None
        if isinstance(loc, dict) and loc.get('seq') is not None:
            try:
                min_seq = int(loc.get('seq'))
            except Exception:
                min_seq = None
        if min_seq is None:
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
                nm = ''
                if tt == 'AST_PARAM':
                    ss = get_string_children(nid_i, children_of, nodes)
                    nm = (ss[0][1] if ss else '')
                else:
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
    loc_to_seqs = build_seqs_by_loc(trace_index_records)
    node_to_min_seq = _build_node_to_min_seq(trace_index_records)
    funcid_to_path = _build_funcid_to_path(trace_index_records, nodes)
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
        extra_scope_locs = []
        for nid in st.get('targets') or []:
            try:
                nid_i = int(nid)
            except Exception:
                continue
            funcid = (nodes.get(nid_i) or {}).get('funcid')
            if funcid is None:
                continue
            try:
                funcid_i = int(funcid)
            except Exception:
                continue
            ftype = ((nodes.get(int(funcid_i)) or {}).get('type') or '').strip()
            if ftype not in ('AST_METHOD', 'AST_FUNC_DECL'):
                continue
            func_line = (nodes.get(int(funcid_i)) or {}).get('lineno')
            func_path = funcid_to_path.get(int(funcid_i))
            if func_path and func_line is not None:
                func_seq = None
                key = _loc_key(func_path, func_line)
                if key is not None:
                    seqs = loc_to_seqs.get(key) or []
                    if seqs:
                        pos = bisect.bisect_left(seqs, int(seq_i))
                        if pos <= 0:
                            func_seq = int(seqs[0])
                        elif pos >= len(seqs):
                            func_seq = int(seqs[-1])
                        else:
                            left = int(seqs[pos - 1])
                            right = int(seqs[pos])
                            func_seq = left if (int(seq_i) - left) <= (right - int(seq_i)) else right
                if func_seq is None:
                    func_seq = node_to_min_seq.get(int(funcid_i))
                loc = {'path': str(func_path), 'line': int(func_line)}
                if func_seq is not None:
                    loc['seq'] = int(func_seq)
                extra_scope_locs.append(loc)
                break
        for t in taints:
            tt = (t.get('type') or '').strip()
            if tt not in _ALLOWED_TYPES:
                continue
            tn = _taint_name(t)
            target_parts = set(_split_var_parts(tt, tn))
            if not target_parts:
                continue
            scope_locs = _collect_scope_locs(t, base_ctx)
            if extra_scope_locs:
                scope_locs = list(scope_locs or []) + list(extra_scope_locs)
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
