"""
Entry-point script for analyzing a single trace line (seq) and expanding taints.

This script:
- Locates `AST_IF_ELEM` nodes corresponding to a trace log line.
- Extracts variables/props/dims/calls under the condition element.
- Runs taint expansion using rule-based handlers, optionally augmented by LLM.
"""

import os
import sys
import json
import bisect
import shutil
from common.app_config import load_app_config
from common.logger import Logger
from utils.extractors.if_extract import (
    norm_trace_path,
    collect_descendants,
    load_nodes,
    load_ast_edges,
    get_string_children,
    get_all_string_descendants,
    find_first_var_string,
)
from taint_handlers import REGISTRY
from taint_handlers.llm.core.llm_process import process_taints_llm
from utils.trace_utils.trace_edges import build_trace_index_records, load_trace_index_records, save_trace_index_records
from llm_utils.prompts.symbolic_prompt import generate_symbolic_execution_prompt
from llm_utils.symbolic_runner import (
    build_symbolic_response_example,
    load_symbolic_solution_defaults,
    parse_symbolic_response,
    run_symbolic_prompt,
    write_symbolic_prompt,
    write_symbolic_response,
    write_symbolic_solution_outputs,
)

def _safe_rmtree(p: str) -> None:
    """Best-effort recursive delete for a directory path."""
    if not p:
        return
    if not os.path.exists(p):
        return
    try:
        shutil.rmtree(p)
    except Exception:
        return


def clean_previous_test_outputs(test_dir: str, seq: int | None = None) -> None:
    """Remove prior test outputs (logs/prompts/rounds and optional output json) for a run."""
    if not test_dir:
        return
    try:
        os.makedirs(test_dir, exist_ok=True)
    except Exception:
        pass
    _safe_rmtree(os.path.join(test_dir, 'logs'))
    _safe_rmtree(os.path.join(test_dir, 'rounds'))
    _safe_rmtree(os.path.join(test_dir, 'symbolic'))
    if isinstance(test_dir, str) and test_dir:
        try:
            os.makedirs(os.path.join(test_dir, 'llm'), exist_ok=True)
        except Exception:
            pass
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


def clean_llm_io_dirs(test_dir: str, *, llm_mode: bool, llm_test_mode: bool) -> None:
    if not test_dir or not llm_mode:
        return
    _safe_rmtree(os.path.join(test_dir, 'llm', 'prompts'))
    if not llm_test_mode:
        _safe_rmtree(os.path.join(test_dir, 'llm', 'responses'))


def _resolve_output_root(cfg) -> str:
    raw = cfg.raw if hasattr(cfg, 'raw') else {}
    paths = raw.get('paths') if isinstance(raw, dict) else {}
    output_dir = ''
    if isinstance(paths, dict):
        output_dir = paths.get('output_dir') or ''
    if not output_dir and isinstance(raw, dict):
        output_dir = raw.get('output_dir') or ''
    output_dir = (output_dir or 'output').strip()
    if not output_dir:
        output_dir = 'output'
    if os.path.isabs(output_dir):
        return os.path.abspath(output_dir)
    return os.path.abspath(os.path.join(cfg.base_dir, output_dir))
 
def read_trace_line(n, trace_path: str | None = None):
    """Read `trace.log` line N and return a normalized `path:line` locator string."""
    p = trace_path or os.path.join(os.getcwd(), 'trace.log')
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
    """Return a best-effort `(type, name)` display for a CPG node id."""
    nx = nodes.get(nid) or {}
    t = nx.get('type') or ''
    def sorted_children(xid: int) -> list[int]:
        ch = list(children_of.get(int(xid), []) or [])
        ch.sort(key=lambda x: (nodes.get(x) or {}).get('childnum') if (nodes.get(x) or {}).get('childnum') is not None else 10**9)
        out = []
        for c in ch:
            try:
                out.append(int(c))
            except Exception:
                continue
        return out
    def static_call_name(call_id: int) -> str:
        class_name = ''
        method_name = ''
        for c in sorted_children(int(call_id)):
            cx = nodes.get(c) or {}
            ct = (cx.get('type') or '').strip()
            if ct == 'AST_NAME' and not class_name:
                ss = get_string_children(c, children_of, nodes)
                class_name = (ss[0][1] if ss else '').strip()
                continue
            if not method_name and (cx.get('labels') == 'string' or ct == 'string'):
                v = (cx.get('code') or cx.get('name') or '').strip()
                if v:
                    method_name = v
        if class_name and method_name:
            return f"{class_name}::{method_name}"
        return method_name or class_name
    def expr_str(xid: int | None, depth: int = 0, seen: set[int] | None = None) -> str:
        if xid is None:
            return ''
        try:
            x = int(xid)
        except Exception:
            return ''
        if depth > 10:
            return ''
        if seen is None:
            seen = set()
        if x in seen:
            return ''
        seen.add(x)
        xx = nodes.get(x) or {}
        tt = (xx.get('type') or '').strip()
        if tt == 'AST_VAR':
            ss = get_string_children(x, children_of, nodes)
            return (ss[0][1] if ss else '').strip()
        if tt == 'AST_PROP':
            base_id = None
            prop_token = ''
            for c in sorted_children(x):
                cx = nodes.get(c) or {}
                ctt = (cx.get('type') or '').strip()
                if ctt == 'AST_ARG_LIST':
                    continue
                if cx.get('labels') == 'string' or ctt == 'string':
                    v = (cx.get('code') or cx.get('name') or '').strip()
                    if v and not prop_token:
                        prop_token = v
                    continue
                if base_id is None:
                    base_id = c
            base_s = expr_str(base_id, depth + 1, seen) if base_id is not None else ''
            if not base_s:
                base_s = (find_first_var_string(x, children_of, nodes) or '').strip()
            if not prop_token:
                ss = get_string_children(x, children_of, nodes)
                prop_token = (ss[0][1] if ss else '').strip()
            if base_s and prop_token:
                return f"{base_s}->{prop_token}"
            return (xx.get('code') or xx.get('name') or '').strip().replace('.', '->')
        if tt == 'AST_DIM':
            ch = sorted_children(x)
            base_id = ch[0] if len(ch) >= 1 else None
            key_id = ch[1] if len(ch) >= 2 else None
            base_s = expr_str(base_id, depth + 1, seen) if base_id is not None else ''
            if not base_s:
                base_s = (find_first_var_string(x, children_of, nodes) or '').strip()
            key_s = expr_str(key_id, depth + 1, seen) if key_id is not None else ''
            if not key_s:
                ss = get_string_children(x, children_of, nodes)
                key_s = (ss[0][1] if ss else '').strip()
            if base_s and key_s:
                return f"{base_s}[{key_s}]"
            return (xx.get('code') or xx.get('name') or '').strip().replace('.', '->')
        if tt == 'AST_METHOD_CALL':
            fn = ''
            recv_id = None
            for c in sorted_children(x):
                cx = nodes.get(c) or {}
                ctt = (cx.get('type') or '').strip()
                if ctt == 'AST_ARG_LIST':
                    continue
                if cx.get('labels') == 'string' or ctt == 'string':
                    v = (cx.get('code') or cx.get('name') or '').strip()
                    if v and not fn:
                        fn = v
                    continue
                if recv_id is None:
                    recv_id = c
            recv = expr_str(recv_id, depth + 1, seen) if recv_id is not None else ''
            if fn and not fn.endswith('()'):
                fn = f"{fn}()"
            if recv:
                recv = recv.replace('.', '->')
            return f"{recv}->{fn}" if recv and fn else (fn or '')
        if tt == 'AST_CALL':
            fn = ''
            for c in sorted_children(x):
                cx = nodes.get(c) or {}
                ctt = (cx.get('type') or '').strip()
                if ctt == 'AST_ARG_LIST':
                    continue
                if cx.get('labels') == 'string' or ctt == 'string':
                    v = (cx.get('code') or cx.get('name') or '').strip()
                    if v and not fn:
                        fn = v
                if ctt == 'AST_NAME' and not fn:
                    ss = get_string_children(c, children_of, nodes)
                    if ss:
                        fn = (ss[0][1] or '').strip()
            if fn and not fn.endswith('()'):
                fn = f"{fn}()"
            return fn
        if tt == 'AST_STATIC_CALL':
            fn = static_call_name(x)
            if fn and not fn.endswith('()'):
                fn = f"{fn}()"
            return fn
        if tt in ('AST_CONST', 'AST_NAME', 'string', 'integer', 'double'):
            ss = get_all_string_descendants(x, children_of, nodes)
            if ss:
                return (ss[0][1] or '').strip()
            return (xx.get('code') or xx.get('name') or '').strip()
        return (xx.get('code') or xx.get('name') or '').strip().replace('.', '->')
    if t == 'AST_VAR':
        ss = get_string_children(nid, children_of, nodes)
        return t, (ss[0][1] if ss else '')
    if t == 'AST_METHOD_CALL':
        ss = get_string_children(nid, children_of, nodes)
        return t, (ss[0][1] if ss else (nx.get('code') or nx.get('name') or ''))
    if t == 'AST_CALL':
        ss = get_all_string_descendants(nid, children_of, nodes)
        return t, (ss[0][1] if ss else (nx.get('code') or nx.get('name') or ''))
    if t == 'AST_STATIC_CALL':
        nm = static_call_name(int(nid))
        if nm:
            return t, nm
        ss = get_all_string_descendants(nid, children_of, nodes)
        return t, (ss[0][1] if ss else (nx.get('code') or nx.get('name') or ''))
    if t == 'AST_PROP':
        return t, expr_str(int(nid))
    if t == 'AST_DIM':
        return t, expr_str(int(nid))
    if t in ('AST_CONST', 'AST_NAME', 'string', 'integer', 'double'):
        ss = get_all_string_descendants(nid, children_of, nodes)
        if ss:
            return t, ss[0][1]
        return t, (nx.get('code') or nx.get('name') or '')
    return t, (nx.get('code') or nx.get('name') or '')
 
def dim_index_roots(dim_id, nodes, children_of):
    """Return index expression roots for an `AST_DIM` node (excluding the base)."""
    ch = list(children_of.get(dim_id, []) or [])
    if len(ch) < 2:
        return []
    ch.sort(key=lambda x: (nodes.get(x) or {}).get('childnum') if (nodes.get(x) or {}).get('childnum') is not None else 10**9)
    return ch[1:]
 
def extract_dim_index_taints(dim_id, nodes, children_of):
    """Collect variable-like taints from the index expression(s) of an `AST_DIM` node."""
    roots = dim_index_roots(dim_id, nodes, children_of)
    if not roots:
        return []
    allowed = {'AST_VAR', 'AST_PROP', 'AST_DIM', 'AST_METHOD_CALL', 'AST_CALL', 'AST_STATIC_CALL'}
    out = []
    seen = set()
    seen_index_literals = set()
    q = list(roots)
    while q:
        x = q.pop()
        if x in seen:
            continue
        seen.add(x)
        nx = nodes.get(x) or {}
        xt = (nx.get('type') or '').strip()
        xl = (nx.get('labels') or '').strip()
        if xl == 'string' or xt == 'string':
            v = (nx.get('code') or nx.get('name') or '').strip().strip("'\"")
            if v and v not in seen_index_literals:
                seen_index_literals.add(v)
                out.append({'id': x, 'type': 'AST_VAR', 'name': v})
            continue
        t, nm = node_display(x, nodes, children_of)
        if t in ('AST_CONST', 'AST_NAME') and nm:
            v = (nm or '').strip().strip("'\"")
            if v and v not in seen_index_literals:
                seen_index_literals.add(v)
                out.append({'id': x, 'type': 'AST_VAR', 'name': v})
        elif t in allowed:
            rec = {'id': x, 'type': t}
            if nm:
                rec['name'] = nm
            out.append(rec)
        for c in children_of.get(x, []) or []:
            q.append(c)
    return out
 
def build_initial_taints(st, nodes, children_of, parent_of):
    """Build initial taint seeds from extracted if-element variables/props/dims/calls."""
    r = st['result']
    taints = []
    seen = set()
    init_seq = st.get('seq')
    allowed = {'AST_VAR', 'AST_PROP', 'AST_DIM', 'AST_METHOD_CALL', 'AST_CALL', 'AST_STATIC_CALL'}
    def is_inside_prop_or_dim(nid):
        if nid is None:
            return False
        try:
            cur = int(nid)
        except Exception:
            return False
        try:
            from utils.cpg_utils.graph_mapping import is_in_dim_index_subtree, is_in_method_call_receiver_subtree, subtree_contains
        except Exception:
            is_in_dim_index_subtree = None
            is_in_method_call_receiver_subtree = None
            subtree_contains = None
        def sorted_children(xid: int) -> list[int]:
            ch = list(children_of.get(int(xid), []) or [])
            ch.sort(key=lambda x: (nodes.get(x) or {}).get('childnum') if (nodes.get(x) or {}).get('childnum') is not None else 10**9)
            out = []
            for c in ch:
                try:
                    out.append(int(c))
                except Exception:
                    continue
            return out
        def prop_base_child_id(pid: int) -> int | None:
            for c in sorted_children(pid):
                cx = nodes.get(c) or {}
                tt = (cx.get('type') or '').strip()
                if tt == 'AST_ARG_LIST':
                    continue
                if cx.get('labels') == 'string' or tt == 'string':
                    continue
                return int(c)
            return None
        seen_local = set()
        for _ in range(20):
            if cur in seen_local:
                break
            seen_local.add(cur)
            p = parent_of.get(cur) if isinstance(parent_of, dict) else None
            if p is None:
                return False
            try:
                p_i = int(p)
            except Exception:
                return False
            pt = ((nodes.get(p_i) or {}).get('type') or '').strip()
            if pt == 'AST_DIM':
                if is_in_dim_index_subtree is not None and is_in_dim_index_subtree(int(p_i), int(nid), nodes, children_of):
                    cur = p_i
                    continue
                return True
            if pt == 'AST_PROP':
                base_child = prop_base_child_id(int(p_i))
                if base_child is not None and subtree_contains is not None and subtree_contains(int(base_child), int(nid), children_of):
                    return True
                if base_child is not None and subtree_contains is None and int(base_child) == int(cur):
                    return True
            if pt == 'AST_METHOD_CALL':
                if is_in_method_call_receiver_subtree is not None and is_in_method_call_receiver_subtree(int(p_i), int(nid), nodes, children_of):
                    return True
            cur = p_i
        return False
    def collect_receiver_related_ids(recv_id):
        """Collect ids of receiver-related nodes so they can be excluded from initial taints."""
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
        """Drop receiver-side vars/props/dims so method calls focus on arguments/results."""
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
        """Insert a taint record if it is allowed and not already present."""
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
        if is_inside_prop_or_dim(v.get('id')):
            continue
        add({'id': v['id'], 'type': 'AST_VAR', 'name': v.get('name', '')})
    for p in r.get('props') or []:
        add({'id': p['id'], 'type': 'AST_PROP', 'base': p.get('base', ''), 'prop': p.get('prop', '')})
    for d in r.get('dims') or []:
        did = d.get('id')
        base_id = None
        base_t = None
        try:
            from taint_handlers.llm_var_split import ast_dim_base_root_id, ast_dim_base_id

            base_id = ast_dim_base_root_id(int(did), children_of, nodes) if did is not None else None
        except Exception:
            base_id = None
        if base_id is not None:
            base_t = (nodes.get(base_id) or {}).get('type')
        if (base_t or '').strip() != 'AST_PROP' and did is not None:
            try:
                b0 = ast_dim_base_id(int(did), children_of, nodes)
            except Exception:
                b0 = None
            bt0 = (nodes.get(b0) or {}).get('type') if b0 is not None else None
            if (bt0 or '').strip() == 'AST_PROP':
                base_id = b0
                base_t = bt0
        if (base_t or '').strip() == 'AST_PROP' and base_id is not None:
            add({'id': base_id, 'type': 'AST_PROP'})
        else:
            add({'id': did, 'type': 'AST_DIM', 'base': d.get('base', ''), 'key': d.get('key', '')})
        for it in extract_dim_index_taints(d['id'], nodes, children_of):
            add(it)
    for c in r.get('calls') or []:
        if c.get('kind') == 'method_call':
            add({'id': c['id'], 'type': 'AST_METHOD_CALL', 'name': c.get('name', ''), 'recv': c.get('recv', '')})
        elif c.get('kind') == 'call':
            add({'id': c['id'], 'type': 'AST_CALL', 'name': c.get('name', '')})
        elif c.get('kind') == 'static_call':
            add({'id': c['id'], 'type': 'AST_STATIC_CALL', 'name': c.get('name', '')})
    return filter_method_call_receivers(taints)
 
def extract_if_elements_fast(arg, seq, nodes, children_of, trace_index_records, seq_to_index):
    """Locate `AST_IF_ELEM` nodes for a trace locator and extract relevant descendant nodes."""
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
        t = (nx.get('type') or '').strip()
        if t in ('AST_IF_ELEM', 'AST_SWITCH'):
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

    def handle_extracted_node(x: int):
        nx = nodes.get(x) or {}
        t = (nx.get('type') or '').strip()
        if t == 'AST_VAR':
            ss = get_string_children(x, children_of, nodes)
            name = ss[0][1] if ss else ''
            result['vars'].append({'id': x, 'name': name})
            return
        if t == 'AST_DIM':
            ch = list(children_of.get(x, []) or [])
            ch.sort(key=lambda y: (nodes.get(y) or {}).get('childnum') if (nodes.get(y) or {}).get('childnum') is not None else 10**9)
            base_id = None
            key_id = None
            if len(ch) >= 1:
                base_id = ch[0]
            if len(ch) >= 2:
                key_id = ch[1]
            base_nm = ''
            if base_id is not None:
                _, base_nm = node_display(int(base_id), nodes, children_of)
            if not base_nm:
                base_nm = find_first_var_string(x, children_of, nodes)
            key = ''
            if key_id is not None:
                try:
                    _, key_nm = node_display(int(key_id), nodes, children_of)
                except Exception:
                    key_nm = ''
                key = (key_nm or '').strip()
            if not key:
                parts = [v for _, v in get_string_children(x, children_of, nodes)]
                key = parts[0] if parts else ''
            result['dims'].append({'id': x, 'base': base_nm, 'key': key})
            return
        if t == 'AST_PROP':
            ch = list(children_of.get(x, []) or [])
            ch.sort(key=lambda y: (nodes.get(y) or {}).get('childnum') if (nodes.get(y) or {}).get('childnum') is not None else 10**9)
            base_id = None
            for c in ch:
                nc = nodes.get(c) or {}
                ctt = (nc.get('type') or '').strip()
                if ctt == 'AST_ARG_LIST':
                    continue
                if nc.get('labels') == 'string' or ctt == 'string':
                    continue
                base_id = c
                break
            base_nm = ''
            if base_id is not None:
                _, base_nm = node_display(int(base_id), nodes, children_of)
            if not base_nm:
                base_nm = find_first_var_string(x, children_of, nodes)
            prop = ''
            if len(ch) >= 2:
                try:
                    _, prop_nm = node_display(int(ch[1]), nodes, children_of)
                except Exception:
                    prop_nm = ''
                prop = (prop_nm or '').strip()
            if not prop:
                parts = [v for _, v in get_string_children(x, children_of, nodes)]
                prop = parts[0] if parts else ''
            result['props'].append({'id': x, 'base': base_nm, 'prop': prop})
            return
        if t == 'AST_CONST':
            parts = [v for _, v in get_all_string_descendants(x, children_of, nodes)]
            result['consts'].append({'id': x, 'type': 'AST_CONST', 'name': parts[0] if parts else ''})
            return
        if t == 'AST_NAME':
            parts = [v for _, v in get_all_string_descendants(x, children_of, nodes)]
            v = parts[0] if parts else (nx.get('code') or nx.get('name') or '')
            result['consts'].append({'id': x, 'type': 'AST_NAME', 'name': v})
            return
        if t == 'AST_METHOD_CALL':
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
            fn = (fn or '').replace('.', '->').strip()
            recv = (recv or '').replace('.', '->').strip()
            if fn.endswith('()'):
                fn = fn[:-2]
            if '->' in fn:
                head, tail = fn.split('->', 1)
                head = head.lstrip('$')
                recv_tail = (recv.split('->')[-1] if recv else '').lstrip('$')
                if recv and head and recv_tail and head == recv_tail and tail:
                    fn = tail
                elif not recv and head and tail:
                    recv = head
                    fn = tail
            arg_list_id = None
            for c in children_of.get(x, []) or []:
                nc = nodes.get(c) or {}
                if nc.get('type') == 'AST_ARG_LIST':
                    arg_list_id = c
            result['calls'].append({'id': x, 'kind': 'method_call', 'name': fn, 'recv': recv, 'recv_id': recv_id, 'arg_list_id': arg_list_id})
            return
        if t == 'AST_CALL':
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
            for c in children_of.get(x, []) or []:
                nc = nodes.get(c) or {}
                if nc.get('type') == 'AST_ARG_LIST':
                    arg_list_id = c
            result['calls'].append({'id': x, 'kind': 'call', 'name': fn, 'arg_list_id': arg_list_id})
            return
        if t == 'AST_STATIC_CALL':
            fn = ''
            cls = ''
            for c in children_of.get(x, []) or []:
                nc = nodes.get(c) or {}
                ct = (nc.get('type') or '').strip()
                if ct == 'AST_NAME' and not cls:
                    ssc = get_string_children(c, children_of, nodes)
                    cls = ssc[0][1] if ssc else ''
                if (nc.get('labels') == 'string' or ct == 'string') and not fn:
                    vv = nc.get('code') or nc.get('name') or ''
                    if vv:
                        fn = vv
            name = f"{cls}::{fn}" if cls and fn else (fn or cls)
            arg_list_id = None
            for c in children_of.get(x, []) or []:
                nc = nodes.get(c) or {}
                if nc.get('type') == 'AST_ARG_LIST':
                    arg_list_id = c
            result['calls'].append({'id': x, 'kind': 'static_call', 'name': name, 'arg_list_id': arg_list_id})
            return

    def sorted_children(xid: int) -> list[int]:
        ch = list(children_of.get(int(xid), []) or [])
        ch.sort(key=lambda y: (nodes.get(y) or {}).get('childnum') if (nodes.get(y) or {}).get('childnum') is not None else 10**9)
        return ch

    def extract_switch_case_expr_roots(switch_id: int) -> list[int]:
        out = []
        sw_children = sorted_children(switch_id)
        switch_list_id = None
        for c in sw_children:
            if ((nodes.get(c) or {}).get('type') or '').strip() == 'AST_SWITCH_LIST':
                switch_list_id = c
                break
        if switch_list_id is None:
            return out
        for case_id in sorted_children(switch_list_id):
            ct = ((nodes.get(case_id) or {}).get('type') or '').strip()
            if ct != 'AST_SWITCH_CASE':
                continue
            case_children = sorted_children(case_id)
            if not case_children:
                continue
            expr_id = case_children[0]
            et = ((nodes.get(expr_id) or {}).get('type') or '').strip()
            if et and et != 'NULL':
                out.append(expr_id)
        return out

    for root in targets:
        rt = ((nodes.get(root) or {}).get('type') or '').strip()
        if rt == 'AST_IF_ELEM':
            desc = collect_descendants(root, children_of, nodes, line)
            for x in desc:
                handle_extracted_node(int(x))
            continue
        if rt == 'AST_SWITCH':
            desc = collect_descendants(root, children_of, nodes, line)
            for x in desc:
                handle_extracted_node(int(x))
            for expr_root in extract_switch_case_expr_roots(int(root)):
                expr_line = (nodes.get(expr_root) or {}).get('lineno')
                if expr_line is None:
                    continue
                handle_extracted_node(int(expr_root))
                for x in collect_descendants(int(expr_root), children_of, nodes, int(expr_line)):
                    handle_extracted_node(int(x))

    return {'arg': arg, 'path': path, 'line': line, 'targets': targets, 'result': result}
 
def process_taints(initial, ctx):
    """Run taint processing in either offline mode or LLM-assisted mode."""
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
    """Parse a `path:line` locator and return `(normalized_path, line)`."""
    if not loc or ':' not in loc:
        return None
    p, ln_s = loc.rsplit(':', 1)
    try:
        ln = int(ln_s)
    except:
        return None
    return norm_trace_path(p), ln

def build_seq_index(trace_index_records):
    """Build a `(path,line) -> sorted unique seq list` index from trace index records."""
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
    """Pick a seq from sorted `seqs` near `ref_seq` using forward/backward preference."""
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
    """Attach a best-effort `seq` to each result-set location using trace index records."""
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
    """Sort and de-duplicate result-set items by `seq` (or by locator when seq is missing)."""
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

def build_result_set_from_llm_seqs(ctx):
    """Build a result-set locator list from the set of seqs returned/used by the LLM."""
    if not isinstance(ctx, dict):
        return []
    seqs = ctx.get('llm_result_seqs') or set()
    seq_to_idx = ctx.get('trace_seq_to_index') or {}
    recs = ctx.get('trace_index_records') or []
    out = []
    for s in seqs:
        try:
            si = int(s)
        except Exception:
            continue
        idx = seq_to_idx.get(si)
        if idx is None:
            for i, r in enumerate(recs):
                if si in (r.get('seqs') or []):
                    idx = i
                    break
        if isinstance(idx, int) and 0 <= idx < len(recs):
            rec = recs[idx] or {}
            p = rec.get('path')
            ln = rec.get('line')
            if p and ln is not None:
                out.append({'seq': si, 'path': p, 'line': ln, 'loc': f"{p}:{ln}"})
                continue
        out.append({'seq': si})
    return out

def parse_cli_args(argv: list[str]) -> dict:
    """
    Parse CLI args for `analyze_if_line.py`.

    Supported flags:
    - `--debug`: enable debug logging.
    - `--llm`: enable LLM-assisted taint loop (may call the configured LLM).
    - `--llm-test`: enable LLM-assisted loop in replay-only mode (never calls LLM).
    - `--prompt`: accepted for compatibility (no behavioral change).
    - `--llm-max=<N>` / `--llm-max <N>`: limit number of LLM calls per run.
    """
    args = list(argv or [])
    args = [x.replace('--llm--', '--llm-') if isinstance(x, str) and x.startswith('--llm--') else x for x in args]
    debug_mode = any(x == '--debug' for x in args)
    llm_mode = any(x == '--llm' for x in args)
    llm_test_mode = any(x == '--llm-test' for x in args)
    prompt_mode = any(x == '--prompt' for x in args)

    llm_max_calls = None
    for i, x in enumerate(args):
        if x.startswith('--llm-max='):
            try:
                llm_max_calls = int(x.split('=', 1)[1])
            except Exception:
                llm_max_calls = None
        if x == '--llm-max' and (i + 1) < len(args):
            try:
                llm_max_calls = int(args[i + 1])
            except Exception:
                llm_max_calls = None

    return {
        'debug_mode': bool(debug_mode),
        'llm_mode': bool(llm_mode),
        'llm_test_mode': bool(llm_test_mode),
        'llm_max_calls': llm_max_calls,
        'prompt_mode': bool(prompt_mode),
    }

def _parse_analyze_flags_from_config(cfg_raw: dict) -> dict:
    if not isinstance(cfg_raw, dict):
        return {'test': False, 'debug': False, 'prompt': False}
    sec = cfg_raw.get('analyze_if')
    if not isinstance(sec, dict):
        sec = cfg_raw.get('analyze_if_line')
    if not isinstance(sec, dict):
        sec = {}
    test_mode = bool(sec.get('test'))
    debug_mode = bool(sec.get('debug'))
    prompt_mode = bool(sec.get('prompt'))
    return {'test': test_mode, 'debug': debug_mode, 'prompt': prompt_mode}

def main():
    """CLI entrypoint: `python analyze_if_line.py <seq> [--debug] [--llm|--llm-test] [--llm-max=N]`."""
    if len(sys.argv) < 2:
        return
    s = sys.argv[1]
    cfg = load_app_config(argv=sys.argv[2:])
    opts = parse_cli_args(sys.argv[2:])
    cfg_flags = _parse_analyze_flags_from_config(cfg.raw if hasattr(cfg, 'raw') else {})
    debug_mode = bool(opts.get('debug_mode') or cfg_flags.get('debug'))
    prompt_mode = bool(opts.get('prompt_mode') or cfg_flags.get('prompt'))
    test_mode = bool(opts.get('llm_test_mode') or cfg_flags.get('test'))
    llm_enabled = bool(opts.get('llm_mode') or test_mode)
    llm_max_calls = opts.get('llm_max_calls')
    try:
        n = int(s)
    except:
        return
    base = cfg.base_dir
    test_root = cfg.test_dir
    os.makedirs(test_root, exist_ok=True)
    run_dir = os.path.join(test_root, f"seq_{int(n)}")
    clean_previous_test_outputs(run_dir, n)
    clean_llm_io_dirs(run_dir, llm_mode=llm_enabled, llm_test_mode=test_mode)
    logger = Logger(base_dir=run_dir, min_level=('DEBUG' if debug_mode else 'INFO'), name=f'analyze_if_line:{n}', also_console=True)
    out_path = os.path.join(run_dir, f"analysis_output_{n}.json")
    def finish(obj):
        with open(out_path, 'w', encoding='utf-8') as f:
            json.dump(obj, f, ensure_ascii=False, indent=2)
        logger.info('write_output', out_path=out_path)
        logger.close()
        return

    trace_path = cfg.find_input_file('trace.log')
    arg = read_trace_line(n, trace_path)
    if not arg:
        return finish({'error': 'trace_log_line_parse_failed'})
    nodes_path = cfg.find_input_file('nodes.csv')
    rels_path = cfg.find_input_file('rels.csv')

    trace_index_path = cfg.tmp_path('trace_index.json')
    os.makedirs(os.path.dirname(trace_index_path) or '.', exist_ok=True)
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
    parent_of, children_of = load_ast_edges(rels_path)
    st = extract_if_elements_fast(arg, n, nodes, children_of, trace_index_records, seq_to_index)
    if not (st.get('targets') or []):
        return finish({'error': 'if_elem_not_found_for_trace_line'})

    st['seq'] = n
    initial = build_initial_taints(st, nodes, children_of, parent_of)

    ctx = {
        'input_seq': n,
        'path': st['path'],
        'line': st['line'],
        'targets': st['targets'],
        'result': st['result'],
        'initial_taints': initial,
        'nodes': nodes,
        'children_of': children_of,
        'parent_of': parent_of,
        'top_id_to_file': top_id_to_file,
        'trace_index_records': trace_index_records,
        'trace_seq_to_index': seq_to_index,
        'argv': sys.argv[2:],
        'trace_path': trace_path,
        'nodes_path': nodes_path,
        'rels_path': rels_path,
        'scope_root': '/app',
        'windows_root': r'D:\files\witcher\app',
        'llm_enabled': llm_enabled,
        'llm_max_calls': (llm_max_calls if llm_enabled else None),
        'llm_offline': (True if test_mode else False) if llm_enabled else None,
        'llm_scope_debug': bool(debug_mode),
        'debug': {},
        'logger': logger,
        'test_dir': run_dir,
    }
    try:
        logger.log_json('INFO', 'initial_taints', initial)
        logger.info(
            'initial_taints_summary',
            count=len(initial or []),
            types=[(t or {}).get('type') for t in (initial or [])],
            ids=[(t or {}).get('id') for t in (initial or [])],
        )
    except Exception:
        pass
    try:
        process_taints(initial, ctx)
    except Exception:
        logger.exception('analyze_failed')
        try:
            if llm_enabled:
                rs2 = sort_dedup_result_set_by_seq(build_result_set_from_llm_seqs(ctx))
            else:
                rs = ctx.get('result_set') or []
                rs2 = attach_min_seq_to_result_set(rs, trace_index_records, ref_seq=n, prefer='forward')
                rs2 = sort_dedup_result_set_by_seq(rs2)
        except Exception:
            rs2 = []
        finish({'input_seq': n, 'initial_taints': initial, 'result_set': rs2, 'error': 'analyze_failed'})
        raise SystemExit(1)
    if llm_enabled:
        rs2 = sort_dedup_result_set_by_seq(build_result_set_from_llm_seqs(ctx))
    else:
        rs = ctx.get('result_set') or []
        rs2 = attach_min_seq_to_result_set(rs, trace_index_records, ref_seq=n, prefer='forward')
        rs2 = sort_dedup_result_set_by_seq(rs2)
    out = {
        'input_seq': n,
        'initial_taints': initial,
        'result_set': rs2,
    }
    try:
        logger.write_json('logs', 'debug_ctx.json', {'ast_method_call': (ctx.get('debug') or {}).get('ast_method_call')})
    except Exception:
        pass
    if prompt_mode:
        try:
            prompt_text = generate_symbolic_execution_prompt(
                rs2,
                input_seq=n,
                input_path=ctx.get('path'),
                input_line=ctx.get('line'),
                scope_root=ctx.get('scope_root') or '/app',
                trace_index_path=trace_index_path,
                windows_root=ctx.get('windows_root') or r'D:\files\witcher\app',
                base_prompt=None,
            )
            if bool(opts.get('llm_mode')) and not test_mode:
                rr = run_symbolic_prompt(
                    prompt_text,
                    run_dir=run_dir,
                    seq=int(n),
                    llm_offline=False,
                    logger=logger,
                )
                out['symbolic_prompt_path'] = rr.get('prompt_path')
                out['symbolic_response_path'] = rr.get('response_path')
                out['symbolic_response_json_path'] = rr.get('response_json_path')
                logger.info('write_symbolic_prompt', prompt_path=out.get('symbolic_prompt_path'), llm_mode=True, test_mode=False)
                try:
                    output_root = _resolve_output_root(cfg)
                    defaults = load_symbolic_solution_defaults(cfg.find_input_file('测试命令.txt'))
                    sols = rr.get('response_obj') or []
                    if not sols and isinstance(out.get('symbolic_response_json_path'), str) and os.path.exists(out.get('symbolic_response_json_path')):
                        try:
                            with open(out.get('symbolic_response_json_path'), 'r', encoding='utf-8', errors='replace') as f:
                                obj = json.load(f)
                            sols = obj.get('solutions') if isinstance(obj, dict) else []
                        except Exception:
                            sols = []
                    if isinstance(sols, str):
                        sols = parse_symbolic_response(sols)
                    wrote = write_symbolic_solution_outputs(sols or [], output_root=output_root, seq=int(n), defaults=defaults)
                    logger.info('write_symbolic_solutions', count=len(wrote), output_root=output_root)
                except Exception:
                    logger.exception('write_symbolic_solutions_failed')
            else:
                prompt_path = write_symbolic_prompt(prompt_text, run_dir=run_dir, seq=int(n))
                out['symbolic_prompt_path'] = prompt_path
                if test_mode:
                    raw_path, json_path = write_symbolic_response(build_symbolic_response_example(), run_dir=run_dir, seq=int(n))
                    out['symbolic_response_path'] = raw_path
                    out['symbolic_response_json_path'] = json_path
                logger.info('write_symbolic_prompt', prompt_path=prompt_path, llm_mode=False, test_mode=bool(test_mode))
                if test_mode:
                    try:
                        output_root = _resolve_output_root(cfg)
                        defaults = load_symbolic_solution_defaults(cfg.find_input_file('测试命令.txt'))
                        sols = []
                        try:
                            with open(out.get('symbolic_response_json_path', ''), 'r', encoding='utf-8', errors='replace') as f:
                                obj = json.load(f)
                            sols = (obj.get('solutions') or []) if isinstance(obj, dict) else []
                        except Exception:
                            sols = []
                        wrote = write_symbolic_solution_outputs(sols or [], output_root=output_root, seq=int(n), defaults=defaults)
                        logger.info('write_symbolic_solutions', count=len(wrote), output_root=output_root)
                    except Exception:
                        logger.exception('write_symbolic_solutions_failed')
        except Exception:
            logger.exception('write_symbolic_prompt_failed')
    return finish(out)

if __name__ == '__main__':
    main()
