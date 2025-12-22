import csv
import os
import json
from var_utils import build_children_parent, extract_varlike_for_nodes

def norm_trace_path(p):
    if p.startswith('/app/'):
        p = p[5:]
    if p.startswith('/'):
        p = p[1:]
    return p.lower()

def norm_nodes_path(p):
    if p.startswith('/app/'):
        p = p[5:]
    if p.startswith('/'):
        p = p[1:]
    return p.lower()

def read_trace_groups(trace_path, limit=None):
    groups = []
    with open(trace_path, 'r', encoding='utf-8') as f:
        count = 0
        last_key = None
        for line in f:
            if limit is not None and count >= limit:
                break
            line = line.strip()
            if not line:
                continue
            prefix = line.split(' | ', 1)[0]
            if ':' not in prefix:
                count += 1
                continue
            path_part, line_part = prefix.rsplit(':', 1)
            try:
                ln = int(line_part)
            except:
                count += 1
                continue
            np = norm_trace_path(path_part)
            key = (np, ln)
            if groups and key == last_key:
                groups[-1]['raw_lines'].append(line)
            else:
                groups.append({'path': np, 'line': ln, 'raw_lines': [line]})
                last_key = key
            count += 1
    return groups

def read_trace_groups_with_seqs(trace_path, limit=None):
    groups = []
    with open(trace_path, 'r', encoding='utf-8', errors='replace') as f:
        count = 0
        last_key = None
        for line in f:
            if limit is not None and count >= limit:
                break
            count += 1
            raw = line.strip()
            if not raw:
                continue
            prefix = raw.split(' | ', 1)[0]
            if ':' not in prefix:
                continue
            path_part, line_part = prefix.rsplit(':', 1)
            try:
                ln = int(line_part)
            except:
                continue
            np = norm_trace_path(path_part)
            key = (np, ln)
            if groups and key == last_key:
                groups[-1]['seqs'].append(count)
            else:
                groups.append({'path': np, 'line': ln, 'seqs': [count]})
                last_key = key
    return groups

def build_trace_index_records(trace_path, nodes_path, limit=None):
    groups = read_trace_groups_with_seqs(trace_path, limit)
    target = [(g['path'], g['line']) for g in groups]
    nodes_index = build_nodes_index(nodes_path, target)
    records = []
    for i, g in enumerate(groups):
        k = (g['path'], g['line'])
        nodes = nodes_index.get(k, [])
        node_ids = [n[0] for n in nodes]
        records.append({'index': i, 'path': g['path'], 'line': g['line'], 'seqs': g['seqs'], 'node_ids': node_ids})
    return records

def load_trace_index_records(index_path):
    if not os.path.exists(index_path):
        return None
    with open(index_path, 'r', encoding='utf-8', errors='replace') as f:
        try:
            obj = json.load(f)
        except Exception:
            return None
    if isinstance(obj, dict) and isinstance(obj.get('records'), list):
        return obj.get('records')
    if isinstance(obj, list):
        return obj
    return None

def save_trace_index_records(index_path, records, meta=None):
    out = {'records': records}
    if isinstance(meta, dict):
        out['meta'] = meta
    tmp_path = index_path + '.tmp'
    with open(tmp_path, 'w', encoding='utf-8') as f:
        json.dump(out, f, ensure_ascii=False, indent=2)
    os.replace(tmp_path, index_path)

def build_nodes_index(nodes_path, target):
    csv.field_size_limit(131072 * 10)
    target_paths = set(k[0] for k in target)
    target_lines_by_path = {}
    for p, ln in target:
        s = target_lines_by_path.get(p)
        if s is None:
            s = set()
            target_lines_by_path[p] = s
        s.add(ln)
    nodes_by_file_line = {}
    top_id_to_file = {}
    parent_of = {}
    children_of = {}

    # Pass 1: build top-level file map and parent map (child -> parent funcid)
    with open(nodes_path, 'r', encoding='utf-8', errors='replace') as f:
        reader = csv.DictReader(f, delimiter='\t')
        for row in reader:
            nid = row.get('id:int')
            if not nid:
                continue
            try:
                nid_i = int(nid)
            except:
                continue
            typ = row.get('type') or ''
            flags = row.get('flags:string_array') or ''
            name = row.get('name') or ''
            doccomment = row.get('doccomment') or ''
            if typ == 'AST_TOPLEVEL' and ('TOPLEVEL_FILE' in flags):
                path_val = name if name else doccomment
                if not path_val:
                    continue
                top_id_to_file[nid_i] = norm_nodes_path(path_val)
                continue
            funcid = row.get('funcid:int') or ''
            try:
                funcid_i = int(funcid)
            except:
                funcid_i = None
            if funcid_i is not None:
                parent_of[nid_i] = funcid_i
                ch = children_of.get(funcid_i)
                if ch is None:
                    ch = set()
                    children_of[funcid_i] = ch
                ch.add(nid_i)

    # memoization: node id -> top-level id
    node_to_top = {}

    def resolve_top_id(nid_i):
        cur = nid_i
        seen = 0
        while cur is not None and seen < 64:
            if cur in node_to_top:
                return node_to_top[cur]
            if cur in top_id_to_file:
                node_to_top[cur] = cur
                return cur
            nxt = parent_of.get(cur)
            if nxt is None:
                # try find a direct child that is a top-level file
                ch = children_of.get(cur)
                if ch:
                    for cid in ch:
                        if cid in top_id_to_file:
                            node_to_top[cur] = cid
                            return cid
                node_to_top[cur] = None
                return None
            cur = nxt
            seen += 1
        return None

    # Pass 2: collect nodes for target path+line pairs by resolving to top-level
    with open(nodes_path, 'r', encoding='utf-8', errors='replace') as f:
        reader = csv.DictReader(f, delimiter='\t')
        for row in reader:
            nid = row.get('id:int')
            if not nid:
                continue
            try:
                nid_i = int(nid)
            except:
                continue
            typ = row.get('type') or ''
            lab = row.get('labels:label') or ''
            lineno = row.get('lineno:int') or ''
            try:
                lineno_i = int(lineno)
            except:
                lineno_i = None
            if lineno_i is None:
                continue
            # resolve from this node's own id upward to a top-level id
            top_i = resolve_top_id(nid_i)
            if top_i is None:
                # try via direct funcid if present
                funcid = row.get('funcid:int') or ''
                try:
                    funcid_i = int(funcid)
                except:
                    funcid_i = None
                if funcid_i is not None:
                    top_i = resolve_top_id(funcid_i)
            if top_i is None:
                continue
            file_path = top_id_to_file.get(top_i)
            if not file_path:
                continue
            if file_path not in target_paths:
                continue
            if lineno_i not in target_lines_by_path.get(file_path, set()):
                continue
            k = (file_path, lineno_i)
            lst = nodes_by_file_line.get(k)
            if lst is None:
                lst = []
                nodes_by_file_line[k] = lst
            lst.append((nid_i, lab, typ))
    return nodes_by_file_line

def load_nodes_meta(nodes_path):
    meta = {}
    csv.field_size_limit(131072 * 10)
    with open(nodes_path, 'r', encoding='utf-8', errors='replace') as f:
        reader = csv.DictReader(f, delimiter='\t')
        for row in reader:
            s = row.get('id:int') or ''
            try:
                nid = int(s)
            except:
                continue
            t = row.get('type') or ''
            lab = row.get('labels:label') or ''
            ln = row.get('lineno:int') or ''
            try:
                ln_i = int(ln)
            except:
                ln_i = None
            code = row.get('code') or ''
            name = row.get('name') or ''
            meta[nid] = {'type': t, 'labels': lab, 'lineno': ln_i, 'code': code, 'name': name}
    return meta

def load_ast_edges(rels_path):
    children_of = {}
    csv.field_size_limit(131072 * 10)
    with open(rels_path, 'r', encoding='utf-8', errors='replace') as f:
        reader = csv.DictReader(f, delimiter='\t')
        for row in reader:
            if (row.get('type') or '') != 'PARENT_OF':
                continue
            s = row.get('start') or ''
            e = row.get('end') or ''
            try:
                si = int(s); ei = int(e)
            except:
                continue
            lst = children_of.get(si)
            if lst is None:
                lst = []
                children_of[si] = lst
            lst.append(ei)
    return children_of

def get_string_children(nid, children_of, nodes_meta):
    vals = []
    for c in children_of.get(nid, []) or []:
        nc = nodes_meta.get(c)
        if not nc:
            continue
        if nc.get('labels') == 'string' or (nc.get('type') == 'string'):
            v = nc.get('code') or nc.get('name') or ''
            if v:
                vals.append(v)
    return vals
def get_all_string_descendants(nid, children_of, nodes_meta):
    vals = []
    q = [nid]
    seen = set()
    while q:
        x = q.pop()
        if x in seen:
            continue
        seen.add(x)
        if x != nid:
            nc = nodes_meta.get(x)
            if nc and (nc.get('labels') == 'string' or (nc.get('type') == 'string')):
                v = nc.get('code') or nc.get('name') or ''
                if v:
                    vals.append(v)
        for c in children_of.get(x, []) or []:
            q.append(c)
    return vals

def find_first_var_string(nid, children_of, nodes_meta):
    q = list(children_of.get(nid, []) or [])
    seen = set()
    while q:
        x = q.pop(0)
        if x in seen:
            continue
        seen.add(x)
        nx = nodes_meta.get(x)
        if not nx:
            continue
        if nx.get('type') == 'AST_VAR':
            ss = get_string_children(x, children_of, nodes_meta)
            if ss:
                return ss[0]
        for c in children_of.get(x, []) or []:
            q.append(c)
    return ''

def collect_descendants_on_line(root, children_of, nodes_meta, line):
    res = []
    q = [root]
    seen = set()
    while q:
        x = q.pop()
        if x in seen:
            continue
        seen.add(x)
        if x != root:
            nx = nodes_meta.get(x)
            if nx and nx.get('lineno') == line:
                res.append(x)
        for c in children_of.get(x, []) or []:
            q.append(c)
    return res

def extract_variables_for_line(if_elem_ids, line, children_of, nodes_meta):
    out = []
    seen_ids = set()
    for root in if_elem_ids:
        desc = collect_descendants_on_line(root, children_of, nodes_meta, line)
        for x in desc:
            if x in seen_ids:
                continue
            nx = nodes_meta.get(x) or {}
            t = nx.get('type') or ''
            if t == 'AST_VAR':
                ss = get_string_children(x, children_of, nodes_meta)
                name = ss[0] if ss else ''
                if name:
                    out.append({'id': x, 'type': t, 'name': name})
                    seen_ids.add(x)
            elif t == 'AST_DIM':
                base = find_first_var_string(x, children_of, nodes_meta)
                ss = get_string_children(x, children_of, nodes_meta)
                key = ss[0] if ss else ''
                nm = base + ('[' + key + ']' if key else '')
                if base or key:
                    out.append({'id': x, 'type': t, 'name': nm})
                    seen_ids.add(x)
            elif t == 'AST_PROP':
                base = find_first_var_string(x, children_of, nodes_meta)
                ss = get_string_children(x, children_of, nodes_meta)
                prop = ss[0] if ss else ''
                nm = base + ('.' + prop if prop else '')
                if base or prop:
                    out.append({'id': x, 'type': t, 'name': nm})
                    seen_ids.add(x)
            elif t == 'AST_CONST':
                ss = get_string_children(x, children_of, nodes_meta)
                name = ss[0] if ss else ''
                if name:
                    out.append({'id': x, 'type': t, 'name': name})
                    seen_ids.add(x)
            elif t == 'AST_NAME':
                name = nx.get('code') or nx.get('name') or ''
                if name:
                    out.append({'id': x, 'type': t, 'name': name})
                    seen_ids.add(x)
    return out

def extract_variables_for_nodes(node_entries, children_of, nodes_meta):
    out = []
    seen_ids = set()
    for entry in node_entries:
        x = entry[0] if isinstance(entry, (list, tuple)) else entry
        if x in seen_ids:
            continue
        nx = nodes_meta.get(x) or {}
        t = nx.get('type') or ''
        if t == 'AST_VAR':
            ss = get_string_children(x, children_of, nodes_meta)
            name = ss[0] if ss else ''
            if name:
                out.append({'id': x, 'type': t, 'name': name})
                seen_ids.add(x)
        elif t == 'AST_DIM':
            base = find_first_var_string(x, children_of, nodes_meta)
            ss = get_string_children(x, children_of, nodes_meta)
            key = ss[0] if ss else ''
            nm = base + ('[' + key + ']' if key else '')
            if base or key:
                out.append({'id': x, 'type': t, 'name': nm})
                seen_ids.add(x)
        elif t == 'AST_PROP':
            base = find_first_var_string(x, children_of, nodes_meta)
            ss = get_string_children(x, children_of, nodes_meta)
            prop = ss[0] if ss else ''
            nm = base + ('.' + prop if prop else '')
            if base or prop:
                out.append({'id': x, 'type': t, 'name': nm})
                seen_ids.add(x)
        elif t == 'AST_CONST':
            ss = get_all_string_descendants(x, children_of, nodes_meta)
            name = ss[0] if ss else ''
            if name:
                out.append({'id': x, 'type': t, 'name': name})
                seen_ids.add(x)
        elif t == 'AST_NAME':
            ss = get_all_string_descendants(x, children_of, nodes_meta)
            name = ss[0] if ss else (nx.get('code') or nx.get('name') or '')
            if name:
                out.append({'id': x, 'type': t, 'name': name})
                seen_ids.add(x)
    return out

def read_existing_calls(edges_path):
    calls = set()
    if not os.path.exists(edges_path):
        return calls
    with open(edges_path, 'r', encoding='utf-8', errors='replace') as f:
        reader = csv.DictReader(f, delimiter='\t')
        for row in reader:
            t = row.get('type') or ''
            if t != 'CALLS':
                continue
            s = row.get('start') or ''
            e = row.get('end') or ''
            try:
                si = int(s)
                ei = int(e)
            except:
                continue
            calls.add((si, ei))
    return calls

def norm_call_name(s):
    s = (s or '').strip().lower()
    if not s:
        return ''
    out = []
    for ch in s:
        if ch.isalnum() or ch in ('_', '\\'):
            out.append(ch)
        else:
            break
    return ''.join(out)

def get_node_best_name(nid, nodes_meta, children_of):
    nx = nodes_meta.get(nid) or {}
    name = (nx.get('name') or '').strip()
    if name:
        return name
    ss = get_string_children(nid, children_of, nodes_meta)
    if ss:
        return ss[0]
    code = (nx.get('code') or '').strip()
    if code:
        return code
    return ''

def get_string_value(nid, nodes_meta):
    nx = nodes_meta.get(nid) or {}
    if nx.get('labels') == 'string' or (nx.get('type') == 'string'):
        v = (nx.get('code') or nx.get('name') or '').strip()
        return v
    return ''

def get_ast_name_string_child(ast_name_id, children_of, nodes_meta):
    for c in children_of.get(ast_name_id, []) or []:
        v = get_string_value(c, nodes_meta)
        if v:
            return v
    return ''

def get_direct_callsite_name(call_id, children_of, nodes_meta):
    for c in children_of.get(call_id, []) or []:
        cx = nodes_meta.get(c) or {}
        ct = cx.get('type') or ''
        if ct == 'AST_ARG_LIST':
            continue
        v = get_string_value(c, nodes_meta)
        if v:
            return v
        if ct == 'AST_NAME':
            v2 = get_ast_name_string_child(c, children_of, nodes_meta)
            if v2:
                return v2
    return ''

def find_descendant_callsite_name(call_id, children_of, nodes_meta):
    q = []
    for c in children_of.get(call_id, []) or []:
        cx = nodes_meta.get(c) or {}
        if (cx.get('type') or '') == 'AST_ARG_LIST':
            continue
        q.append(c)
    seen = set()
    while q:
        x = q.pop(0)
        if x in seen:
            continue
        seen.add(x)
        xx = nodes_meta.get(x) or {}
        xt = xx.get('type') or ''
        if xt == 'AST_NAME':
            v = get_ast_name_string_child(x, children_of, nodes_meta)
            if v:
                return v
        for c in children_of.get(x, []) or []:
            q.append(c)
    return ''

def get_call_name(nid, nodes_meta, children_of):
    nx = nodes_meta.get(nid) or {}
    name = (nx.get('name') or '').strip()
    if name:
        return name
    v = get_direct_callsite_name(nid, children_of, nodes_meta)
    if v:
        return v
    v2 = find_descendant_callsite_name(nid, children_of, nodes_meta)
    if v2:
        return v2
    code = (nx.get('code') or '').strip()
    if code:
        return code
    return ''

def get_decl_name(nid, nodes_meta, children_of):
    nx = nodes_meta.get(nid) or {}
    name = (nx.get('name') or '').strip()
    if name:
        return name
    for c in children_of.get(nid, []) or []:
        cx = nodes_meta.get(c) or {}
        ct = cx.get('type') or ''
        if ct == 'AST_NAME':
            v = get_ast_name_string_child(c, children_of, nodes_meta)
            if v:
                return v
        v2 = get_string_value(c, nodes_meta)
        if v2:
            return v2
    ss = get_string_children(nid, children_of, nodes_meta)
    if ss:
        return ss[0]
    code = (nx.get('code') or '').strip()
    if code:
        return code
    return ''

def pick_call_edge(a_id, a_type, dst_type, dst_candidates, nodes_meta, children_of, existing_calls, guard_calls):
    call_name_raw = get_call_name(a_id, nodes_meta, children_of)
    call_name = norm_call_name(call_name_raw)
    picked = dst_candidates[0]
    picked_name_raw = get_decl_name(picked, nodes_meta, children_of)
    picked_name = norm_call_name(picked_name_raw)
    picked_by = 'first'
    name_match = ''
    skipped = False
    edge_exists = False

    if not call_name:
        skipped = True
        picked_by = 'skip_no_call_name'
    elif call_name in guard_calls:
        skipped = True
        picked_by = 'skip_guard'
    else:
        matched = False
        for cand in dst_candidates:
            cand_name_raw = get_decl_name(cand, nodes_meta, children_of)
            cand_name = norm_call_name(cand_name_raw)
            if cand_name and cand_name == call_name:
                picked = cand
                picked_name_raw = cand_name_raw
                picked_name = cand_name
                picked_by = 'name'
                matched = True
                break
        if not matched:
            skipped = True
            picked_by = 'skip_no_match'

    if call_name and picked_name:
        name_match = 'yes' if call_name == picked_name else 'no'

    if not skipped:
        edge_exists = (a_id, picked) in existing_calls

    return {
        'picked': picked,
        'picked_name_raw': picked_name_raw,
        'picked_by': picked_by,
        'call_name_raw': call_name_raw,
        'name_match': name_match,
        'skipped': skipped,
        'edge_exists': edge_exists,
    }

def main():
    base = os.getcwd()
    trace_path = os.path.join(base, 'trace.log')
    nodes_path = os.path.join(base, 'nodes.csv')
    edges_path = os.path.join(base, 'cpg_edges.csv')
    rels_path = os.path.join(base, 'rels.csv')
    guard_calls = {
        'function_exists',
        'defined',
        'class_exists',
        'interface_exists',
        'trait_exists',
        'method_exists',
        'property_exists',
        'extension_loaded',
        'is_callable',
    }
    groups = read_trace_groups(trace_path, None)
    target = [(g['path'], g['line']) for g in groups]
    nodes_index = build_nodes_index(nodes_path, target)
    existing_calls = read_existing_calls(edges_path)
    nodes_meta = load_nodes_meta(nodes_path)
    children_of, parent_of = build_children_parent(rels_path)
    trace_edges = []
    debug_rows = []
    existed_count = 0
    for i, g in enumerate(groups):
        k = (g['path'], g['line'])
        nodes = nodes_index.get(k, [])
        ids = [str(n[0]) for n in nodes]
        types = [n[2] for n in nodes]
        has_method_call = any(t == 'AST_METHOD_CALL' for t in types)
        has_call = any(t == 'AST_CALL' for t in types)
        call_nodes = [n for n in nodes if n[2] in ('AST_METHOD_CALL', 'AST_CALL')]
        variables = extract_varlike_for_nodes(nodes, children_of, parent_of, nodes_meta)
        debug_rows.append({
            'index': i,
            'path': g['path'],
            'line': g['line'],
            'matched': 'yes' if nodes else 'no',
            'node_ids': ','.join(ids),
            'node_types': ','.join(types),
            'has_ast_method_call': 'yes' if has_method_call else 'no',
            'has_ast_call': 'yes' if has_call else 'no',
            'variables': variables
        })
        if not call_nodes:
            continue
        j = i + 1
        while j < len(groups):
            if groups[j]['path'] != g['path'] or groups[j]['line'] != g['line']:
                break
            j += 1
        if j >= len(groups):
            continue
        ng = groups[j]
        nk = (ng['path'], ng['line'])
        n_nodes = nodes_index.get(nk, [])
        n_types = [n[2] for n in n_nodes]
        for cn in call_nodes:
            a_id = cn[0]
            a_type = cn[2]
            if a_type == 'AST_METHOD_CALL':
                dst_type = 'AST_METHOD'
            else:
                dst_type = 'AST_FUNC_DECL'

            dst_candidates = [x[0] for x in n_nodes if x[2] == dst_type]
            if not dst_candidates:
                continue

            picked_info = pick_call_edge(
                a_id,
                a_type,
                dst_type,
                dst_candidates,
                nodes_meta,
                children_of,
                existing_calls,
                guard_calls,
            )
            picked = picked_info['picked']
            picked_name_raw = picked_info['picked_name_raw']
            picked_by = picked_info['picked_by']
            call_name_raw = picked_info['call_name_raw']
            name_match = picked_info['name_match']
            skipped = picked_info['skipped']
            edge_exists = picked_info['edge_exists']

            if not skipped:
                if edge_exists:
                    existed_count += 1
                else:
                    trace_edges.append((a_id, picked, 'CALLS', ''))

            debug_rows.append({
                'index': f'{i}->{j}',
                'path': f'{g["path"]} -> {ng["path"]}',
                'line': f'{g["line"]} -> {ng["line"]}',
                'matched': 'pair',
                'node_ids': f'{a_id if a_id is not None else ""},{picked if picked is not None else ""}',
                'node_types': f'{a_type},{dst_type}',
                'call_name': call_name_raw,
                'decl_name': picked_name_raw,
                'name_match': name_match,
                'picked_by': picked_by,
                'edge_exists_in_cpg_edges': 'skipped' if skipped else ('yes' if edge_exists else 'no')
            })
    # dedup output edges (easy to remove later)
    edges_out = list(dict.fromkeys(trace_edges))
    if edges_out:
        with open('trace_edges.csv', 'w', encoding='utf-8', newline='') as f:
            w = csv.writer(f, delimiter='\t')
            w.writerow(['start', 'end', 'type', 'var'])
            for a, b, t, v in edges_out:
                w.writerow([a, b, t, v])
    with open('trace_debug.json', 'w', encoding='utf-8') as f:
        json.dump(debug_rows, f, ensure_ascii=False, indent=2)
    with open('trace_stats.txt', 'w', encoding='utf-8') as f:
        f.write(f'groups={len(groups)}\n')
        f.write(f'missing_edges={len(edges_out)}\n')
        f.write(f'existing_edges_in_cpg_edges={existed_count}\n')

if __name__ == '__main__':
    main()

