import csv
import os
import sys
csv.field_size_limit(10**9)

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

def safe_int(s):
    try:
        return int(s)
    except:
        return None

def load_nodes(nodes_path):
    nodes = {}
    top_id_to_file = {}
    with open(nodes_path, 'r', encoding='utf-8', errors='replace') as f:
        reader = csv.DictReader(f, delimiter='\t')
        for row in reader:
            s = row.get('id:int')
            if not s:
                continue
            try:
                nid = int(s)
            except:
                continue
            nodes[nid] = {
                'type': row.get('type') or '',
                'labels': row.get('labels:label') or '',
                'flags': row.get('flags:string_array') or '',
                'lineno': safe_int(row.get('lineno:int')),
                'code': row.get('code') or '',
                'childnum': safe_int(row.get('childnum:int')),
                'funcid': safe_int(row.get('funcid:int')),
                'classname': row.get('classname') or '',
                'namespace': row.get('namespace') or '',
                'name': row.get('name') or '',
                'doccomment': row.get('doccomment') or ''
            }
            if nodes[nid]['type'] == 'AST_TOPLEVEL' and ('TOPLEVEL_FILE' in nodes[nid]['flags']):
                path_val = nodes[nid]['name'] if nodes[nid]['name'] else nodes[nid]['doccomment']
                if path_val:
                    top_id_to_file[nid] = norm_nodes_path(path_val)
    return nodes, top_id_to_file

def load_ast_edges(rels_path):
    parent_of = {}
    children_of = {}
    with open(rels_path, 'r', encoding='utf-8', errors='replace') as f:
        reader = csv.DictReader(f, delimiter='\t')
        for row in reader:
            t = row.get('type') or ''
            if t != 'PARENT_OF':
                continue
            s = row.get('start') or ''
            e = row.get('end') or ''
            try:
                si = int(s)
                ei = int(e)
            except:
                continue
            parent_of[ei] = si
            lst = children_of.get(si)
            if lst is None:
                lst = []
                children_of[si] = lst
            lst.append(ei)
    return parent_of, children_of

def resolve_top_id(nid, parent_of, nodes, top_id_to_file):
    cur = nid
    steps = 0
    while cur is not None and steps < 64:
        if cur in top_id_to_file:
            return cur
        nxt = parent_of.get(cur)
        if nxt is None:
            funcid = nodes.get(cur, {}).get('funcid')
            cur = funcid
        else:
            cur = nxt
        steps += 1
    return None

def collect_descendants(root, children_of, nodes, line):
    res = []
    q = [root]
    seen = set()
    while q:
        x = q.pop()
        if x in seen:
            continue
        seen.add(x)
        if x != root:
            nx = nodes.get(x)
            if nx and nx.get('lineno') == line:
                res.append(x)
        for c in children_of.get(x, []):
            q.append(c)
    return res

def get_string_children(nid, children_of, nodes):
    vals = []
    for c in children_of.get(nid, []):
        nc = nodes.get(c)
        if not nc:
            continue
        if nc.get('labels') == 'string' or (nc.get('type') == 'string'):
            v = nc.get('code') or nc.get('name') or ''
            if v:
                vals.append((c, v))
    return vals

def get_all_string_descendants(nid, children_of, nodes):
    vals = []
    q = list(children_of.get(nid, []) or [])
    seen = set()
    while q:
        x = q.pop()
        if x in seen:
            continue
        seen.add(x)
        nx = nodes.get(x)
        if not nx:
            continue
        if nx.get('labels') == 'string' or (nx.get('type') == 'string'):
            v = nx.get('code') or nx.get('name') or ''
            if v:
                vals.append((x, v))
        for c in children_of.get(x, []) or []:
            q.append(c)
    return vals

def find_first_var_string(nid, children_of, nodes):
    q = list(children_of.get(nid, []) or [])
    seen = set()
    while q:
        x = q.pop(0)
        if x in seen:
            continue
        seen.add(x)
        nx = nodes.get(x)
        if not nx:
            continue
        if nx.get('type') == 'AST_VAR':
            ss = get_string_children(x, children_of, nodes)
            if ss:
                return ss[0][1]
        for c in children_of.get(x, []) or []:
            q.append(c)
    return ''

def extract_if_elements(arg, nodes_path=None, rels_path=None):
    base = os.getcwd()
    nodes_path = nodes_path or os.path.join(base, 'nodes.csv')
    rels_path = rels_path or os.path.join(base, 'rels.csv')
    pth, ln_s = arg.rsplit(':', 1)
    line = int(ln_s)
    path = norm_trace_path(pth)
    nodes, top_id_to_file = load_nodes(nodes_path)
    parent_of, children_of = load_ast_edges(rels_path)
    idx_by_line = {}
    for nid, nd in nodes.items():
        ln = nd.get('lineno')
        if ln is None:
            continue
        top = resolve_top_id(nid, parent_of, nodes, top_id_to_file)
        if top is None:
            continue
        fp = top_id_to_file.get(top)
        if fp != path:
            continue
        if ln != line:
            continue
        lst = idx_by_line.get(line)
        if lst is None:
            lst = []
            idx_by_line[line] = lst
        lst.append(nid)
    targets = [nid for nid in idx_by_line.get(line, []) if nodes[nid]['type'] == 'AST_IF_ELEM']
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
            t = nodes[x]['type']
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
                v = parts[0] if parts else (nodes[x].get('code') or nodes[x].get('name') or '')
                result['consts'].append({'id': x, 'type': 'AST_NAME', 'name': v})
            elif t == 'AST_METHOD_CALL':
                fn = ''
                recv = ''
                for c in children_of.get(x, []):
                    nc = nodes.get(c)
                    if not nc:
                        continue
                    if nc.get('type') == 'AST_VAR':
                        ssc = get_string_children(c, children_of, nodes)
                        recv = ssc[0][1] if ssc else ''
                    if nc.get('labels') == 'string' or nc.get('type') == 'string':
                        vv = nc.get('code') or nc.get('name') or ''
                        if vv:
                            fn = vv
                arg_list_id = None
                args = []
                for c in children_of.get(x, []):
                    nc = nodes.get(c)
                    if not nc:
                        continue
                    if nc.get('type') == 'AST_ARG_LIST':
                        arg_list_id = c
                        for ac in children_of.get(c, []) or []:
                            anc = nodes.get(ac)
                            if not anc:
                                continue
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
                result['calls'].append({'id': x, 'kind': 'method_call', 'name': fn, 'recv': recv, 'arg_list_id': arg_list_id, 'args': args})
            elif t == 'AST_CALL':
                fn = ''
                for c in children_of.get(x, []) or []:
                    nc = nodes.get(c)
                    if not nc:
                        continue
                    if nc.get('labels') == 'string' or nc.get('type') == 'string':
                        vv = nc.get('code') or nc.get('name') or ''
                        if vv:
                            fn = vv
                arg_list_id = None
                args = []
                for c in children_of.get(x, []) or []:
                    nc = nodes.get(c)
                    if not nc:
                        continue
                    if nc.get('type') == 'AST_ARG_LIST':
                        arg_list_id = c
                        for ac in children_of.get(c, []) or []:
                            anc = nodes.get(ac)
                            if not anc:
                                continue
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
                result['calls'].append({'id': x, 'kind': 'call', 'name': fn, 'recv': '', 'arg_list_id': arg_list_id, 'args': args})
            elif t == 'AST_STATIC_CALL':
                cls = ''
                fn = ''
                for c in children_of.get(x, []) or []:
                    nc = nodes.get(c)
                    if not nc:
                        continue
                    if nc.get('type') == 'AST_NAME' or nc.get('labels') == 'string' or nc.get('type') == 'string':
                        vv = nc.get('code') or nc.get('name') or ''
                        if vv and not cls:
                            cls = vv
                        elif vv:
                            fn = vv
                arg_list_id = None
                args = []
                for c in children_of.get(x, []) or []:
                    nc = nodes.get(c)
                    if not nc:
                        continue
                    if nc.get('type') == 'AST_ARG_LIST':
                        arg_list_id = c
                        for ac in children_of.get(c, []) or []:
                            anc = nodes.get(ac)
                            if not anc:
                                continue
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
                result['calls'].append({'id': x, 'kind': 'static_call', 'name': fn, 'recv': cls, 'arg_list_id': arg_list_id, 'args': args})
            elif t == 'AST_ISSET':
                targets2 = []
                for c in children_of.get(x, []) or []:
                    nc = nodes.get(c)
                    if not nc:
                        continue
                    if nc.get('type') == 'AST_VAR':
                        ss = get_string_children(c, children_of, nodes)
                        name = ss[0][1] if ss else ''
                        if name:
                            targets2.append({'id': c, 'kind': 'var', 'name': name})
                    elif nc.get('type') == 'AST_DIM':
                        parts = [v for _, v in get_string_children(c, children_of, nodes)]
                        base_nm = find_first_var_string(c, children_of, nodes)
                        key = parts[0] if parts else ''
                        targets2.append({'id': c, 'kind': 'dim', 'base': base_nm, 'key': key})
                    elif nc.get('type') == 'AST_PROP':
                        base_nm = find_first_var_string(c, children_of, nodes)
                        parts = [v for _, v in get_string_children(c, children_of, nodes)]
                        prop = parts[0] if parts else ''
                        targets2.append({'id': c, 'kind': 'prop', 'base': base_nm, 'prop': prop})
                result['isset'].append({'id': x, 'targets': targets2})
            elif t == 'AST_EMPTY':
                targets2 = []
                for c in children_of.get(x, []) or []:
                    nc = nodes.get(c)
                    if not nc:
                        continue
                    if nc.get('type') == 'AST_VAR':
                        ss = get_string_children(c, children_of, nodes)
                        name = ss[0][1] if ss else ''
                        if name:
                            targets2.append({'id': c, 'kind': 'var', 'name': name})
                    elif nc.get('type') == 'AST_DIM':
                        parts = [v for _, v in get_string_children(c, children_of, nodes)]
                        base_nm = find_first_var_string(c, children_of, nodes)
                        key = parts[0] if parts else ''
                        targets2.append({'id': c, 'kind': 'dim', 'base': base_nm, 'key': key})
                    elif nc.get('type') == 'AST_PROP':
                        base_nm = find_first_var_string(c, children_of, nodes)
                        parts = [v for _, v in get_string_children(c, children_of, nodes)]
                        prop = parts[0] if parts else ''
                        targets2.append({'id': c, 'kind': 'prop', 'base': base_nm, 'prop': prop})
                result['empty'].append({'id': x, 'targets': targets2})
            elif t == 'AST_CLASS_CONST':
                cls = ''
                const = ''
                for c in children_of.get(x, []) or []:
                    nc = nodes.get(c)
                    if not nc:
                        continue
                    if not cls and (nc.get('type') == 'AST_NAME' or nc.get('labels') == 'string' or nc.get('type') == 'string'):
                        cls = (nc.get('code') or nc.get('name') or '')
                    elif const == '' and (nc.get('labels') == 'string' or nc.get('type') == 'string'):
                        const = (nc.get('code') or nc.get('name') or '')
                result['class_consts'].append({'id': x, 'class': cls, 'const': const})
            elif t == 'AST_STATIC_PROP':
                cls = ''
                prop = ''
                for c in children_of.get(x, []) or []:
                    nc = nodes.get(c)
                    if not nc:
                        continue
                    if not cls and (nc.get('type') == 'AST_NAME' or nc.get('labels') == 'string' or nc.get('type') == 'string'):
                        cls = (nc.get('code') or nc.get('name') or '')
                    elif prop == '' and (nc.get('labels') == 'string' or nc.get('type') == 'string'):
                        prop = (nc.get('code') or nc.get('name') or '')
                result['static_props'].append({'id': x, 'class': cls, 'prop': prop})
            elif t == 'AST_INSTANCEOF':
                expr = ''
                cls = ''
                for c in children_of.get(x, []) or []:
                    nc = nodes.get(c)
                    if not nc:
                        continue
                    if expr == '' and nc.get('type') == 'AST_VAR':
                        ss = get_string_children(c, children_of, nodes)
                        expr = ss[0][1] if ss else ''
                    elif cls == '' and (nc.get('type') == 'AST_NAME' or nc.get('labels') == 'string' or nc.get('type') == 'string'):
                        cls = (nc.get('code') or nc.get('name') or '')
                result['instanceof'].append({'id': x, 'expr': expr, 'class': cls})
            elif t == 'AST_CONDITIONAL':
                names = []
                for c in children_of.get(x, []) or []:
                    nc = nodes.get(c)
                    if not nc:
                        continue
                    if nc.get('type') == 'AST_VAR':
                        ss = get_string_children(c, children_of, nodes)
                        if ss:
                            names.append({'id': c, 'name': ss[0][1]})
                    elif nc.get('type') in ('AST_PROP', 'AST_DIM'):
                        ssc = get_all_string_descendants(c, children_of, nodes)
                        if ssc:
                            names.append({'id': c, 'name': ssc[0][1]})
                    elif nc.get('type') in ('AST_NAME', 'AST_CONST') or nc.get('labels') == 'string' or nc.get('type') == 'string':
                        vv = nc.get('code') or nc.get('name') or ''
                        if vv:
                            names.append({'id': c, 'name': vv})
                result['conditional'].append({'id': x, 'names': names})
            elif t == 'AST_BINARY_OP':
                result['binary_ops'].append({'id': x, 'op': nodes[x].get('flags') or ''})
            elif t == 'AST_UNARY_OP':
                result['unary_ops'].append({'id': x, 'op': nodes[x].get('flags') or ''})
    return {'arg': arg, 'path': path, 'line': line, 'targets': targets, 'result': result}

def main():
    base = os.getcwd()
    nodes_path = os.path.join(base, 'nodes.csv')
    rels_path = os.path.join(base, 'rels.csv')
    arg = '/app/phpbb/memberlist.php:98'
    if len(sys.argv) >= 2:
        arg = sys.argv[1]
    st = extract_if_elements(arg, nodes_path, rels_path)
    targets = st['targets']
    result = st['result']
    out_lines = []
    out_lines.append('input ' + arg)
    out_lines.append('if_elem_ids ' + ','.join(str(x) for x in targets))
    for item in result['vars']:
        out_lines.append(f"{item['id']} AST_VAR {item['name']}")
    for item in result['calls']:
        if item.get('kind') == 'method_call':
            args_str = '|'.join([f"{a['id']}:{a['name']}" for a in item['args']])
            out_lines.append(f"{item['id']} AST_METHOD_CALL {item['name']} {item['recv']} " + (str(item['arg_list_id']) if item['arg_list_id'] is not None else '') + ' ' + args_str)
    print('\n'.join(out_lines))
    with open('if_extract_output.txt', 'w', encoding='utf-8') as f:
        f.write('\n'.join(out_lines))

if __name__ == '__main__':
    main()
