import csv
import os
from var_utils import build_children_parent, extract_varlike_for_nodes
csv.field_size_limit(10**9)

def load_nodes(nodes_path):
    nodes = {}
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
                'code': row.get('code') or '',
                'name': row.get('name') or ''
            }
    return nodes

def load_ast_edges(rels_path):
    children_of = {}
    with open(rels_path, 'r', encoding='utf-8', errors='replace') as f:
        reader = csv.DictReader(f, delimiter='\t')
        for row in reader:
            if (row.get('type') or '') != 'PARENT_OF':
                continue
            try:
                si = int(row.get('start') or '')
                ei = int(row.get('end') or '')
            except:
                continue
            lst = children_of.get(si)
            if lst is None:
                lst = []
                children_of[si] = lst
            lst.append(ei)
    return children_of

def collect_descendants(nid, children_of):
    res = []
    q = [nid]
    seen = set()
    while q:
        x = q.pop()
        if x in seen:
            continue
        seen.add(x)
        if x != nid:
            res.append(x)
        for c in children_of.get(x, []) or []:
            q.append(c)
    return res

def main():
    base = os.getcwd()
    nodes_path = os.path.join(base, 'nodes.csv')
    rels_path = os.path.join(base, 'rels.csv')
    nodes = load_nodes(nodes_path)
    children_of, parent_of = build_children_parent(rels_path)
    types_seen = set()
    for nid, nd in nodes.items():
        if nd.get('type') != 'AST_IF_ELEM':
            continue
        desc = collect_descendants(nid, children_of)
        items = extract_varlike_for_nodes(desc, children_of, parent_of, nodes)
        for it in items:
            t = it.get('type')
            if t:
                types_seen.add(t)
    lines = sorted(types_seen)
    out = '\n'.join(lines)
    print(out)
    with open('if_elem_types.txt', 'w', encoding='utf-8') as f:
        f.write(out)

if __name__ == '__main__':
    main()
