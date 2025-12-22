import json
import re


def _try_load_json(s: str):
    if not isinstance(s, str):
        return None
    s = s.strip()
    if not s:
        return None
    try:
        obj = json.loads(s)
    except Exception:
        return None
    return obj


def _extract_json_text(text: str) -> str | None:
    if not isinstance(text, str):
        return None
    t = text.strip()
    if not t:
        return None
    m = re.search(r"```(?:json)?\s*([\s\S]*?)\s*```", t, flags=re.IGNORECASE)
    if m:
        inner = (m.group(1) or '').strip()
        if inner.startswith('{') and inner.endswith('}'):
            return inner
    i = t.find('{')
    j = t.rfind('}')
    if i >= 0 and j >= 0 and j > i:
        return t[i : j + 1]
    return None


def parse_llm_taint_response(text: str):
    raw_obj = _try_load_json(text)
    if raw_obj is None:
        js = _extract_json_text(text)
        raw_obj = _try_load_json(js or '')
    if not isinstance(raw_obj, dict):
        return {'taints': [], 'edges': [], 'seqs': []}
    taints = raw_obj.get('taints')
    edges = raw_obj.get('edges')
    seqs = raw_obj.get('seqs')
    if not isinstance(taints, list):
        taints = []
    if not isinstance(edges, list):
        edges = []
    if not isinstance(seqs, list):
        seqs = []
    out_taints = []
    seen = set()
    for it in taints:
        if not isinstance(it, dict):
            continue
        seq = it.get('seq')
        tt = (it.get('type') or '').strip()
        nm = (it.get('name') or '').strip()
        try:
            seq_i = int(seq)
        except Exception:
            continue
        if not tt or not nm:
            continue
        k = (seq_i, tt, nm)
        if k in seen:
            continue
        seen.add(k)
        out_taints.append({'seq': seq_i, 'type': tt, 'name': nm})
    out_edges = []
    seen_e = set()
    for e in edges:
        if not isinstance(e, dict):
            continue
        src = e.get('src')
        dst = e.get('dst')
        if not isinstance(src, dict) or not isinstance(dst, dict):
            continue
        try:
            src_seq = int(src.get('seq'))
            dst_seq = int(dst.get('seq'))
        except Exception:
            continue
        src_type = (src.get('type') or '').strip()
        dst_type = (dst.get('type') or '').strip()
        src_name = (src.get('name') or '').strip()
        dst_name = (dst.get('name') or '').strip()
        if not src_type or not dst_type or not src_name or not dst_name:
            continue
        k = (src_seq, src_type, src_name, dst_seq, dst_type, dst_name)
        if k in seen_e:
            continue
        seen_e.add(k)
        out_edges.append({
            'src': {'seq': src_seq, 'type': src_type, 'name': src_name},
            'dst': {'seq': dst_seq, 'type': dst_type, 'name': dst_name},
        })
    out_seqs = []
    seen_s = set()
    for s in seqs:
        try:
            si = int(s)
        except Exception:
            continue
        if si in seen_s:
            continue
        seen_s.add(si)
        out_seqs.append(si)
    out_seqs.sort()
    return {'taints': out_taints, 'edges': out_edges, 'seqs': out_seqs}
