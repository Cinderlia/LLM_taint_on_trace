from __future__ import annotations

import re


_SEQ_LINE_RE = re.compile(r'^\s*(\d+)\s')


def _safe_int(x) -> int | None:
    try:
        return int(x)
    except Exception:
        return None


def block_seq_set(block: str) -> set[int]:
    out: set[int] = set()
    if not isinstance(block, str) or not block.strip():
        return out
    for line in block.splitlines():
        m = _SEQ_LINE_RE.match(line)
        if not m:
            continue
        si = _safe_int(m.group(1))
        if si is not None:
            out.add(int(si))
    return out


def _taint_items_for_meta(meta: dict) -> list[dict]:
    merged = meta.get('merged_members')
    if isinstance(merged, list) and merged:
        out = []
        for m in merged:
            if not isinstance(m, dict):
                continue
            tt = (m.get('tt') or '').strip()
            nm = (m.get('nm') or '').strip()
            if tt and nm:
                out.append({'tt': tt, 'nm': nm})
        if out:
            return out
    tt0 = (meta.get('tt') or '').strip()
    nm0 = (meta.get('nm') or '').strip()
    return [{'tt': tt0, 'nm': nm0}] if tt0 and nm0 else []


def _scope_group_for_meta(meta: dict) -> dict | None:
    if not isinstance(meta, dict):
        return None
    block = meta.get('block') or ''
    if not isinstance(block, str) or not block.strip():
        return None
    seq_set = block_seq_set(block)
    return {
        'meta': meta,
        'this_obj': (meta.get('this_obj') or '').strip(),
        'seqs': seq_set,
        'block': block,
        'taints': _taint_items_for_meta(meta),
        'prompt_scope_set': set(meta.get('prompt_scope_set') or set()),
    }


def _is_merge_candidate(group: dict, *, small_scope_max: int) -> bool:
    if not isinstance(group, dict):
        return False
    seqs = group.get('seqs')
    if not isinstance(seqs, set) or not seqs:
        return False
    if len(seqs) >= int(small_scope_max):
        return False
    meta = group.get('meta') or {}
    if isinstance(meta.get('prop_call_scopes_info'), list):
        return False
    return True


def _render_scope_section(group: dict, *, index: int) -> str:
    taints = group.get('taints') or []
    taint_lines = []
    for t in taints:
        if not isinstance(t, dict):
            continue
        tt = (t.get('tt') or '').strip()
        nm = (t.get('nm') or '').strip()
        if tt and nm:
            taint_lines.append(f"- {tt} {nm}")
    taints_part = "\n".join(taint_lines) if taint_lines else "- <UNKNOWN>"
    block = (group.get('block') or '').rstrip()
    return (
        f"【Scope {int(index)}】\n"
        "请只在这个Scope里的代码中，找出会影响下面这些污点取值的变量和函数调用；不要引用其他Scope中的赋值关系。\n"
        "污点：\n" 
        + taints_part
        + "\n"
        + block
        + "\n"
    )


def build_composite_taint_prompt(scope_groups: list[dict]) -> str:
    sections = []
    for i, g in enumerate(scope_groups or [], start=1):
        sections.append(_render_scope_section(g, index=i))
    body = "\n".join(sections).strip() + "\n"
    return (
        "你是一个代码分析助手。\n"
        "下面给出若干个Scope，每个Scope里都对应了一组污点。请分别在各自Scope内分析影响因素。\n"
        "如果某个污点的影响因素不在它自己的Scope里，就不要跨Scope推断。\n"
        "type字段尽量基于字面形式判断类型，仅允许：AST_VAR、AST_PROP、AST_DIM、AST_METHOD_CALL、AST_STATIC_CALL、AST_CALL。\n"
        "通过中间变量间接影响时，把中间变量放入intermediates，同时把最终影响因素放入taints。\n"
        "只输出合法JSON，不要输出解释或Markdown。\n\n"
        "代码（每行格式为：seq + 源码行）：\n"
        + body
        +"\n统一把所有Scope里的污点都放到taints字段里，所有中间变量都放到intermediates字段里，只输出一个JSON对象。\n"
        + "\n输出JSON格式必须为：\n"
        "{\"taints\":[{\"seq\":51529,\"type\":\"AST_VAR\",\"name\":\"negate\"}],\"intermediates\":[{\"seq\":51573,\"type\":\"AST_VAR\",\"name\":\"ret\"}]}\n"
        "如果找不到新污点，输出：\n"
        "{\"taints\":[],\"intermediates\":[]}\n"
    )


def pack_small_scopes_into_composites(
    metas: list[dict],
    *,
    small_scope_max: int = 30,
    max_prompt_seqs: int = 100,
) -> list[dict]:
    groups = []
    kept = []
    for m in metas or []:
        g = _scope_group_for_meta(m)
        if g is None:
            kept.append(m)
            continue
        if _is_merge_candidate(g, small_scope_max=small_scope_max):
            groups.append(g)
        else:
            kept.append(m)

    by_obj: dict[str, list[dict]] = {}
    for g in groups:
        key = (g.get('this_obj') or '').strip()
        by_obj.setdefault(key, []).append(g)

    composite_metas: list[dict] = []
    for _, lst in by_obj.items():
        pending = list(lst)
        pending.sort(key=lambda x: len(x.get('seqs') or set()))
        while pending:
            bucket = []
            bucket_seqs: set[int] = set()
            i = 0
            while i < len(pending):
                g = pending[i]
                seqs = g.get('seqs') or set()
                merged = bucket_seqs.union(seqs)
                if len(merged) >= int(max_prompt_seqs):
                    i += 1
                    continue
                bucket.append(g)
                bucket_seqs = merged
                pending.pop(i)
                continue
            if not bucket:
                bucket.append(pending.pop(0))
            if len(bucket) <= 1:
                kept.append((bucket[0] or {}).get('meta') or {})
                continue
            rep_meta = dict((bucket[0] or {}).get('meta') or {})
            rep_meta['key'] = None
            rep_meta['merged_members'] = None
            rep_meta['composite_scopes'] = [
                {'taints': (g.get('taints') or []), 'seq_count': len(g.get('seqs') or set())}
                for g in bucket
            ]
            rep_meta['prompt_scope_set'] = set().union(*(g.get('prompt_scope_set') or set() for g in bucket))
            rep_meta['scope_only_seqs'] = frozenset(bucket_seqs)
            infos = []
            for g in bucket:
                info = ((g.get('meta') or {}).get('call_param_arg_info') or None)
                if isinstance(info, dict):
                    infos.append(info)
            if infos:
                rep_meta['call_param_arg_info'] = infos
            rep_meta['prompt'] = build_composite_taint_prompt(bucket)
            composite_metas.append(rep_meta)

    return kept + composite_metas
