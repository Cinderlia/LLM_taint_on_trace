"""
Helpers for building LLM prompts and translating trace locations into code blocks.

This module provides:
- Prompt template rendering for taint expansion
- Trace-index based selection of representative seqs for `(path,line)` locations
- Conversion of scope locations into `seq + source_line` code blocks
"""

from string import Template
from typing import Any
import json
import os

from utils.extractors.if_extract import norm_trace_path


def render_template(template: str, **kwargs: Any) -> str:
    """Render a string.Template using `safe_substitute`."""
    return Template(template).safe_substitute(**kwargs)

_DEFAULT_LLM_TAINT_TEMPLATE_TAIL = (
    "，并以json格式输出变量名、变量类型和所在行的id（id就是每行开头的seq）。\n"
    "type字段仅为猜测，尽量基于字面形式判断类型。\n"
    "仅允许输出以下类型：AST_VAR、AST_PROP、AST_DIM、AST_METHOD_CALL、AST_STATIC_CALL、AST_CALL。\n"
    "必须列出所有能够影响到{name}取值的变量和函数调用，不管是直接影响还是间接地影响。\n"
    "还可能通过中间变量间接影响：A = B; {name} = A;\n"
    "如果是通过中间变量间接影响，请把中间变量放入intermediates，同时把最终影响{name}的所有因素放入taints。\n"
    "如果没有找到新的影响因素，仍然必须输出合法json，确保字段存在。\n"
    "必须输出合法的json格式，只输出json，不要输出任何解释性文字或Markdown。\n\n"
    "代码（每行格式为：seq + 源码行）：\n"
    "{result_set}\n\n"
    "输出json格式必须为：\n"
    "{\"taints\":[{\"seq\":51529,\"type\":\"AST_VAR\",\"name\":\"negate\"}],\"intermediates\":[{\"seq\":51573,\"type\":\"AST_VAR\",\"name\":\"ret\"}]}\n"
    "如果找不到新污点，输出：\n"
    "{\"taints\":[],\"intermediates\":[]}\n"
)

DEFAULT_LLM_TAINT_TEMPLATE_VAR = (
    "你是一个代码分析助手,请你找出下列代码中"
    "所有的有可能影响到{type}变量{name}取值的变量和函数调用"
    + _DEFAULT_LLM_TAINT_TEMPLATE_TAIL
)

DEFAULT_LLM_TAINT_TEMPLATE_FUNC = (
    "你是一个代码分析助手,请你找出下列代码中"
    "所有的有可能影响到{type}函数{name}的返回值的变量和函数调用"
    + _DEFAULT_LLM_TAINT_TEMPLATE_TAIL
)

DEFAULT_LLM_TAINT_TEMPLATE = DEFAULT_LLM_TAINT_TEMPLATE_VAR

def _name_with_this_alias(tt: str, name: str) -> str:
    t = (tt or '').strip()
    v = (name or '').strip()
    if not v or '或者' in v:
        return v
    if t not in ('AST_PROP', 'AST_METHOD_CALL'):
        return v
    if v.startswith('this->') or v.startswith('$this->'):
        return v
    if '->' not in v:
        return v
    tail = (v.split('->', 1)[1] or '').strip()
    if not tail:
        return v
    alt = f'this->{tail}'
    if alt == v:
        return v
    return f'{v}或者{alt}'

def render_llm_taint_prompt(*, template: str, taint_type: str, taint_name: str, result_set: str) -> str:
    """Render the final prompt text for a given taint and its scoped code block."""
    tt = (taint_type or '').strip()
    use_default = (template is None) or (template in (DEFAULT_LLM_TAINT_TEMPLATE, DEFAULT_LLM_TAINT_TEMPLATE_VAR, DEFAULT_LLM_TAINT_TEMPLATE_FUNC))
    if use_default:
        t = DEFAULT_LLM_TAINT_TEMPLATE_FUNC if tt in ('AST_METHOD_CALL', 'AST_CALL') else DEFAULT_LLM_TAINT_TEMPLATE_VAR
    else:
        t = template
    if tt == 'AST_PROP':
        t += (
            "\n注意：代码块中可能包含展开的函数scope，范围用FUNCTION_SCOPE_START和FUNCTION_SCOPE_END标记。"
            "\n在类方法的函数scope内，this指代当前对象本身：this->x 等价于 对象->x。"
        )
    name_for_prompt = _name_with_this_alias(tt, taint_name)
    return (
        (t.replace('{type}', str(taint_type or ''))
          .replace('{name}', str(name_for_prompt or ''))
          .replace('{result_set}', str(result_set or '')))
    )


def _strip_app_prefix(p: str) -> str:
    """Strip leading `/app/` or `/` to match project-relative paths."""
    p = (p or '').strip()
    if p.startswith('/app/'):
        return p[5:]
    if p.startswith('/'):
        return p[1:]
    return p


def _parse_loc(loc: str):
    """Parse a `path:line` locator into `(normalized_path, line)`."""
    if not loc or ':' not in loc:
        return None
    p, ln_s = loc.rsplit(':', 1)
    try:
        ln = int(ln_s)
    except:
        return None
    p = _strip_app_prefix(p).replace('\\', '/')
    return p, ln


def _load_trace_index_min_seqs(trace_index_path: str):
    """Load `(path,line)->min_seq` mapping from a `trace_index.json` file."""
    if not trace_index_path:
        return {}
    if not os.path.exists(trace_index_path):
        return {}
    with open(trace_index_path, 'r', encoding='utf-8', errors='replace') as f:
        try:
            obj = json.load(f)
        except Exception:
            return {}
    recs = obj.get('records') if isinstance(obj, dict) else obj
    if not isinstance(recs, list):
        return {}
    out = {}
    for r in recs:
        if not isinstance(r, dict):
            continue
        p = r.get('path')
        ln = r.get('line')
        if not p or ln is None:
            continue
        seqs = r.get('seqs') or []
        if not seqs:
            continue
        try:
            seq_min = min(int(x) for x in seqs)
        except:
            continue
        k = (p, ln)
        cur = out.get(k)
        if cur is None or seq_min < cur:
            out[k] = seq_min
    return out


def resolve_source_path(scope_root: str, src_path: str, windows_root: str = r'D:\files\witcher\app') -> str:
    """Resolve a source path from trace/CPG to a local filesystem path."""
    scope_root = (scope_root or '').strip()
    src_path = (src_path or '').strip()
    src_path = src_path.replace('\\', '/')
    if os.name == 'nt' and scope_root.startswith('/app'):
        suffix = scope_root[4:]
        suffix = _strip_app_prefix(suffix).replace('/', os.sep)
        scope_root = os.path.join(windows_root, suffix) if suffix else windows_root
    if os.name == 'nt' and src_path.startswith('/app/'):
        src_path = _strip_app_prefix(src_path)
    if src_path.startswith('/'):
        return src_path
    return os.path.join(scope_root, src_path.replace('/', os.sep))


def build_seqs_by_loc(trace_index_records):
    """Build `(path,line)->sorted unique seqs` mapping from trace index records."""
    out = {}
    for rec in trace_index_records or []:
        if not isinstance(rec, dict):
            continue
        p = rec.get('path')
        ln = rec.get('line')
        if not p or ln is None:
            continue
        try:
            k = (norm_trace_path(str(p)), int(ln))
        except Exception:
            continue
        buf = out.get(k)
        if buf is None:
            buf = []
            out[k] = buf
        for s in rec.get('seqs') or []:
            try:
                buf.append(int(s))
            except Exception:
                continue
    for k, buf in list(out.items()):
        if not buf:
            out.pop(k, None)
            continue
        buf.sort()
        uniq = []
        last = None
        for x in buf:
            if last is None or x != last:
                uniq.append(x)
                last = x
        out[k] = uniq
    return out


def build_seq_groups_by_loc(trace_index_records):
    """Build `(path,line)->seq groups` where each group is a contiguous trace record."""
    out = {}
    for rec in trace_index_records or []:
        if not isinstance(rec, dict):
            continue
        p = rec.get('path')
        ln = rec.get('line')
        if not p or ln is None:
            continue
        try:
            k = (norm_trace_path(str(p)), int(ln))
        except Exception:
            continue
        seqs = []
        for s in rec.get('seqs') or []:
            try:
                seqs.append(int(s))
            except Exception:
                continue
        if not seqs:
            continue
        seqs.sort()
        groups = out.get(k)
        if groups is None:
            groups = []
            out[k] = groups
        groups.append({'min': int(seqs[0]), 'max': int(seqs[-1]), 'seqs': seqs})
    for k, groups in list(out.items()):
        if not groups:
            out.pop(k, None)
            continue
        groups.sort(key=lambda g: (int(g.get('min') or 0), int(g.get('max') or 0)))
        out[k] = groups
    return out


def pick_seq_by_ref(groups, ref_seq: int | None, prefer: str = 'forward'):
    """Pick a representative seq from grouped seq ranges given a reference seq."""
    if not groups:
        return None
    if ref_seq is None:
        g0 = groups[0]
        return int(g0.get('min')) if g0 else None
    try:
        r = int(ref_seq)
    except Exception:
        g0 = groups[0]
        return int(g0.get('min')) if g0 else None
    if (prefer or '').strip() == 'backward':
        picked = None
        for g in groups:
            try:
                gmin = int(g.get('min'))
            except Exception:
                continue
            if gmin <= r:
                picked = g
                continue
            break
        return int(picked.get('min')) if picked else None
    for g in groups:
        try:
            gmin = int(g.get('min'))
        except Exception:
            continue
        if gmin >= r:
            return int(gmin)
    return None


def loc_to_path_line(loc):
    """Normalize a locator (dict or string) to `(path,line)` or return None."""
    if isinstance(loc, dict):
        p = loc.get('path')
        ln = loc.get('line')
        if p and ln is not None:
            try:
                return norm_trace_path(str(p)), int(ln)
            except Exception:
                pass
        loc2 = loc.get('loc')
        if isinstance(loc2, str) and loc2:
            pr = _parse_loc(loc2)
            if pr:
                return norm_trace_path(pr[0]), int(pr[1])
        return None
    if isinstance(loc, str):
        pr = _parse_loc(loc)
        if pr:
            return norm_trace_path(pr[0]), int(pr[1])
        return None
    return None


def ensure_seqs_by_loc(ctx):
    """Cache and return `(path,line)->seqs` mapping inside ctx."""
    if not isinstance(ctx, dict):
        return {}
    seqs_by_loc = ctx.get('_seqs_by_loc')
    if seqs_by_loc is None:
        seqs_by_loc = build_seqs_by_loc(ctx.get('trace_index_records') or [])
        ctx['_seqs_by_loc'] = seqs_by_loc
    return seqs_by_loc


def ensure_seq_groups_by_loc(ctx):
    """Cache and return `(path,line)->seq groups` mapping inside ctx."""
    if not isinstance(ctx, dict):
        return {}
    groups_by_loc = ctx.get('_seq_groups_by_loc')
    if groups_by_loc is None:
        groups_by_loc = build_seq_groups_by_loc(ctx.get('trace_index_records') or [])
        ctx['_seq_groups_by_loc'] = groups_by_loc
    return groups_by_loc


def _filter_prompt_locs(locs, ctx):
    if not locs or not isinstance(ctx, dict):
        return list(locs or [])
    try:
        from taint_handlers.handlers.helpers.ast_var_include import (
            _filter_define_locs_from_include,
            _filter_func_def_locs_from_include,
        )
    except Exception:
        return list(locs or [])
    recs = ctx.get('trace_index_records') or []
    nodes = ctx.get('nodes') or {}
    children_of = ctx.get('children_of') or {}
    parent_of = ctx.get('parent_of') or {}
    def _loc_key(x):
        if not x:
            return None
        if isinstance(x, dict):
            lk = (x.get('loc') or '').strip()
            if lk:
                return lk
            p = (x.get('path') or '').strip()
            ln = x.get('line')
            if p and ln is not None:
                try:
                    return f"{p}:{int(ln)}"
                except Exception:
                    return None
            return None
        if isinstance(x, str):
            return x
        return None
    loc_keys = []
    for x in locs or []:
        k = _loc_key(x)
        if k:
            loc_keys.append(k)
    if not loc_keys:
        return list(locs or [])
    loc_keys = _filter_func_def_locs_from_include(list(loc_keys), recs, nodes, ctx)
    loc_keys = _filter_define_locs_from_include(list(loc_keys), recs, nodes, children_of, parent_of, ctx)
    keep = set(loc_keys)
    if not keep:
        return []
    out = []
    for x in locs or []:
        k = _loc_key(x)
        if k and k in keep:
            out.append(x)
    return out


def locs_to_seq_code_block(locs, ctx, *, prefer: str = 'forward'):
    """Convert a list of locators into a sorted `seq + source_line` code block string."""
    scope_root = (ctx.get('scope_root') if isinstance(ctx, dict) else None) or '/app'
    windows_root = (ctx.get('windows_root') if isinstance(ctx, dict) else None) or r'D:\files\witcher\app'
    ref_seq = (ctx.get('_llm_ref_seq') if isinstance(ctx, dict) else None)
    if ref_seq is None and isinstance(ctx, dict):
        ref_seq = ctx.get('input_seq')
    groups_by_loc = ensure_seq_groups_by_loc(ctx)
    preamble_locs = (ctx.get('_llm_scope_preamble_locs') if isinstance(ctx, dict) else None) or []
    preamble_locs = _filter_prompt_locs(preamble_locs, ctx)
    locs = _filter_prompt_locs(locs, ctx)
    starts = set()
    ends = set()
    if isinstance(ctx, dict):
        for m in ctx.get('_llm_scope_markers') or []:
            if not isinstance(m, dict):
                continue
            if (m.get('kind') or '').strip() != 'function_scope':
                continue
            st = m.get('start')
            ed = m.get('end')
            if isinstance(st, str) and st:
                starts.add(st)
            if isinstance(ed, str) and ed:
                ends.add(ed)

    preamble_set = set()
    preamble_lines = []
    pj = 0
    for loc in preamble_locs or []:
        if not loc:
            continue
        loc_key = loc.get('loc') if isinstance(loc, dict) else loc
        if not loc_key:
            pr = loc_to_path_line(loc)
            if pr:
                p0, ln0 = pr
                loc_key = f"{p0}:{int(ln0)}"
        if not loc_key or loc_key in preamble_set:
            continue
        pr = loc_to_path_line(loc)
        if not pr:
            continue
        p, ln = pr
        seq = None
        if isinstance(loc, dict) and loc.get('seq') is not None:
            try:
                seq = int(loc.get('seq'))
            except Exception:
                seq = None
        if seq is None:
            seq = pick_seq_by_ref(groups_by_loc.get((p, int(ln))) or [], ref_seq, prefer=prefer)
        if seq is None:
            continue
        fs = resolve_source_path(scope_root, p, windows_root=windows_root)
        code = ''
        try:
            with open(fs, 'r', encoding='utf-8', errors='replace') as f:
                for i, line in enumerate(f, start=1):
                    if i == int(ln):
                        code = line.strip()
                        break
        except Exception:
            code = ''
        if not code:
            continue
        if loc_key in starts:
            preamble_lines.append((int(seq), 0, pj, f"{seq} // FUNCTION_SCOPE_START"))
            pj += 1
        preamble_lines.append((int(seq), 1, pj, f"{seq} {code}"))
        pj += 1
        if loc_key in ends:
            preamble_lines.append((int(seq), 2, pj, f"{seq} // FUNCTION_SCOPE_END"))
            pj += 1
        preamble_set.add(loc_key)
    preamble_lines.sort(key=lambda x: (x[0], x[1], x[2]))
    preamble_out = [s for _, _, _, s in preamble_lines]

    out_lines = []
    j = 0
    seen_loc = set()
    for loc in locs or []:
        if not loc:
            continue
        loc_key = loc.get('loc') if isinstance(loc, dict) else loc
        if not loc_key:
            pr = loc_to_path_line(loc)
            if pr:
                p0, ln0 = pr
                loc_key = f"{p0}:{int(ln0)}"
        if not loc_key or loc_key in preamble_set or loc_key in seen_loc:
            continue
        seen_loc.add(loc_key)
        pr = loc_to_path_line(loc)
        if not pr:
            continue
        p, ln = pr
        seq = None
        if isinstance(loc, dict) and loc.get('seq') is not None:
            try:
                seq = int(loc.get('seq'))
            except Exception:
                seq = None
        if seq is None:
            seq = pick_seq_by_ref(groups_by_loc.get((p, int(ln))) or [], ref_seq, prefer=prefer)
        if seq is None:
            continue
        fs = resolve_source_path(scope_root, p, windows_root=windows_root)
        code = ''
        try:
            with open(fs, 'r', encoding='utf-8', errors='replace') as f:
                for i, line in enumerate(f, start=1):
                    if i == int(ln):
                        code = line.strip()
                        break
        except Exception:
            code = ''
        if not code:
            continue
        if loc_key in starts:
            out_lines.append((int(seq), 0, j, f"{seq} // FUNCTION_SCOPE_START"))
            j += 1
        out_lines.append((int(seq), 1, j, f"{seq} {code}"))
        j += 1
        if loc_key in ends:
            out_lines.append((int(seq), 2, j, f"{seq} // FUNCTION_SCOPE_END"))
            j += 1
    out_lines.sort(key=lambda x: (x[0], x[1], x[2]))
    rest = [s for _, _, _, s in out_lines]
    if preamble_out and rest:
        return '\n'.join(list(preamble_out) + [''] + rest)
    if preamble_out:
        return '\n'.join(preamble_out)
    return '\n'.join(rest)


def locs_to_scope_seqs(locs, ctx, *, ref_seq: int | None, prefer: str = 'forward'):
    """Convert locators into a sorted unique list of representative seqs."""
    groups_by_loc = ensure_seq_groups_by_loc(ctx)
    out = []
    seen = set()
    for loc in locs or []:
        if isinstance(loc, dict) and loc.get('seq') is not None:
            try:
                seq = int(loc.get('seq'))
            except Exception:
                seq = None
            if seq is None:
                continue
            if seq in seen:
                continue
            seen.add(seq)
            out.append(int(seq))
            continue
        pr = loc_to_path_line(loc)
        if not pr:
            continue
        p, ln = pr
        seq = pick_seq_by_ref(groups_by_loc.get((p, int(ln))) or [], ref_seq, prefer=prefer)
        if seq is None:
            continue
        if seq in seen:
            continue
        seen.add(seq)
        out.append(int(seq))
    out.sort()
    return out


# Summary: Dedupe LLM scope requests by skipping scopes already covered by prior calls.
def should_skip_llm_scope(scope_seqs, ctx, *, dedupe_key: str | None = None) -> bool:
    """Return True if a given scope has already been processed for LLM calls."""
    if not isinstance(ctx, dict):
        return False
    lg = ctx.get('logger')
    cur = []
    for x in scope_seqs or []:
        try:
            cur.append(int(x))
        except Exception:
            continue
    if not cur:
        if lg is not None and ctx.get('llm_scope_debug'):
            try:
                lg.debug('llm_scope_dedupe_empty_scope_seqs')
            except Exception:
                pass
        return False
    cur_set = frozenset(cur)
    dk = (dedupe_key or '').strip() or None
    history = ctx.setdefault('_llm_scope_history', [])
    for i, prev in enumerate(history or []):
        try:
            prev_key = None
            prev_set = None
            if isinstance(prev, dict):
                prev_key = (prev.get('key') or '').strip() or None
                prev_set = prev.get('scope')
            else:
                prev_set = prev
            if prev_set is None:
                continue
            if dk is not None and prev_key is not None and dk != prev_key:
                continue
            # if cur_set.issubset(set(prev_set)):
            #     if lg is not None and ctx.get('llm_scope_debug'):
            #         try:
            #             cur_sorted = sorted(cur_set)
            #             prev_sorted = sorted(set(prev_set))
            #             lg.debug(
            #                 'llm_scope_dedupe_skip',
            #                 cur_len=len(cur_set),
            #                 prev_len=len(set(prev_set)),
            #                 prev_index=i,
            #                 cur_preview=cur_sorted[:12],
            #                 prev_preview=prev_sorted[:12],
            #             )
            #         except Exception:
            #             pass
            #     return True
        except Exception:
            continue
    if history:
        pruned = []
        for prev in history:
            try:
                if isinstance(prev, dict):
                    prev_key = (prev.get('key') or '').strip() or None
                    prev_scope = prev.get('scope')
                    if prev_scope is None:
                        pruned.append(prev)
                        continue
                    if dk is not None and prev_key is not None and dk != prev_key:
                        pruned.append(prev)
                        continue
                    if set(prev_scope).issubset(cur_set):
                        continue
                    pruned.append(prev)
                    continue
                if set(prev).issubset(cur_set):
                    continue
            except Exception:
                pruned.append(prev)
                continue
            pruned.append(prev)
        history[:] = pruned
    history.append({'key': dk, 'scope': cur_set} if dk is not None else cur_set)
    if lg is not None and ctx.get('llm_scope_debug'):
        try:
            lg.debug(
                'llm_scope_dedupe_check',
                cur_len=len(cur_set),
                history_len=len(history),
                cur_preview=sorted(cur_set)[:12],
            )
        except Exception:
            pass
    return False


def map_result_set_to_source_lines(scope_root: str, result_set, trace_index_path: str = os.path.join("tmp", "trace_index.json"), windows_root: str = r'D:\files\witcher\app'):
    """Map a result-set of locators to `{seq,path,line,code}` entries with source lines."""
    min_seqs = _load_trace_index_min_seqs(trace_index_path)
    out = []
    for it in result_set or []:
        if isinstance(it, dict):
            p = it.get('path')
            ln = it.get('line')
            seq = it.get('seq')
            if (not p or ln is None) and it.get('loc'):
                pr = _parse_loc(it.get('loc'))
                if pr:
                    p, ln = pr
            if not p or ln is None:
                continue
            if seq is None:
                seq = min_seqs.get((p, ln))
            fs_path = resolve_source_path(scope_root, p, windows_root=windows_root)
            code = ''
            try:
                with open(fs_path, 'r', encoding='utf-8', errors='replace') as f:
                    for i, line in enumerate(f, start=1):
                        if i == int(ln):
                            code = line.rstrip('\n')
                            break
            except Exception:
                code = ''
            out.append({'seq': seq, 'path': p, 'line': int(ln), 'code': code})
            continue
        if isinstance(it, str):
            pr = _parse_loc(it)
            if not pr:
                continue
            p, ln = pr
            seq = min_seqs.get((p, ln))
            fs_path = resolve_source_path(scope_root, p, windows_root=windows_root)
            code = ''
            try:
                with open(fs_path, 'r', encoding='utf-8', errors='replace') as f:
                    for i, line in enumerate(f, start=1):
                        if i == int(ln):
                            code = line.rstrip('\n')
                            break
            except Exception:
                code = ''
            out.append({'seq': seq, 'path': p, 'line': int(ln), 'code': code})
    return out


def generate_taint_prompt(result_set_or_path, scope_root: str, base_prompt: str = '', trace_index_path: str = os.path.join("tmp", "trace_index.json"), windows_root: str = r'D:\files\witcher\app', taint_sources=None) -> str:
    """Build a plain-text prompt from taint sources and `seq + code` source lines."""
    rs = None
    ts = taint_sources
    if isinstance(result_set_or_path, str) and os.path.exists(result_set_or_path):
        with open(result_set_or_path, 'r', encoding='utf-8', errors='replace') as f:
            obj = json.load(f)
        if isinstance(obj, dict):
            rs = obj.get('result_set')
            if ts is None:
                ts = obj.get('taint_sources') or obj.get('taints')
    else:
        rs = result_set_or_path
    lines = map_result_set_to_source_lines(scope_root, rs or [], trace_index_path=trace_index_path, windows_root=windows_root)
    chunks = [base_prompt] if base_prompt else []
    for it in ts or []:
        if isinstance(it, str):
            s = it.strip()
            if s:
                chunks.append(s)
            continue
        if isinstance(it, dict):
            tt = (it.get('type') or '').strip()
            src = (it.get('source') or it.get('name') or '').strip()
            if tt and src:
                chunks.append(f"{tt} {src}")
    for it in lines:
        seq = it.get('seq')
        if seq is None:
            continue
        code = (it.get('code') or '').strip()
        chunks.append(f"{seq} {code}".rstrip())
    return '\n'.join(x for x in chunks if x is not None)


def generate_llm_taint_prompt_from_result_set(
    *,
    taint_type: str,
    taint_name: str,
    result_set_or_path,
    scope_root: str,
    template: str | None = None,
    trace_index_path: str = os.path.join("tmp", "trace_index.json"),
    windows_root: str = r'D:\files\witcher\app',
) -> str:
    """Generate an LLM prompt for one taint using a scoped result-set as context."""
    body = generate_taint_prompt(
        result_set_or_path,
        scope_root=scope_root,
        base_prompt='',
        trace_index_path=trace_index_path,
        windows_root=windows_root,
        taint_sources=None,
    )
    return render_llm_taint_prompt(
        template=(template or DEFAULT_LLM_TAINT_TEMPLATE),
        taint_type=taint_type,
        taint_name=taint_name,
        result_set=body,
    )
