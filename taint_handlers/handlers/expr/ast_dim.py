"""Thin wrapper taint handler for `AST_DIM` nodes (array/index access)."""

from . import ast_var


def _parse_dim_base_prop(taint) -> tuple[str, str]:
    if not isinstance(taint, dict):
        return '', ''
    base = (taint.get('base') or '').strip()
    key = (taint.get('key') or '').strip()
    nm = (taint.get('name') or '').strip()
    if base and '[' in base:
        base = base.split('[', 1)[0].strip()
    if nm and not base:
        v = nm.replace('.', '->')
        if '[' in v:
            v = v.split('[', 1)[0].strip()
        base = v
    base = base.lstrip('$')
    if not base:
        return '', ''
    if '->' not in base:
        return '', ''
    recv, prop = base.split('->', 1)
    recv = (recv or '').strip().lstrip('$')
    prop = (prop or '').strip()
    if not recv or not prop:
        return '', ''
    return recv, prop


def process(taint, ctx):
    """Delegate `AST_DIM` handling to the shared variable handler logic."""
    res = ast_var.process(taint, ctx)
    recv, prop = _parse_dim_base_prop(taint)
    if recv and prop:
        try:
            start_seq = int(taint.get('seq'))
        except Exception:
            start_seq = None
        if start_seq is not None:
            try:
                from . import ast_prop

                kept_locs, markers, stats = ast_prop.expand_receiver_method_scopes(
                    start_seq=int(start_seq),
                    ctx=ctx,
                    recv_obj=recv,
                    target_prop=prop,
                )
                if kept_locs:
                    extra = ctx.setdefault('_llm_extra_prompt_locs', [])
                    existing = set(extra or [])
                    for loc in kept_locs:
                        if not loc or loc in existing:
                            continue
                        existing.add(loc)
                        extra.append(loc)
                if markers:
                    ctx.setdefault('_llm_scope_markers', []).extend(list(markers))
                dbg_ctx = ctx.get('debug')
                if isinstance(dbg_ctx, dict):
                    dbg_ctx.setdefault('ast_dim', []).append({'recv': recv, 'prop': prop, 'stats': stats})
                lg = ctx.get('logger')
                if lg is not None:
                    try:
                        lg.debug(
                            'ast_dim_expand',
                            recv=recv,
                            prop=prop,
                            start_seq=int(start_seq),
                            **(stats or {}),
                        )
                    except Exception:
                        pass
            except Exception:
                pass
    return res
