import os

from logger import Logger
from taint_handlers import REGISTRY


def _get_logger(ctx):
    if not isinstance(ctx, dict):
        return None
    lg = ctx.get('logger')
    if lg is not None:
        return lg
    test_dir = ctx.get('test_dir') or os.path.join(os.getcwd(), 'test')
    try:
        lg = Logger(base_dir=test_dir, min_level='INFO', name='joerntrace', also_console=False)
        ctx['logger'] = lg
        return lg
    except Exception:
        return None


def _taint_brief(t):
    if not isinstance(t, dict):
        return None
    out = {
        'id': t.get('id'),
        'seq': t.get('seq'),
        'type': t.get('type'),
    }
    nm = t.get('name')
    if isinstance(nm, str) and nm:
        out['name'] = nm
    recv = t.get('recv')
    if isinstance(recv, str) and recv:
        out['recv'] = recv
    return out


def _queue_brief(q, limit: int = 50):
    out = []
    for it in (q or [])[: max(0, int(limit))]:
        b = _taint_brief(it)
        if b:
            out.append(b)
    return out


def _taint_display(taint, nodes, children_of):
    from .llm_response import _node_display

    tt = (taint.get('type') or '').strip()
    if not tt:
        return '', ''
    if tt == 'AST_VAR':
        nm = (taint.get('name') or '').strip()
        if not nm and taint.get('id') is not None:
            _, nm = _node_display(taint.get('id'), nodes, children_of)
        return tt, nm
    if tt == 'AST_PROP':
        base = (taint.get('base') or '').strip()
        prop = (taint.get('prop') or '').strip()
        if base and prop:
            return tt, f"{base}->{prop}"
        nm = (taint.get('name') or '').strip()
        if not nm and taint.get('id') is not None:
            _, nm = _node_display(taint.get('id'), nodes, children_of)
        nm = nm.replace('.', '->')
        return tt, nm
    if tt == 'AST_DIM':
        base = (taint.get('base') or '').strip()
        key = (taint.get('key') or '').strip()
        if base and key:
            return tt, f"{base}[{key}]"
        nm = (taint.get('name') or '').strip()
        if not nm and taint.get('id') is not None:
            _, nm = _node_display(taint.get('id'), nodes, children_of)
        return tt, nm
    if tt == 'AST_CALL':
        nm = (taint.get('name') or '').strip()
        if not nm and taint.get('id') is not None:
            _, nm = _node_display(taint.get('id'), nodes, children_of)
        if nm and not nm.endswith('()'):
            nm = f"{nm}()"
        return tt, nm
    if tt == 'AST_METHOD_CALL':
        recv = (taint.get('recv') or '').strip()
        nm = (taint.get('name') or '').strip()
        if not nm and taint.get('id') is not None:
            _, nm = _node_display(taint.get('id'), nodes, children_of)
        if nm and not nm.endswith('()'):
            nm = f"{nm}()"
        if recv and nm:
            return tt, f"{recv}->{nm}"
        return tt, nm
    nm = (taint.get('name') or '').strip()
    if not nm and taint.get('id') is not None:
        _, nm = _node_display(taint.get('id'), nodes, children_of)
    return tt, nm


def _dedupe_name_key(tt: str, nm: str) -> str:
    from .llm_response import _norm_llm_name

    t = (tt or '').strip()
    v = (nm or '').strip()
    if not v:
        return ''
    v = v.replace('.', '->')
    v = _norm_llm_name(v)
    if not v:
        return ''
    if t == 'AST_DIM':
        return (v.split('[', 1)[0] or '').strip()
    if t == 'AST_PROP':
        parts = [p for p in v.split('->') if p]
        if len(parts) >= 2:
            return parts[0] + '->' + parts[1]
        return v
    if t == 'AST_METHOD_CALL':
        if v.endswith('()'):
            v = v[:-2]
        parts = [p for p in v.split('->') if p]
        if len(parts) >= 2:
            return parts[0] + '->' + parts[1]
        return v
    if t == 'AST_CALL':
        if v.endswith('()'):
            v = v[:-2]
        return v
    if t == 'AST_VAR':
        return v
    return v


def _taint_scope_key(taint, nodes, children_of, this_obj: str = ''):
    from .llm_response import _rewrite_this_prefix

    tid = taint.get('id')
    if tid is None:
        return None
    try:
        tid_i = int(tid)
    except Exception:
        return None
    funcid = (nodes.get(tid_i) or {}).get('funcid')
    if funcid is None:
        return None
    tt, nm = _taint_display(taint, nodes, children_of)
    if this_obj:
        nm = _rewrite_this_prefix(nm or '', this_obj)
    nk = _dedupe_name_key(tt, nm)
    if not nk:
        return None
    return (int(funcid), tt, nk)


def process_taints_llm(initial, ctx):
    from llm_utils import get_default_client
    from llm_utils.prompt_utils import (
        DEFAULT_LLM_TAINT_TEMPLATE,
        locs_to_scope_seqs,
        locs_to_seq_code_block,
        render_llm_taint_prompt,
        should_skip_llm_scope,
    )
    from llm_utils.taint_json import parse_llm_taint_response
    from llm_utils.taint_llm_calls import LLMCallFailure, chat_text_with_retries

    from .llm_response import (
        _expand_var_components,
        _norm_llm_name,
        _rewrite_this_prefix,
        map_llm_edges_to_nodes,
        map_llm_taints_to_nodes,
    )

    lg = _get_logger(ctx)

    client = ctx.get('llm_client')
    if client is None:
        try:
            client = get_default_client()
        except Exception:
            client = None
        ctx['llm_client'] = client

    preA = list(initial)
    preB = []
    useA = True
    seen = ctx.setdefault('_taint_seen', set())
    queued = ctx.setdefault('_taint_queued', set())
    seen_scope = ctx.setdefault('_taint_seen_scope', set())
    queued_scope = ctx.setdefault('_taint_queued_scope', set())
    llm_seqs = ctx.setdefault('llm_result_seqs', set())
    llm_new = ctx.setdefault('llm_new_taints', [])
    llm_new_seen = ctx.setdefault('_llm_new_seen', set())
    llm_new_minseq = ctx.setdefault('_llm_new_minseq', {})
    llm_new_key_to_index = ctx.setdefault('_llm_new_key_to_index', {})
    llm_edges = ctx.setdefault('llm_edges', [])
    llm_edges_seen = ctx.setdefault('_llm_edges_seen', set())
    llm_incoming = ctx.setdefault('_llm_graph_incoming', {})
    llm_calls = ctx.setdefault('_llm_call_count', 0)
    llm_max_calls = ctx.get('llm_max_calls')
    qstats = ctx.setdefault(
        '_llm_queue_stats',
        {
            'processed_A': 0,
            'processed_B': 0,
            'enqueued_to_A': 0,
            'enqueued_to_B': 0,
            'skipped_seen': 0,
            'skipped_queued': 0,
        },
    )
    calls_edges_union = ctx.get('calls_edges_union')
    if calls_edges_union is None:
        try:
            from taint_handlers import ast_method_call

            calls_edges_union = ast_method_call.read_calls_edges(os.getcwd())
        except Exception:
            calls_edges_union = {}
        ctx['calls_edges_union'] = calls_edges_union

    def append_llm_new_taint(item: dict) -> None:
        if not isinstance(item, dict):
            return
        tt = (item.get('type') or '').strip()
        nm = (item.get('name') or '').strip()
        seq = item.get('seq')
        if tt in ('AST_VAR', 'AST_PROP', 'AST_DIM') and nm and isinstance(seq, int):
            if tt == 'AST_PROP':
                nm = nm.replace('.', '->')
            k = (tt, _norm_llm_name(nm))
            cur = llm_new_minseq.get(k)
            if cur is None or seq < int(cur):
                idx = llm_new_key_to_index.get(k)
                if isinstance(idx, int) and 0 <= idx < len(llm_new):
                    llm_new[idx] = item
                else:
                    llm_new_key_to_index[k] = len(llm_new)
                    llm_new.append(item)
                llm_new_minseq[k] = int(seq)
            return
        llm_new.append(item)

    processed = ctx.setdefault('_llm_processed', [])
    prev_dropped = ctx.setdefault('_llm_prev_dropped', [])
    round_index = ctx.setdefault('_llm_round_index', 0)
    max_concurrency = ctx.get('llm_max_concurrency')
    try:
        max_concurrency = int(max_concurrency) if max_concurrency is not None else 6
    except Exception:
        max_concurrency = 6

    import asyncio

    async def _run_call_batch(coros):
        sem = asyncio.Semaphore(max(1, int(max_concurrency)))

        async def _run_one(c):
            async with sem:
                try:
                    return await c
                except BaseException as e:
                    return e

        tasks = [asyncio.create_task(_run_one(c)) for c in (coros or [])]
        if not tasks:
            return []
        return await asyncio.gather(*tasks)

    def _write_round_file(queue_label: str, dropped):
        nonlocal round_index
        round_index += 1
        ctx['_llm_round_index'] = round_index
        if lg is None:
            return
        lg.write_json(
            'rounds',
            f'round_{round_index}_{queue_label}.json',
            {
                'A': _queue_brief(preA, limit=10**9),
                'B': _queue_brief(preB, limit=10**9),
                'processed': list(processed),
                'dropped': list(dropped or []),
            },
        )

    while preA or preB:
        active = preA if useA else preB
        if not active:
            useA = not useA
            continue
        if lg is not None:
            lg.debug(
                'queue_state',
                active_queue=('A' if useA else 'B'),
                preA_len=len(preA),
                preB_len=len(preB),
            )
            lg.log_json('DEBUG', 'queue_preA', _queue_brief(preA))
            lg.log_json('DEBUG', 'queue_preB', _queue_brief(preB))

        round_dropped = []
        round_metas = []
        call_coros = []
        call_metas = []
        stop_due_to_max_calls = False

        for _ in range(len(active)):
            t = active.pop(0)
            tid = t.get('id')
            tseq = t.get('seq')
            if tid is None or tseq is None:
                continue
            key = (int(tid), int(tseq))
            nodes = ctx.get('nodes') or {}
            children_of = ctx.get('children_of') or {}
            bt = _taint_brief(t)
            this_obj = (t.get('recv') or '').strip() if (t.get('type') or '').strip() == 'AST_METHOD_CALL' else ''
            if not this_obj:
                this_obj = (t.get('_this_obj') or '').strip()
            this_call_seq = t.get('_this_call_seq')
            if this_call_seq is not None:
                try:
                    this_call_seq = int(this_call_seq)
                except Exception:
                    this_call_seq = None
            if this_call_seq is None and (t.get('type') or '').strip() == 'AST_METHOD_CALL' and tseq is not None:
                try:
                    this_call_seq = int(tseq)
                except Exception:
                    this_call_seq = None
            scope_key = _taint_scope_key(t, nodes, children_of, this_obj)
            if scope_key is not None and scope_key in seen_scope:
                continue
            if key in seen:
                continue
            seen.add(key)
            if scope_key is not None:
                seen_scope.add(scope_key)
            if bt:
                processed.append(bt)
            fn = REGISTRY.get(t.get('type') or '')
            if not fn:
                continue
            if lg is not None:
                lg.log_json('DEBUG', 'processing_taint', bt)
            before = len(ctx.get('result_set') or [])
            ctx['_llm_scope_markers'] = []
            ctx['_llm_extra_prompt_locs'] = []
            fn(t, ctx)
            after = len(ctx.get('result_set') or [])
            if useA:
                qstats['processed_A'] = int(qstats.get('processed_A') or 0) + 1
            else:
                qstats['processed_B'] = int(qstats.get('processed_B') or 0) + 1
            rs_all = ctx.get('result_set') or []
            locs = rs_all[before:after] if after >= before else []
            extra_locs = ctx.get('_llm_extra_prompt_locs') or []
            if extra_locs:
                combined = []
                seen_loc = set()
                for x in list(locs) + list(extra_locs):
                    if not x or x in seen_loc:
                        continue
                    seen_loc.add(x)
                    combined.append(x)
                locs = combined
            ctx['_llm_ref_seq'] = int(tseq) if tseq is not None else None
            prefer = (ctx.get('_llm_scope_prefer') or '').strip()
            if not prefer:
                prefer = 'forward' if (t.get('type') or '').strip() in ('AST_METHOD_CALL', 'AST_CALL') else 'backward'
            block = locs_to_seq_code_block(locs, ctx, prefer=prefer)
            tt, nm = _taint_display(t, nodes, children_of)
            prompt = render_llm_taint_prompt(
                template=DEFAULT_LLM_TAINT_TEMPLATE,
                taint_type=tt,
                taint_name=nm,
                result_set=block,
            )

            scope_seqs = locs_to_scope_seqs(locs, ctx, ref_seq=(int(tseq) if tseq is not None else None), prefer=prefer) if block else []
            prompt_scope_set = set(int(x) for x in (scope_seqs or []) if isinstance(x, int) or str(x).isdigit())
            if prompt_scope_set and should_skip_llm_scope(sorted(prompt_scope_set), ctx):
                if lg is not None:
                    lg.info('llm_skip_scope_subset', taint_type=tt, taint_name=nm, scope_len=len(prompt_scope_set))
                continue

            meta = {
                't': t,
                'tid': tid,
                'tseq': tseq,
                'key': key,
                'this_obj': this_obj,
                'this_call_seq': this_call_seq,
                'tt': tt,
                'nm': nm,
                'locs': locs,
                'block': block,
                'prompt': prompt,
                'prompt_scope_set': prompt_scope_set,
            }

            if block:
                if client is None:
                    if lg is not None:
                        lg.warning('llm_client_missing', taint_type=tt, taint_name=nm)
                else:
                    if llm_max_calls is not None:
                        try:
                            if llm_calls >= int(llm_max_calls):
                                if lg is not None:
                                    lg.warning('llm_max_calls_reached_before_call', llm_calls=llm_calls, llm_max_calls=llm_max_calls)
                                stop_due_to_max_calls = True
                                break
                        except Exception:
                            pass
                    llm_calls += 1
                    ctx['_llm_call_count'] = llm_calls
                    call_index = llm_calls
                    meta['call_index'] = call_index
                    if lg is not None:
                        lg.info(
                            'llm_call',
                            call_index=call_index,
                            taint_type=tt,
                            taint_name=nm,
                            locs_count=len(locs),
                            block_lines=len((block or '').splitlines()),
                        )
                        try:
                            lg.write_text('llm/prompts', f'prompt_{call_index}_seq_{tseq}_id_{tid}.txt', prompt)
                        except Exception:
                            pass
                    call_coros.append(
                        chat_text_with_retries(
                            client=client,
                            prompt=prompt,
                            system=None,
                            logger=lg,
                            max_attempts=3,
                            call_timeout_s=getattr(client, 'timeout_s', None) if client is not None else None,
                            call_index=call_index,
                            taint_type=tt,
                            taint_name=nm,
                        )
                    )
                    call_metas.append(meta)
            round_metas.append(meta)

        if stop_due_to_max_calls:
            round_metas = []

        call_results = []
        fatal_exc = None
        if call_coros:
            call_results = asyncio.run(_run_call_batch(call_coros))
            first_exc = None
            for meta, res in zip(call_metas, call_results):
                call_index = meta.get('call_index')
                tid = meta.get('tid')
                tseq = meta.get('tseq')
                resp_txt = ''
                if isinstance(res, BaseException):
                    if isinstance(res, LLMCallFailure):
                        resp_txt = f'[joerntrace] llm_call_failed: {res}'
                    else:
                        resp_txt = f'[joerntrace] llm_call_failed: {type(res).__name__}'
                    if first_exc is None:
                        first_exc = res
                else:
                    resp_txt = str(res)
                meta['resp_txt'] = resp_txt
                if lg is not None and call_index is not None:
                    lg.write_text('llm/responses', f'response_{call_index}_seq_{tseq}_id_{tid}.txt', resp_txt or '')
            if first_exc is not None:
                fatal_exc = first_exc

        if fatal_exc is not None:
            round_metas = []

        for meta in round_metas:
            t = meta.get('t') or {}
            tid = meta.get('tid')
            tseq = meta.get('tseq')
            key = meta.get('key')
            this_obj = meta.get('this_obj') or ''
            this_call_seq = meta.get('this_call_seq')
            tt = meta.get('tt') or ''
            nm = meta.get('nm') or ''
            prompt_scope_set = meta.get('prompt_scope_set') or set()
            resp_txt = meta.get('resp_txt') or ''

            parsed = parse_llm_taint_response(resp_txt) if resp_txt else {'taints': [], 'edges': [], 'seqs': []}
            if lg is not None:
                lg.log_json('DEBUG', 'llm_parsed', parsed)

            call_index = meta.get('call_index')
            llm_scope_set = set(prompt_scope_set)
            if call_index is not None and llm_scope_set:
                if this_obj and this_call_seq is not None:
                    if tt in ('AST_PROP', 'AST_DIM'):
                        raw_name = (t.get('name') or '').strip()
                        raw_base = (t.get('base') or '').strip()
                        if (
                            raw_base in ('this', '$this')
                            or raw_name.startswith('this->')
                            or raw_name.startswith('$this->')
                            or raw_name.startswith('this.')
                            or raw_name.startswith('$this.')
                            or raw_name.startswith('this[')
                            or raw_name.startswith('$this[')
                        ):
                            llm_scope_set.add(int(this_call_seq))
                    elif tt == 'AST_METHOD_CALL':
                        raw_taints = parsed.get('taints') or []
                        for rt in raw_taints:
                            if not isinstance(rt, dict):
                                continue
                            rtt = (rt.get('type') or '').strip()
                            if rtt not in ('AST_PROP', 'AST_DIM'):
                                continue
                            rnm = (rt.get('name') or '').strip()
                            if (
                                rnm.startswith('this->')
                                or rnm.startswith('$this->')
                                or rnm.startswith('this.')
                                or rnm.startswith('$this.')
                                or rnm.startswith('this[')
                                or rnm.startswith('$this[')
                            ):
                                llm_scope_set.add(int(this_call_seq))
                                break
                ctx.setdefault('llm_scopes', []).append(sorted(llm_scope_set))

            for s in parsed.get('seqs') or []:
                try:
                    llm_seqs.add(int(s))
                except Exception:
                    continue

            mapped_nodes = map_llm_taints_to_nodes(parsed.get('taints') or [], ctx)
            mapped_edges = map_llm_edges_to_nodes(parsed.get('edges') or [], ctx)
            if lg is not None:
                lg.log_json('DEBUG', 'llm_mapped_nodes', mapped_nodes)
                lg.log_json('DEBUG', 'llm_mapped_edges', mapped_edges)
            for me in mapped_edges:
                src = me.get('src') or {}
                dst = me.get('dst') or {}
                sk = (int(src.get('id')), int(src.get('seq')))
                dk = (int(dst.get('id')), int(dst.get('seq')))
                ek = (sk, dk)
                if ek not in llm_edges_seen:
                    llm_edges_seen.add(ek)
                    if this_obj:
                        llm_edges.append(
                            {
                                'src': {**src, 'name': _rewrite_this_prefix(src.get('name') or '', this_obj)},
                                'dst': {**dst, 'name': _rewrite_this_prefix(dst.get('name') or '', this_obj)},
                            }
                        )
                    else:
                        llm_edges.append(me)
                inc = llm_incoming.get(dk)
                if inc is None:
                    inc = set()
                    llm_incoming[dk] = inc
                inc.add(sk)

            candidate = {}
            for nt in mapped_nodes:
                nid = nt.get('id')
                nseq = nt.get('seq')
                if nid is None or nseq is None:
                    continue
                candidate[(int(nid), int(nseq))] = nt
            for me in mapped_edges:
                for side in ('src', 'dst'):
                    nt = me.get(side) or {}
                    nid = nt.get('id')
                    nseq = nt.get('seq')
                    if nid is None or nseq is None:
                        continue
                    candidate.setdefault((int(nid), int(nseq)), nt)

            candidate2 = dict(candidate)
            for nt in list(candidate.values()):
                ntt = (nt.get('type') or '').strip()
                if ntt not in ('AST_VAR', 'AST_PROP', 'AST_DIM'):
                    continue
                for comp in _expand_var_components(nt, ctx):
                    cid = comp.get('id')
                    cseq = comp.get('seq')
                    if cid is None or cseq is None:
                        continue
                    try:
                        ck = (int(cid), int(cseq))
                    except Exception:
                        continue
                    candidate2.setdefault(ck, comp)
            candidate = candidate2

            leaf_nodes = []
            call_kept = 0
            call_dropped = 0
            for nk, nt in candidate.items():
                if nk == key:
                    continue
                ntt = (nt.get('type') or '').strip()
                if ntt in ('AST_METHOD_CALL', 'AST_CALL'):
                    cid = nt.get('id')
                    if cid is None:
                        continue
                    if calls_edges_union.get(int(cid)) or []:
                        leaf_nodes.append(nt)
                        call_kept += 1
                    else:
                        call_dropped += 1
                    continue
                inc = llm_incoming.get(nk)
                if inc:
                    continue
                leaf_nodes.append(nt)
            if lg is not None:
                lg.log_json('DEBUG', 'llm_leaf_nodes', leaf_nodes)

            leaf_keys = set()
            for nt in leaf_nodes:
                nid = nt.get('id')
                nseq = nt.get('seq')
                if nid is None or nseq is None:
                    continue
                leaf_keys.add((int(nid), int(nseq)))
            for dk in sorted((set(candidate.keys()) - leaf_keys - {key}) if key is not None else (set(candidate.keys()) - leaf_keys)):
                bt = _taint_brief(candidate.get(dk) or {})
                if bt:
                    round_dropped.append(bt)

            target_q = preB if useA else preA
            added = 0
            skipped_seen = 0
            skipped_queued = 0
            for nt in leaf_nodes:
                nid = nt.get('id')
                nseq = nt.get('seq')
                if nid is None or nseq is None:
                    continue
                k2 = (int(nid), int(nseq))
                scope_k2 = _taint_scope_key(nt, nodes, children_of, this_obj)
                if scope_k2 is not None and scope_k2 in seen_scope:
                    skipped_seen += 1
                    continue
                if k2 in seen:
                    skipped_seen += 1
                    continue
                if scope_k2 is not None and scope_k2 in queued_scope:
                    skipped_queued += 1
                    continue
                if k2 in queued:
                    skipped_queued += 1
                    continue
                queued.add(k2)
                if scope_k2 is not None:
                    queued_scope.add(scope_k2)
                ntq = dict(nt)
                if this_obj:
                    ntq['_this_obj'] = this_obj
                    if this_call_seq is not None and (nt.get('type') or '').strip() in ('AST_PROP', 'AST_DIM'):
                        ntq['_this_call_seq'] = int(this_call_seq)
                target_q.append(ntq)
                added += 1
                k3 = (int(nid), int(nseq), nt.get('type') or '', nt.get('name') or '', this_obj or '')
                if k3 not in llm_new_seen:
                    llm_new_seen.add(k3)
                    if this_obj:
                        disp = dict(ntq)
                        disp.pop('_this_obj', None)
                        disp['name'] = _rewrite_this_prefix(disp.get('name') or '', this_obj)
                        append_llm_new_taint(disp)
                    else:
                        append_llm_new_taint(ntq)
            if useA:
                qstats['enqueued_to_B'] = int(qstats.get('enqueued_to_B') or 0) + added
            else:
                qstats['enqueued_to_A'] = int(qstats.get('enqueued_to_A') or 0) + added
            qstats['skipped_seen'] = int(qstats.get('skipped_seen') or 0) + skipped_seen
            qstats['skipped_queued'] = int(qstats.get('skipped_queued') or 0) + skipped_queued
            if lg is not None:
                lg.info(
                    'queue_diffusion',
                    from_queue=('A' if useA else 'B'),
                    to_queue=('B' if useA else 'A'),
                    leaf_count=len(leaf_nodes),
                    candidate_count=len(candidate),
                    mapped_nodes_count=len(mapped_nodes),
                    mapped_edges_count=len(mapped_edges),
                    call_kept=call_kept,
                    call_dropped=call_dropped,
                    added=added,
                    skipped_seen=skipped_seen,
                    skipped_queued=skipped_queued,
                    preA_len=len(preA),
                    preB_len=len(preB),
                )

            if llm_max_calls is not None:
                try:
                    if llm_calls >= int(llm_max_calls):
                        if lg is not None:
                            lg.warning('llm_stop_after_max_calls', llm_calls=llm_calls, llm_max_calls=llm_max_calls)
                            lg.log_json(
                                'INFO',
                                'llm_partial_summary',
                                {
                                    'result_set_count': len(ctx.get('result_set') or []),
                                    'llm_result_seqs': sorted(int(x) for x in (ctx.get('llm_result_seqs') or set()) if str(x).isdigit()),
                                    'llm_new_taints': ctx.get('llm_new_taints') or [],
                                    'llm_edges': ctx.get('llm_edges') or [],
                                },
                            )
                        stop_due_to_max_calls = True
                        break
                except Exception:
                    pass

        _write_round_file('A' if useA else 'B', prev_dropped)
        prev_dropped = list(round_dropped)
        ctx['_llm_prev_dropped'] = prev_dropped
        if fatal_exc is not None:
            raise SystemExit(1)
        if stop_due_to_max_calls:
            return []
        useA = not useA
    return []
