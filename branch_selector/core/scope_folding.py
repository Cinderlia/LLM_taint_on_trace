"""
Utilities for folding adjacent prompt sections when one scope is a subset of another.
"""

from collections.abc import Iterable


def is_subset_scope(a_scope_seqs: Iterable[int], b_scope_seqs: Iterable[int]) -> bool:
    a_set = set()
    for x in a_scope_seqs or []:
        try:
            a_set.add(int(x))
        except Exception:
            continue
    if not a_set:
        return True
    b_set = set()
    for x in b_scope_seqs or []:
        try:
            b_set.add(int(x))
        except Exception:
            continue
    if not b_set:
        return False
    return a_set.issubset(b_set)


def _ensure_int_list(xs) -> list[int]:
    out = []
    for x in xs or []:
        try:
            out.append(int(x))
        except Exception:
            continue
    return out


class ScopeSubsetFolder:
    def __init__(self):
        self._pending = None

    def push(self, item: dict | None) -> list[dict]:
        if item is None:
            return []
        if self._pending is None:
            self._pending = item
            return []
        cur = self._pending
        nxt = item
        if is_subset_scope(cur.get('scope_seqs') or [], nxt.get('scope_seqs') or []):
            marks = set(_ensure_int_list(nxt.get('mark_seqs') or [nxt.get('seq')]))
            try:
                marks.add(int(cur.get('seq')))
            except Exception:
                pass
            nxt['mark_seqs'] = sorted(marks)
            self._pending = nxt
            return []
        self._pending = nxt
        return [cur]

    def flush(self) -> list[dict]:
        if self._pending is None:
            return []
        out = [self._pending]
        self._pending = None
        return out

