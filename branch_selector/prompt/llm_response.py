"""
Parse the LLM response for branch selection into groups of trace sequence numbers.
"""

import json
import os
import random
import sys
from typing import Iterable

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from common.logger import Logger


# Summary: Decode JSON produced by the LLM into groups of integer seqs (tolerant to minor format variants).
def parse_llm_response(text: str, logger: Logger | None = None) -> list[list[int]]:
    if not isinstance(text, str):
        return []
    s = text.strip()
    if not s:
        return []
    try:
        obj = json.loads(s)
    except Exception:
        if logger is not None:
            logger.warning("llm_response_parse_failed")
        return []
    if isinstance(obj, list):
        if not obj:
            return []
        if all(isinstance(x, int) or (isinstance(x, str) and str(x).isdigit()) for x in obj):
            out = [[int(x) for x in obj]]
            if logger is not None:
                logger.info("llm_response_parsed", groups=len(out), seqs=len(out[0]))
            return out
        out: list[list[int]] = []
        for it in obj:
            if isinstance(it, list):
                buf = []
                for x in it:
                    try:
                        buf.append(int(x))
                    except Exception:
                        continue
                if buf:
                    out.append(buf)
        if logger is not None:
            total = sum(len(x) for x in out)
            logger.info("llm_response_parsed", groups=len(out), seqs=total)
        return out
    return []


def build_test_response_from_prompts(prompt_items: Iterable[dict], pick_count: int = 5, logger: Logger | None = None) -> list[list[int]]:
    seqs = []
    for it in prompt_items or []:
        s = it.get("seq")
        if s is None:
            continue
        try:
            seqs.append(int(s))
        except Exception:
            continue
    if not seqs:
        return []
    if len(seqs) <= int(pick_count):
        chosen = seqs
    else:
        chosen = random.sample(seqs, int(pick_count))
    out = [list(chosen)]
    if logger is not None:
        logger.info("llm_test_response_built", picked=len(out[0]))
    return out
