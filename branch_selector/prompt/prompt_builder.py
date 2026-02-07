"""
Build the branch-selection prompt text and format per-seq code sections.
"""

import os
import sys
from collections.abc import Iterable

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from common.logger import Logger

BASE_PROMPT = """你是一个专注于攻击面分析的渗透测试专家，正在寻找所有可能由用户控制的分支路径。
你的目标是最大化符号执行的覆盖范围，尽可能多地发现潜在的攻击向量。

核心指导思想：宁可选错，也不要放过任何一个有可能的分支。当规则未明确涵盖时，只要存在任何可能性（哪怕很小）变量可能被外部影响，就选择该分支。

明确规则：
1. 【必须选】如果分支语句中的变量可能直接或间接来源于用户输入（GET、POST、COOKIE、HTTP头部等）
2. 【必须选】如果分支语句中的变量可能来源于环境变量（如getenv）
3. 【不要选】如果变量大概率来源于本地文件、硬编码配置、SESSION存储
4. 【不要选】如果变量很可能来源于数据库连接（不包括查询结果数据）
5. 【不要选】如果是系统环境检查（PHP版本、SQL版本、系统版本等）
6. 【不要选】如果是本地文件存在性检查
7. 【不要选】如果是数据库连接测试或组件功能验证
8. 【应该选】对于不确定来源的变量，优先考虑它是否可能来自GET、POST、COOKIE或环境变量
9. 【应该选】如果变量名或使用模式暗示可能是用户输入（如$input、$param、$data等），选择该分支
10. 【应该选】对于处理业务数据的变量，倾向于认为可能来自用户输入
11. 【应该选】如果无法确定，但有可能性（哪怕很小）变量间接来自可修改的四种来源之一（GET、POST、COOKIE、环境变量），就选择该分支

如果明确规则没有覆盖到的话，请选择所有可能（哪怕只是理论上可能）被外部输入影响的分支。不要考虑"概率太低"，只要存在任何理论可能性就选择。
重要心理提示：你的分析将被用于符号执行探索，多选几个分支不会造成危害，但少选可能错过重要漏洞。因此，请大胆选择！

输出格式：
仅输出一个JSON数组，包含被选择分支前面的编号。如果没有选择任何分支，也需要返回一个合法的空数组。
示例：[123, 456, 789]
不要输出任何其他内容。"""


def build_prompt(*, sections: Iterable[dict], separator: str, base_prompt: str | None = None, logger: Logger | None = None) -> str:
    chunks = []
    count = 0
    prompt_text = (base_prompt or "").strip()
    if not prompt_text:
        prompt_text = BASE_PROMPT.strip()
    chunks.append(prompt_text)
    for sec in sections or []:
        seq = sec.get("seq")
        code = sec.get("code") or ""
        if seq is None:
            continue
        body = f"{code}".rstrip()
        chunks.append(body)
        count += 1
    out = f"\n{separator}\n".join(chunks)
    if logger is not None:
        logger.debug("prompt_built", sections=count, chars=len(out))
    return out


# Summary: Collapse mapped source lines into a compact, optionally marked prompt section for one seq.
def format_section(seq: int, lines: list[dict], mark_seqs: Iterable[int] | None = None, logger: Logger | None = None) -> dict:
    code_lines = []
    mark_set = set()
    try:
        mark_set.add(int(seq))
    except Exception:
        pass
    for ms in mark_seqs or []:
        try:
            mark_set.add(int(ms))
        except Exception:
            continue
    grouped_keys = []
    best_by_key = {}
    for it in lines or []:
        if not isinstance(it, dict):
            continue
        p = it.get("path")
        ln = it.get("line")
        if p and ln is not None:
            key = (str(p), int(ln))
        else:
            key = ("__code__", (it.get("code") or "").strip())
        if key not in best_by_key:
            best_by_key[key] = it
            grouped_keys.append(key)
            continue
        try:
            si = int(it.get("seq")) if it.get("seq") is not None else None
        except Exception:
            si = None
        if si is not None and (int(si) == int(seq) or int(si) in mark_set):
            best_by_key[key] = it
    for key in grouped_keys:
        it = best_by_key.get(key)
        if not isinstance(it, dict):
            continue
        s = it.get("seq")
        code = (it.get("code") or "").strip()
        if s is None:
            continue
        if int(s) in mark_set:
            code_lines.append(f"{int(s)} {code}".rstrip())
        else:
            code_lines.append(f"{code}".rstrip())
    out = {"seq": int(seq), "code": "\n".join(code_lines)}
    if logger is not None:
        logger.debug("section_formatted", seq=int(seq), lines=len(code_lines))
    return out
