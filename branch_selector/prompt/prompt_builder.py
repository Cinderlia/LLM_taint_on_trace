import os
import sys
from typing import Iterable

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from common.logger import Logger

BASE_PROMPT = """你是一个精通代码分析和漏洞挖掘的安全专家，请根据以下规则，从分支代码中筛选出适合进行符号执行的分支。

核心原则：当规则未明确涵盖时，请积极利用你对代码安全、攻击面和漏洞模式的先验知识来判断。只要存在通过外部输入影响分支执行路径的可能性，就应该倾向于选择。

明确规则：
1. 【必须选】如果分支语句中的变量可能直接或间接来源于用户输入（GET、POST、COOKIE、HTTP头部等）
2. 【必须选】如果分支语句中的变量可能来源于环境变量（如getenv）
3. 【不要选】如果变量明确来源于本地文件、硬编码配置、SESSION存储
4. 【不要选】如果变量直接来源于数据库连接（不包括查询结果数据）
5. 【不要选】如果是系统环境检查（PHP版本、SQL版本、系统版本等）
6. 【不要选】如果是本地文件存在性检查
7. 【不要选】如果是数据库连接测试或组件功能验证

关键补充规则：
8. 对于不确定来源的变量，优先考虑它是否可能来自GET、POST、COOKIE或环境变量
9. 如果变量名或使用模式暗示可能是用户输入（如$input、$param、$data等），选择该分支
10. 在Web应用上下文中，对于处理业务数据的变量，倾向于认为可能来自用户输入
11. 如果无法确定，但有合理可能性变量来自可修改的四种来源之一，就选择该分支

输出格式：
仅输出一个JSON数组，包含被选择分支前面的编号。如果没有选择任何分支，也需要返回一个合法的空数组。
示例：[123, 456, 789]
不要输出任何其他内容。"""


def build_prompt(*, sections: Iterable[dict], separator: str, logger: Logger | None = None) -> str:
    chunks = []
    count = 0
    chunks.append(BASE_PROMPT.strip())
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


def format_section(seq: int, lines: list[dict], logger: Logger | None = None) -> dict:
    code_lines = []
    if_line_written = False
    for it in lines or []:
        s = it.get("seq")
        code = (it.get("code") or "").strip()
        if s is None:
            continue
        if not if_line_written and int(s) == int(seq):
            code_lines.append(f"{int(s)} {code}".rstrip())
            if_line_written = True
        else:
            code_lines.append(f"{code}".rstrip())
    out = {"seq": int(seq), "code": "\n".join(code_lines)}
    if logger is not None:
        logger.debug("section_formatted", seq=int(seq), lines=len(code_lines))
    return out
