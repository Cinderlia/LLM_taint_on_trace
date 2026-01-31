import json
import os
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class BranchSelectorConfig:
    seq_limit: int = 10000
    buffer_token_limit: int = 3000
    buffer_count: int = 1
    max_analyze_concurrency: int = 5
    test_mode: bool = True
    analyze_llm_test_mode: bool = True
    llm_max_attempts: int = 0
    nearest_seq_count: int = 3
    farthest_seq_count: int = 3
    base_prompt: str = ""
    prompt_out_dir: str = os.path.join("test", "branch_selector", "prompts")
    response_out_dir: str = os.path.join("test", "branch_selector", "responses")
    trace_index_path: str = os.path.join("tmp", "trace_index.json")
    scope_root: str = "/app"
    windows_root: str = r"D:\files\witcher\app"


def _default_config() -> BranchSelectorConfig:
    return BranchSelectorConfig()


def load_config(config_path: str | None = None) -> BranchSelectorConfig:
    base = os.path.dirname(os.path.abspath(__file__))
    root = os.path.dirname(base)
    repo_root = os.path.dirname(root)
    cfg_path = config_path or os.path.join(repo_root, "config.json")
    if not os.path.exists(cfg_path):
        cfg_path = os.path.join(root, "config.json")
    if not os.path.exists(cfg_path):
        cfg_path = os.path.join(base, "config.json")
    if not os.path.exists(cfg_path):
        return _default_config()
    try:
        with open(cfg_path, "r", encoding="utf-8", errors="replace") as f:
            obj = json.load(f)
    except Exception:
        return _default_config()
    if not isinstance(obj, dict):
        return _default_config()
    if isinstance(obj.get("branch_selector"), dict):
        obj = obj.get("branch_selector") or {}
    def _get_int(k: str, d: int) -> int:
        v = obj.get(k)
        try:
            return int(v) if v is not None else d
        except Exception:
            return d
    def _get_bool(k: str, d: bool) -> bool:
        v = obj.get(k)
        if isinstance(v, bool):
            return v
        if isinstance(v, str):
            s = v.strip().lower()
            if s in ("1", "true", "yes", "on"):
                return True
            if s in ("0", "false", "no", "off"):
                return False
        return d
    def _get_str(k: str, d: str) -> str:
        v = obj.get(k)
        return str(v).strip() if isinstance(v, str) else d
    return BranchSelectorConfig(
        seq_limit=_get_int("seq_limit", 10000),
        buffer_token_limit=_get_int("buffer_token_limit", 3000),
        buffer_count=_get_int("buffer_count", 1),
        max_analyze_concurrency=_get_int("max_analyze_concurrency", 5),
        test_mode=_get_bool("test_mode", True),
        analyze_llm_test_mode=_get_bool("analyze_llm_test_mode", True),
        llm_max_attempts=_get_int("llm_max_attempts", 0),
        nearest_seq_count=_get_int("nearest_seq_count", 3),
        farthest_seq_count=_get_int("farthest_seq_count", 3),
        base_prompt=_get_str("base_prompt", ""),
        prompt_out_dir=_get_str("prompt_out_dir", os.path.join("test", "branch_selector", "prompts")),
        response_out_dir=_get_str("response_out_dir", os.path.join("test", "branch_selector", "responses")),
        trace_index_path=_get_str("trace_index_path", os.path.join("tmp", "trace_index.json")),
        scope_root=_get_str("scope_root", "/app"),
        windows_root=_get_str("windows_root", r"D:\files\witcher\app"),
    )

