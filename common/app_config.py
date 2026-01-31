import json
import os
from dataclasses import dataclass
from typing import Any
from pathlib import Path


@dataclass(frozen=True)
class AppConfig:
    base_dir: str
    config_path: str
    input_dir: str
    tmp_dir: str
    test_dir: str
    raw: dict[str, Any]

    def input_path(self, *parts: str) -> str:
        return os.path.join(self.input_dir, *parts)

    def tmp_path(self, *parts: str) -> str:
        return os.path.join(self.tmp_dir, *parts)

    def test_path(self, *parts: str) -> str:
        return os.path.join(self.test_dir, *parts)

    def find_input_file(self, name: str) -> str:
        c1 = self.input_path(name)
        if os.path.exists(c1):
            return c1
        c2 = os.path.join(self.base_dir, name)
        return c2


def _is_abs(p: str) -> bool:
    try:
        return Path(p).is_absolute()
    except Exception:
        return os.path.isabs(p)


def _abspath(base_dir: str, p: str) -> str:
    v = (p or "").strip()
    if not v:
        return os.path.abspath(base_dir)
    if _is_abs(v):
        return os.path.abspath(v)
    return os.path.abspath(os.path.join(base_dir, v))


def _read_json(path: str) -> dict[str, Any]:
    if not path or not os.path.exists(path):
        return {}
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            obj = json.load(f)
    except Exception:
        return {}
    return obj if isinstance(obj, dict) else {}


def _parse_kv_arg(argv: list[str], key: str) -> str | None:
    if not argv:
        return None
    for i, x in enumerate(argv):
        if not isinstance(x, str):
            continue
        if x.startswith(key + "="):
            return (x.split("=", 1)[1] or "").strip()
        if x == key and (i + 1) < len(argv):
            v = argv[i + 1]
            return (v or "").strip() if isinstance(v, str) else None
    return None


def load_app_config(*, config_path: str | None = None, argv: list[str] | None = None, base_dir: str | None = None) -> AppConfig:
    base = os.path.abspath(base_dir or os.getcwd())
    args = list(argv or [])

    cfg_path = (
        _parse_kv_arg(args, "--config")
        or config_path
        or os.environ.get("JOERNTRACE_CONFIG")
        or os.path.join(base, "config.json")
    )
    cfg_path = _abspath(base, cfg_path)
    raw = _read_json(cfg_path)

    paths = raw.get("paths") if isinstance(raw.get("paths"), dict) else {}
    input_dir = _parse_kv_arg(args, "--input-dir") or (paths.get("input_dir") if isinstance(paths, dict) else None) or raw.get("input_dir") or "input"
    tmp_dir = _parse_kv_arg(args, "--tmp-dir") or (paths.get("tmp_dir") if isinstance(paths, dict) else None) or raw.get("tmp_dir") or "tmp"
    test_dir = _parse_kv_arg(args, "--test-dir") or (paths.get("test_dir") if isinstance(paths, dict) else None) or raw.get("test_dir") or "test"

    input_abs = _abspath(base, str(input_dir))
    tmp_abs = _abspath(base, str(tmp_dir))
    test_abs = _abspath(base, str(test_dir))

    return AppConfig(
        base_dir=base,
        config_path=str(cfg_path),
        input_dir=input_abs,
        tmp_dir=tmp_abs,
        test_dir=test_abs,
        raw=raw,
    )
