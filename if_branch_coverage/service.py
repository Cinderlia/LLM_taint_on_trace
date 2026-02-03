from common.app_config import load_app_config
from cpg_utils.graph_mapping import load_ast_edges, load_nodes, norm_nodes_path, safe_int

import os

from if_branch_coverage.cache import get_cached_result, init_cache, set_cached_result
from if_branch_coverage.coverage_parser import build_coverage_index, find_cc_json, has_covered_line, load_coverage
from if_branch_coverage.if_scope import get_if_branch_lines, get_if_file_path, is_ast_if


class IfBranchCoverageService:
    def __init__(self, *, config_path: str | None = None, argv: list[str] | None = None, base_dir: str | None = None):
        cfg = load_app_config(config_path=config_path, argv=argv, base_dir=base_dir)
        self.config = cfg
        self.input_dir = cfg.input_dir
        cache_path = os.path.join(cfg.tmp_dir, "if_branch_coverage_cache.json")
        init_cache(cache_path)
        self.nodes_path = cfg.find_input_file("nodes.csv")
        self.rels_path = cfg.find_input_file("rels.csv")
        self.nodes, self.top_id_to_file = load_nodes(self.nodes_path)
        self.parent_of, self.children_of = load_ast_edges(self.rels_path)
        self.cc_path = find_cc_json(self.input_dir)
        self.coverage_index = build_coverage_index(load_coverage(self.cc_path)) if self.cc_path else {}

    def check_if_coverage(self, if_id) -> bool:
        nid = safe_int(if_id)
        if nid is None:
            return False
        cached = get_cached_result(nid)
        if cached is not None:
            return bool(cached)
        if not is_ast_if(nid, self.nodes):
            set_cached_result(nid, False)
            return False
        file_path = get_if_file_path(nid, self.parent_of, self.nodes, self.top_id_to_file)
        if not file_path:
            set_cached_result(nid, False)
            return False
        norm_path = norm_nodes_path(file_path)
        true_lines, false_lines = get_if_branch_lines(nid, self.nodes, self.children_of)
        true_covered = has_covered_line(self.coverage_index, norm_path, true_lines)
        if false_lines:
            false_covered = has_covered_line(self.coverage_index, norm_path, false_lines)
            result = bool(true_covered and false_covered)
        else:
            result = bool(true_covered)
        set_cached_result(nid, result)
        return result


_DEFAULT_SERVICE: IfBranchCoverageService | None = None
_DEFAULT_CONFIG_KEY: str = ""


def get_service(config_path: str | None = None) -> IfBranchCoverageService:
    global _DEFAULT_SERVICE, _DEFAULT_CONFIG_KEY
    key = (config_path or "").strip()
    if _DEFAULT_SERVICE is None or _DEFAULT_CONFIG_KEY != key:
        _DEFAULT_SERVICE = IfBranchCoverageService(config_path=config_path)
        _DEFAULT_CONFIG_KEY = key
    return _DEFAULT_SERVICE


def check_if_branch_coverage(if_id, config_path: str | None = None) -> bool:
    svc = get_service(config_path=config_path)
    return svc.check_if_coverage(if_id)
