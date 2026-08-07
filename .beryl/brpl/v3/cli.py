"""Trusted command-line boundary for evaluating BRPL v3 contracts."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from ..v2.core import hash_candidate_tree
from ..v2.runtime import _changes, _checks, _dependencies, _manifest_deltas
from .compiler import compile_contracts, load_capabilities, parse_contract
from .runtime import cli_error_report, evaluate_plan


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Compile and evaluate BRPL v3 contracts.")
    parser.add_argument("--repo-root", default=".")
    parser.add_argument("--base", required=True)
    parser.add_argument("--policy", action="append", required=True)
    parser.add_argument("--capabilities", required=True)
    parser.add_argument("--check-registry")
    parser.add_argument("--format", choices=("human", "json"), default="human")
    parser.add_argument("--json-report")
    args = parser.parse_args(argv)
    root = Path(args.repo_root).resolve()
    try:
        root = root.resolve(strict=True)
        plan = compile_contracts([parse_contract(Path(path).read_text(encoding="utf-8"), path) for path in args.policy], load_capabilities(args.capabilities))
        candidate = hash_candidate_tree(root)
        manifests = [rule["manifest"] for rule in plan["rules"] if rule["operation"] == "direct_dependency_delta"]
        checks = [rule["check"] for rule in plan["rules"] if rule["operation"] == "check_pass"]
        legacy_manifests = [{"spec": {"rules": [{"kind": "manifest.direct_dependencies", "manifest": name} for name in manifests]}}]
        legacy_checks = [{"spec": {"rules": [{"kind": "check.require", "checks": checks}]}}]
        config = type("Config", (), {"check_results": None, "execute_checks": True, "check_registry_path": Path(args.check_registry).resolve(strict=True) if args.check_registry else None})()
        edges = _dependencies(root)
        for edge in edges:
            if edge.get("relation") == "python_import":
                edge["relation"] = "python-import"
        evidence: dict[str, Any] = {"schema": "brpl-evidence/v3", "candidate_tree": {"sha256": candidate}, "git_changes": _changes(root, args.base), "source_dependencies": edges, "manifest_delta": _manifest_deltas(root, args.base, legacy_manifests), "check_results": _checks(root, legacy_checks, config, candidate)}
        report = evaluate_plan(plan, evidence)
        rendered = json.dumps(report, indent=2, sort_keys=True) + "\n"
        if args.json_report:
            target = Path(args.json_report).resolve(strict=False)
            if target.is_relative_to(root):
                raise ValueError("--json-report must be outside --repo-root")
            target.write_text(rendered, encoding="utf-8")
        print(rendered if args.format == "json" else f"BRPL v3 policy report\nstatus: {'PASS' if report['ok'] else 'FAIL'}\nrules evaluated: {len(report['rules_evaluated'])}\n", end="")
        return 0 if report["ok"] else 1
    except (OSError, ValueError) as exc:
        error_report = cli_error_report(str(exc))
        if args.json_report and not Path(args.json_report).resolve(strict=False).is_relative_to(root):
            Path(args.json_report).write_text(error_report, encoding="utf-8")
        if args.format == "json":
            sys.stderr.write(error_report)
        else:
            print(f"BRPL v3 error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
