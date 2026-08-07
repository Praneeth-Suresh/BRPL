"""Command-line interface for the active BRPL v2 runtime."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .core import load_policy_file
from .runtime import BRPLConfigError, BRPLEvaluationError, EvaluationConfig, cli_error_report, evaluate_policy_set, report_to_human, report_to_json


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Evaluate Beryl Repository Policy Language v2 policies.")
    parser.add_argument("--repo-root", default=".")
    parser.add_argument("--base", required=True)
    parser.add_argument("--policy", action="append", required=True)
    parser.add_argument("--check-registry")
    parser.add_argument("--no-execute-checks", action="store_true")
    parser.add_argument("--check-result", action="append", default=[])
    parser.add_argument("--format", choices=("human", "json"), default="human")
    parser.add_argument("--json-report")
    args = parser.parse_args(argv)
    root = Path(args.repo_root).resolve()
    try:
        checks = _parse_checks(args.check_result)
        if args.json_report and Path(args.json_report).resolve(strict=False).is_relative_to(root):
            raise BRPLConfigError("--json-report must be outside --repo-root")
        report = evaluate_policy_set(
            [load_policy_file(path) for path in args.policy],
            EvaluationConfig(root, args.base, Path(args.check_registry).resolve(strict=True) if args.check_registry else None, not args.no_execute_checks, checks),
        )
        if args.json_report:
            Path(args.json_report).write_text(report_to_json(report), encoding="utf-8")
        sys.stdout.write(report_to_json(report) if args.format == "json" else report_to_human(report))
        return 0 if report["ok"] else 1
    except (BRPLConfigError, BRPLEvaluationError, ValueError) as exc:
        # Evaluation errors are still gate decisions.  Persist the same
        # machine-readable blocked-decision record that is written for an
        # ordinary policy violation so callers never need to infer failure from
        # an absent report file or parse stderr.
        error_report = cli_error_report(str(exc))
        if args.json_report and not Path(args.json_report).resolve(strict=False).is_relative_to(root):
            Path(args.json_report).write_text(error_report, encoding="utf-8")
        if args.format == "json":
            sys.stderr.write(error_report)
        else:
            sys.stderr.write(f"BRPL v2 error: {exc}\n")
        return 2


def _parse_checks(items: list[str]) -> dict[str, dict[str, str]] | None:
    if not items:
        return None
    result: dict[str, dict[str, str]] = {}
    for item in items:
        check, separator, status = item.partition("=")
        if not separator or not check or status not in {"pass", "fail", "error", "timeout", "missing"} or check in result:
            raise BRPLConfigError(f"invalid or duplicate --check-result {item!r}")
        result[check] = {"status": status, "evidence": f"external result {status}"}
    return result
