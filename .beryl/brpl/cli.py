"""Command-line interface for BRPL."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

from .core import (
    BRPLConfigError,
    BRPLEvaluationError,
    BRPLSchemaError,
    EvaluationConfig,
    cli_error_report,
    evaluate_policy_set,
    load_policy_file,
    report_to_human,
    report_to_json,
)


_ID_RE = re.compile(r"^[A-Za-z0-9_.:-]+$")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Evaluate Beryl Repository Policy Language policies.")
    parser.add_argument("--repo-root", default=".", help="Repository root to evaluate.")
    parser.add_argument("--base", required=True, help="Explicit git baseline ref or SHA.")
    parser.add_argument("--policy", action="append", required=True, help="BRPL policy YAML file. Repeat for overlays.")
    parser.add_argument("--check-registry", help="Trusted required-check adapter registry JSON.")
    parser.add_argument("--no-execute-checks", action="store_true", help="Do not run required-check adapters.")
    parser.add_argument("--check-result", action="append", default=[], help="External check result in id=pass|fail|error form.")
    parser.add_argument("--format", choices=("human", "json"), default="human", help="Report format.")
    parser.add_argument("--json-report", help="Optional path for a JSON report copy.")
    args = parser.parse_args(argv)

    try:
        check_results = _parse_check_results(args.check_result)
        repo_root = Path(args.repo_root).resolve()
        if args.json_report:
            _reject_json_report_inside_repo(Path(args.json_report), repo_root)
        policies = [load_policy_file(path) for path in args.policy]
        config = EvaluationConfig(
            repo_root=repo_root,
            base_ref=args.base,
            check_registry_path=Path(args.check_registry) if args.check_registry else None,
            execute_checks=not args.no_execute_checks,
            check_results=check_results,
        )
        report = evaluate_policy_set(policies, config)
        if args.json_report:
            Path(args.json_report).write_text(report_to_json(report), encoding="utf-8")
        sys.stdout.write(report_to_json(report) if args.format == "json" else report_to_human(report))
        return 0 if report["ok"] else 1
    except (BRPLSchemaError, BRPLConfigError, BRPLEvaluationError) as exc:
        if args.format == "json":
            sys.stderr.write(cli_error_report(str(exc)))
        else:
            sys.stderr.write(f"BRPL error: {exc}\n")
        return 2


def _parse_check_results(items: list[str]) -> dict[str, dict[str, str]] | None:
    if not items:
        return None
    results: dict[str, dict[str, str]] = {}
    for item in items:
        if "=" not in item:
            raise BRPLConfigError(f"invalid --check-result {item!r}; expected id=status")
        check_id, status = item.split("=", 1)
        if not _ID_RE.fullmatch(check_id):
            raise BRPLConfigError(f"invalid check id for --check-result {item!r}")
        if check_id in results:
            raise BRPLConfigError(f"duplicate --check-result for {check_id!r}")
        if status not in {"pass", "fail", "error", "missing"}:
            raise BRPLConfigError(f"invalid status for --check-result {item!r}")
        results[check_id] = {"status": status, "evidence": f"external result {status}"}
    return results


def _reject_json_report_inside_repo(report_path: Path, repo_root: Path) -> None:
    resolved = report_path.resolve(strict=False)
    try:
        inside_repo = resolved.is_relative_to(repo_root)
    except ValueError:
        inside_repo = False
    if inside_repo:
        raise BRPLConfigError("--json-report must be outside --repo-root; use --format json for stdout")


if __name__ == "__main__":
    raise SystemExit(main())
