"""Explicit trusted-adapter driver, deliberately separate from the v4 core."""
from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path

from .adapters import adapter_artifact_digest
from .adapters.python_static import collect
from .tree import candidate_tree_hash


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Produce normalized evidence using a named trusted BRPL v4 adapter.")
    parser.add_argument("--adapter", choices=("python-evidence-bundle",), required=True)
    parser.add_argument("--repo-root", required=True)
    parser.add_argument("--base", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--check-results", help="external JSON object with schema brpl-fixed-check-results/v4 and check/status records")
    args = parser.parse_args(argv)
    root = Path(args.repo_root).resolve(strict=True); output = Path(args.output).resolve(strict=False)
    if output.is_relative_to(root): parser.error("--output must be outside --repo-root")
    checks = _fixed_checks(Path(args.check_results).resolve(strict=True), root, args.base) if args.check_results else []
    if args.check_results and Path(args.check_results).resolve().is_relative_to(root): parser.error("--check-results must be outside --repo-root")
    # The printed digest is the catalog value an external launch authority pins.
    evidence = collect(root, args.base, checks)
    output.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"adapter": args.adapter, "artifact_sha256": adapter_artifact_digest(args.adapter), "evidence": str(output)}, sort_keys=True))
    return 0


def _fixed_checks(path: Path, root: Path, base: str) -> list[dict[str, str]]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict) or set(value) != {"schema", "candidate_tree", "baseline", "checks"} or value["schema"] != "brpl-fixed-check-results/v4" or not isinstance(value["checks"], list): raise ValueError("--check-results has invalid schema")
    candidate = value["candidate_tree"]; baseline = value["baseline"]
    if not isinstance(candidate, dict) or set(candidate) != {"sha256"} or not isinstance(baseline, dict) or set(baseline) != {"sha256"}: raise ValueError("--check-results must bind candidate_tree and baseline")
    resolved = _baseline(root, base)
    if candidate.get("sha256") != candidate_tree_hash(root): raise ValueError("--check-results candidate identity does not match current tree")
    if baseline.get("sha256") != resolved: raise ValueError("--check-results baseline identity does not match resolved base")
    return value["checks"]


def _baseline(root: Path, base: str) -> str:
    result = subprocess.run(["git", "-C", str(root), "rev-parse", f"{base}^{{commit}}"], capture_output=True, text=True, check=False)
    if result.returncode: raise ValueError("cannot resolve --check-results baseline")
    return result.stdout.strip()


if __name__ == "__main__": raise SystemExit(main())
