"""Explicit v4 command boundary; it never imports legacy runtime extractors."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from .compiler import compile_policies, load_catalog, parse_policy
from .runtime import BRPLVerificationError, cli_error_report, evaluate_plan, validate_evidence
from .tree import candidate_tree_hash

# Compatibility-only name for test and evaluator callers; both boundaries use
# the same implementation in tree.py.
_tree_hash = candidate_tree_hash

LAUNCH_SCHEMA = "brpl-launch-manifest/v4"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Evaluate explicitly selected BRPL v4 normalized evidence.")
    parser.add_argument("--repo-root", required=True)
    parser.add_argument("--policy", action="append", required=True, help="external repository or task policy JSON")
    parser.add_argument("--catalog", required=True, help="external trusted adapter catalog JSON")
    parser.add_argument("--evidence", required=True, help="normalized evidence JSON created by trusted adapters")
    parser.add_argument("--launch-manifest", help="externally controlled v4 launch manifest; required in enforce mode")
    parser.add_argument("--enforce", action="store_true")
    parser.add_argument("--format", choices=("human", "json"), default="human")
    parser.add_argument("--json-report")
    args = parser.parse_args(argv)
    root = Path(args.repo_root).resolve()
    try:
        root = root.resolve(strict=True)
        paths = [Path(path).resolve(strict=True) for path in args.policy]
        catalog_path = Path(args.catalog).resolve(strict=True); evidence_path = Path(args.evidence).resolve(strict=True)
        if args.enforce:
            if not args.launch_manifest: raise ValueError("--launch-manifest is required with --enforce")
            launch_path = Path(args.launch_manifest).resolve(strict=True)
            _external(root, *paths, catalog_path, evidence_path, launch_path)
            launch = _load_launch(launch_path)
            _external(root, *(Path(item["path"]).resolve(strict=False) for item in launch["capabilities"]), *(Path(launch[key]["path"]).resolve(strict=False) for key in ("adapter_bundle", "checker", "baseline", "evaluator")))
            launch_before = _digest(launch_path)
        candidate_before = candidate_tree_hash(root)
        plan = compile_policies([parse_policy(path) for path in paths], load_catalog(catalog_path))
        if args.enforce:
            _verify_launch(launch, catalog_path, paths, plan)
        evidence = validate_evidence(_json(evidence_path))
        if evidence["candidate_tree"]["sha256"] != candidate_before: raise ValueError("evidence is not bound to the candidate tree before evaluation")
        if args.enforce and evidence["baseline"]["sha256"] != launch["baseline"]["id"]: raise ValueError("evidence baseline does not match launch baseline identity")
        report = evaluate_plan(plan, evidence)
        if args.enforce:
            if candidate_tree_hash(root) != candidate_before: raise ValueError("candidate tree changed during evaluation")
            if _digest(launch_path) != launch_before: raise ValueError("launch manifest changed during evaluation")
            _verify_launch(launch, catalog_path, paths, plan)
        rendered = json.dumps(report, sort_keys=True, indent=2) + "\n"
        if args.json_report:
            report_path = Path(args.json_report).resolve(strict=False)
            _external(root, report_path)
            report_path.write_text(rendered, encoding="utf-8")
        if args.format == "json": print(rendered, end="")
        else: print(f"BRPL v4 policy report\nstatus: {'PASS' if report['ok'] else 'BLOCKED'}\nrules evaluated: {len(report['rules'])}")
        return 0 if report["ok"] else 1
    except (OSError, ValueError, BRPLVerificationError) as exc:
        rendered = cli_error_report(str(exc))
        if args.json_report:
            report_path = Path(args.json_report).resolve(strict=False)
            if not report_path.is_relative_to(root): report_path.write_text(rendered, encoding="utf-8")
        if args.format == "json": sys.stderr.write(rendered)
        else: print(f"BRPL v4 error: {exc}", file=sys.stderr)
        return 2


def _json(path: Path) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_pairs)
    if not isinstance(data, dict): raise ValueError(f"{path} must contain a JSON object")
    return data


def _pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
    output: dict[str, Any] = {}
    for key, value in items:
        if key in output: raise ValueError(f"duplicate JSON key {key!r}")
        output[key] = value
    return output


def _load_launch(path: Path) -> dict[str, Any]:
    value = _json(path)
    if set(value) != {"schema", "catalog", "policies", "capabilities", "adapter_bundle", "checker", "baseline", "evaluator"} or value["schema"] != LAUNCH_SCHEMA: raise ValueError("launch manifest has invalid schema or fields")
    for key in ("catalog", "adapter_bundle", "checker", "baseline", "evaluator"):
        _pinned(value[key], key)
    if not isinstance(value["policies"], list) or not value["policies"]: raise ValueError("launch manifest requires policies")
    for item in value["policies"]: _pinned(item, "policy")
    if not isinstance(value["capabilities"], list): raise ValueError("launch manifest capabilities must be a list")
    for item in value["capabilities"]: _pinned(item, "capability")
    if len({item["id"] for item in value["capabilities"]}) != len(value["capabilities"]): raise ValueError("launch manifest capability ids must be unique")
    return value


def _pinned(value: Any, label: str) -> None:
    if not isinstance(value, dict) or set(value) != {"id", "path", "sha256"} or not all(isinstance(value[key], str) and value[key] for key in value): raise ValueError(f"launch {label} must have id, path, sha256")
    if len(value["sha256"]) != 64 or any(char not in "0123456789abcdef" for char in value["sha256"]): raise ValueError(f"launch {label} digest is invalid")


def _verify_launch(launch: dict[str, Any], catalog: Path, policies: list[Path], plan: dict[str, Any]) -> None:
    expected = {Path(launch["catalog"]["path"]).resolve(): launch["catalog"]["sha256"]}
    expected.update({Path(item["path"]).resolve(): item["sha256"] for item in launch["policies"]})
    if set(policies) != {path for path in expected if path != Path(launch["catalog"]["path"]).resolve()} or catalog != Path(launch["catalog"]["path"]).resolve(): raise ValueError("launch manifest does not pin selected policy/catalog paths")
    for path, digest in expected.items():
        if _digest(path) != digest: raise ValueError(f"launch-pinned artifact digest mismatch: {path}")
    # adapter bundle, checker, baseline, and evaluator are trust-root identities
    # whose immutable external artifacts are verified at launch and rechecked later.
    for key in ("adapter_bundle", "checker", "baseline", "evaluator"):
        path = Path(launch[key]["path"]).resolve(strict=True)
        if _digest(path) != launch[key]["sha256"]: raise ValueError(f"launch-pinned {key} digest mismatch")
    selected = {item["id"]: item for item in plan["capabilities"]}
    pinned = {item["id"]: item for item in launch["capabilities"]}
    if set(selected) != set(pinned): raise ValueError("launch manifest does not pin exactly the selected capabilities")
    for capability_id, capability in selected.items():
        item = pinned[capability_id]
        actual = _digest(Path(item["path"]).resolve(strict=True))
        if actual != item["sha256"]: raise ValueError(f"launch-pinned capability digest mismatch: {capability_id}")
        if item["sha256"] != capability["digest"]: raise ValueError(f"launch capability does not match catalog digest: {capability_id}")


def _external(root: Path, *paths: Path) -> None:
    for path in paths:
        if path.is_relative_to(root): raise ValueError(f"authoritative path must be outside candidate worktree: {path}")


def _digest(path: Path) -> str:
    import hashlib
    return hashlib.sha256(path.read_bytes()).hexdigest()


if __name__ == "__main__": raise SystemExit(main())
