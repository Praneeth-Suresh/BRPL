"""Trusted evidence extraction and repository adapter for BRPL v2."""

from __future__ import annotations

import ast
import hashlib
import json
import re
import subprocess
import tomllib
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any

from .core import BRPLV2Error, LintContext, evaluate_policy_set as evaluate_typed, hash_candidate_tree

CHECKER_VERSION = "2.0.0"
MAX_CHECK_TIMEOUT_SECONDS = 600
_ID_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_.:-]*$")
_PEP503_RE = re.compile(r"[-_.]+")


class BRPLConfigError(BRPLV2Error):
    pass


class BRPLEvaluationError(BRPLV2Error):
    pass


@dataclass(frozen=True)
class EvaluationConfig:
    repo_root: Path
    base_ref: str
    check_registry_path: Path | None = None
    execute_checks: bool = True
    check_results: dict[str, dict[str, str]] | None = None


def evaluate_policy_set(policies: list[dict[str, Any]], config: EvaluationConfig) -> dict[str, Any]:
    if not policies or not config.base_ref:
        raise BRPLConfigError("at least one BRPL v2 policy and an explicit Git baseline are required")
    root = config.repo_root.resolve(strict=True)
    baseline = _git(root, ["rev-parse", "--verify", f"{config.base_ref}^{{commit}}"]).strip()
    candidate = hash_candidate_tree(root)
    changes = _changes(root, config.base_ref)
    edges = _dependencies(root)
    manifests = _manifest_deltas(root, baseline, policies)
    checks = _checks(root, policies, config, candidate)
    evidence = {
        "schema": "brpl-evidence/v2",
        "candidate_tree": {"sha256": candidate},
        "git_changes": changes,
        "source_dependencies": edges,
        "manifest_delta": manifests,
        "check_results": checks,
        "control_integrity": {"control_hashes": [], "events": []},
    }
    report = evaluate_typed(
        policies,
        evidence,
        lint_context=LintContext(
            known_manifests=frozenset(item["manifest"] for item in manifests),
            known_checks=frozenset(item["check"] for item in checks),
        ),
    )
    report.update({
        "checker_version": CHECKER_VERSION,
        "baseline": {"ref": config.base_ref, "sha": baseline},
        "changed_files": sorted({path for change in changes for path in [change["path"], change.get("old_path")] if path}),
        "policy_hashes": {"semantic_sha256": report["policy_sha256"]},
    })
    report["violations"] = [_compatibility_finding(item) for item in report["findings"]]
    return report


def report_to_json(report: dict[str, Any]) -> str:
    return json.dumps(report, indent=2, sort_keys=True) + "\n"


def report_to_human(report: dict[str, Any]) -> str:
    lines = [
        f"BRPL v{report['brpl_version']} policy report",
        f"schema: {report['schema']}",
        f"checker: {report.get('checker_version', CHECKER_VERSION)}",
        f"baseline: {report.get('baseline', {}).get('ref', '<unknown>')} ({report.get('baseline', {}).get('sha', '<unknown>')})",
        "policies: " + ", ".join(report.get("policy_ids", [])),
        f"rules evaluated: {len(report.get('rules_evaluated', []))}",
        f"changed files: {len(report.get('changed_files', []))}",
        "status: " + ("PASS" if report["ok"] else "FAIL"),
    ]
    for finding in report.get("findings", []):
        lines.append(f"- {finding['severity']} {finding['rule_id']}: {finding['evidence'].get('type', finding['policy_class'])}")
        lines.append(f"  remediation: {finding['remediation']}")
    return "\n".join(lines) + "\n"


def cli_error_report(message: str) -> str:
    return report_to_json({"schema": "brpl-report/v2", "brpl_version": 2, "checker_version": CHECKER_VERSION, "outcome": "blocked_evaluation_error", "ok": False, "findings": [], "violations": [], "errors": [{"severity": "error", "evidence": {"type": "error", "text": message}}]})


def _changes(root: Path, base: str) -> list[dict[str, Any]]:
    tokens = _git_bytes(root, ["diff", "--name-status", "-z", "--find-renames", "--find-copies", base]).split(b"\0")
    result: list[dict[str, Any]] = []
    index = 0
    while index < len(tokens) and tokens[index]:
        status = _decode(tokens[index])[0]
        index += 1
        if status in "RC":
            old, new = _norm(_decode(tokens[index]), "old path"), _norm(_decode(tokens[index + 1]), "new path")
            index += 2
            result.append({"status": "renamed" if status == "R" else "copied", "path": new, "old_path": old})
        else:
            path = _norm(_decode(tokens[index]), "changed path")
            index += 1
            result.append({"status": {"A": "added", "M": "modified", "D": "deleted", "T": "type_changed"}.get(status, "modified"), "path": path})
    for raw in _git_bytes(root, ["ls-files", "-z", "--others", "--exclude-standard"]).split(b"\0"):
        if raw:
            result.append({"status": "untracked", "path": _norm(_decode(raw), "untracked path")})
    return sorted(result, key=lambda item: (item["path"], item.get("old_path", ""), item["status"]))


def _dependencies(root: Path) -> list[dict[str, Any]]:
    paths = [path for path in _paths(root) if path.endswith(".py") and (root / path).is_file()]
    modules: dict[str, set[str]] = {}
    for path in paths:
        if (root / path).is_symlink():
            raise BRPLEvaluationError(f"Python source is a symlink: {path}")
        module = _module(path)
        modules.setdefault(module, set()).add(path)
        if path.endswith("/__init__.py"):
            modules.setdefault(module + ".__init__", set()).add(path)
    edges: set[tuple[str, str, str]] = set()
    for path in paths:
        try:
            tree = ast.parse((root / path).read_text(encoding="utf-8"), filename=path)
        except (OSError, SyntaxError, UnicodeDecodeError) as exc:
            raise BRPLEvaluationError(f"cannot parse Python imports in {path}: {exc}") from exc
        current = _module(path)
        package = current if path.endswith("/__init__.py") else current.rsplit(".", 1)[0]
        targets: list[str] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                targets.extend(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom):
                base = _relative(package, node.level, node.module)
                if base:
                    targets.append(base)
                targets.extend(f"{base}.{alias.name}" if base else alias.name for alias in node.names if alias.name != "*")
            for target in targets:
                for resolved in _resolve(target, modules):
                    edges.add(("python_import", path, resolved))
                targets.clear()
    return [{"relation": relation, "source": source, "target": target} for relation, source, target in sorted(edges)]


def _manifest_deltas(root: Path, baseline: str, policies: list[dict[str, Any]]) -> list[dict[str, Any]]:
    names = sorted({rule["manifest"] for policy in policies for rule in policy["spec"]["rules"] if rule["kind"] == "manifest.direct_dependencies"})
    result = []
    for name in names:
        current = _deps((root / name).read_bytes(), name)
        ref = f"{baseline}:{name}"
        if _git(root, ["cat-file", "-t", ref]).strip() != "blob":
            raise BRPLEvaluationError(f"baseline dependency manifest is missing: {name}")
        previous = _deps(_git_bytes(root, ["show", ref]), f"baseline {name}")
        result.append({"manifest": name, "added": sorted(current - previous), "removed": sorted(previous - current)})
    return result


def _checks(root: Path, policies: list[dict[str, Any]], config: EvaluationConfig, candidate: str) -> list[dict[str, Any]]:
    required = sorted({check for policy in policies for rule in policy["spec"]["rules"] if rule["kind"] == "check.require" for check in rule["checks"]})
    if config.check_results is not None:
        results = {check: config.check_results.get(check, {"status": "missing", "evidence": "no result"}) for check in required}
        return [_typed_check(check, results[check], candidate, results[check]) for check in required]
    if not required:
        return []
    if not config.execute_checks:
        return [_typed_check(check, {"status": "missing", "evidence": "check execution disabled"}, candidate, {"check": check}) for check in required]
    if config.check_registry_path is None:
        raise BRPLConfigError("required checks need a trusted check registry")
    registry = _registry(config.check_registry_path)
    result = []
    for check in required:
        if check not in registry:
            raise BRPLConfigError(f"required check {check!r} is not in the trusted registry")
        adapter = registry[check]
        result.append(_typed_check(check, _run(root, adapter), candidate, adapter))
    return result


def _typed_check(check: str, value: dict[str, str], candidate: str, input_data: Any) -> dict[str, Any]:
    status = value.get("status", "missing")
    if status not in {"pass", "fail", "error", "timeout", "missing"}:
        raise BRPLConfigError(f"invalid check result status: {status}")
    return {"check": check, "status": status, "candidate_tree_sha256": candidate, "tool_id": f"trusted.{check}", "input_sha256": _hash(input_data), "evidence": value.get("evidence", "")}


def _registry(path: Path) -> dict[str, dict[str, Any]]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_pairs)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise BRPLConfigError(f"cannot read trusted check registry {path}: {exc}") from exc
    if not isinstance(data, dict) or data.get("version") != 1 or not isinstance(data.get("checks"), list):
        raise BRPLConfigError("trusted check registry must contain version=1 and checks list")
    result = {}
    for entry in data["checks"]:
        if not isinstance(entry, dict) or not isinstance(entry.get("id"), str) or not _ID_RE.fullmatch(entry["id"]):
            raise BRPLConfigError("trusted check registry contains an invalid id")
        if not isinstance(entry.get("command"), list) or not entry["command"] or not all(isinstance(item, str) and item for item in entry["command"]):
            raise BRPLConfigError(f"trusted check {entry.get('id')} needs an argv command")
        timeout = entry.get("timeout_seconds")
        cwd = entry.get("cwd", "")
        # An omitted cwd means the evaluated repository root.  Non-empty cwd
        # values must remain a normalized, relative descendant of that root.
        if not isinstance(cwd, str) or cwd.startswith("/") or "\\" in cwd or (
            cwd and any(part in {"", ".", ".."} for part in cwd.split("/"))
        ):
            raise BRPLConfigError(f"trusted check {entry.get('id')} has an unsafe cwd")
        if not isinstance(timeout, int) or isinstance(timeout, bool) or not 0 < timeout <= MAX_CHECK_TIMEOUT_SECONDS:
            raise BRPLConfigError(f"trusted check {entry['id']} has an invalid timeout")
        result[entry["id"]] = {"id": entry["id"], "command": entry["command"], "cwd": cwd, "timeout_seconds": timeout}
    return result


def _run(root: Path, adapter: dict[str, Any]) -> dict[str, str]:
    try:
        completed = subprocess.run(adapter["command"], cwd=root / adapter["cwd"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=adapter["timeout_seconds"], check=False, shell=False)
    except subprocess.TimeoutExpired:
        return {"status": "timeout", "evidence": f"timeout after {adapter['timeout_seconds']}s"}
    except OSError as exc:
        return {"status": "error", "evidence": str(exc)}
    lines = (completed.stdout + completed.stderr).strip().splitlines()
    return {"status": "pass" if completed.returncode == 0 else "fail", "evidence": (lines[-1] if lines else f"exit {completed.returncode}")[:300]}


def _compatibility_finding(finding: dict[str, Any]) -> dict[str, Any]:
    family = {"change.paths": "change_scope", "change.protect": "protected_paths", "dependency.forbid": "architecture.forbid_imports", "manifest.direct_dependencies": "new_dependencies", "check.require": "required_checks"}.get(finding["policy_class"], finding["policy_class"])
    return {**finding, "family": family, "violation_id": finding["finding_id"]}


def _paths(root: Path) -> list[str]:
    raw = _git_bytes(root, ["ls-files", "-z"]) + _git_bytes(root, ["ls-files", "-z", "--others", "--exclude-standard"])
    return sorted({_norm(_decode(item), "repository path") for item in raw.split(b"\0") if item})


def _module(path: str) -> str:
    value = path[:-3]
    return value[:-len("/__init__")] .replace("/", ".") if value.endswith("/__init__") else value.replace("/", ".")


def _relative(package: str, level: int, module: str | None) -> str:
    if level == 0:
        return module or ""
    parts = package.split(".") if package else []
    base = parts[:max(0, len(parts) - level + 1)]
    if module:
        base.extend(module.split("."))
    return ".".join(base)


def _resolve(target: str, modules: dict[str, set[str]]) -> set[str]:
    parts = target.split(".")
    result: set[str] = set()
    for end in range(len(parts), 0, -1):
        result.update(modules.get(".".join(parts[:end]), set()))
    return result


def _deps(raw: bytes, source: str) -> set[str]:
    try:
        data = tomllib.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        raise BRPLEvaluationError(f"cannot parse {source}: {exc}") from exc
    project = data.get("project", {})
    if not isinstance(project, dict):
        raise BRPLEvaluationError(f"{source}: project must be a table")
    values = list(project.get("dependencies", []) or [])
    for group in (project.get("optional-dependencies", {}) or {}).values():
        values.extend(group)
    if not all(isinstance(item, str) for item in values):
        raise BRPLEvaluationError(f"{source}: dependency declarations must be strings")
    return {_PEP503_RE.sub("-", re.split(r"[\[<>=~!;()\s]", item.strip(), maxsplit=1)[0]).lower() for item in values}


def _norm(value: str, source: str) -> str:
    path = PurePosixPath(value)
    if not value or "\0" in value or "\\" in value or path.is_absolute() or value != path.as_posix() or any(part in {"", ".", ".."} for part in path.parts):
        raise BRPLEvaluationError(f"{source} is not a normalized repository path")
    return value


def _git_bytes(root: Path, args: list[str]) -> bytes:
    completed = subprocess.run(["git", "-C", str(root), *args], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    if completed.returncode:
        raise BRPLConfigError(completed.stderr.decode("utf-8", errors="replace").strip() or "Git command failed")
    return completed.stdout


def _git(root: Path, args: list[str]) -> str:
    return _git_bytes(root, args).decode("utf-8", errors="replace")


def _decode(value: bytes) -> str:
    try:
        return value.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise BRPLEvaluationError(f"Git path is not UTF-8: {exc}") from exc


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key {key!r}")
        result[key] = value
    return result


def _hash(value: Any) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")).hexdigest()
