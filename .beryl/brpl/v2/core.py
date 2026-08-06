"""Closed, data-only BRPL v2 policies and typed evidence evaluation."""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Iterable

from ..strict_yaml import StrictYAMLError, load_strict_yaml


POLICY_API_VERSION = "beryl.dev/brpl/v2"
EVIDENCE_SCHEMA = "brpl-evidence/v2"
REPORT_SCHEMA = "brpl-report/v2"
TEST_API_VERSION = "beryl.dev/brpl-tests/v2"
MAX_DOCUMENT_BYTES = 256 * 1024
MAX_DOCUMENT_LINES = 8000
MAX_DOCUMENT_NESTING = 32

_ID_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_.:-]*$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_RULE_KINDS = {
    "change.paths",
    "change.protect",
    "dependency.forbid",
    "manifest.direct_dependencies",
    "check.require",
}
_SEVERITIES = {"error", "warning"}
_CHANGE_STATUSES = {"added", "modified", "deleted", "renamed", "copied", "type_changed", "untracked"}
_CHECK_STATUSES = {"pass", "fail", "error", "timeout", "missing"}
REMEDIATION_CLASSES = frozenset({
    "remove_change", "move_change", "change_dependency", "run_required_check",
    "recheck_candidate", "restore_trusted_control", "preserve_gate_decision", "stop_and_report",
})


class BRPLV2Error(ValueError):
    """A fail-closed v2 document, lint, evidence, or evaluation error."""


@dataclass(frozen=True)
class LintContext:
    repository_paths: frozenset[str] = frozenset()
    known_manifests: frozenset[str] = frozenset()
    known_checks: frozenset[str] = frozenset()


def load_policy_file(path: os.PathLike[str] | str) -> dict[str, Any]:
    return validate_policy(_load_yaml_document(path), str(path))


def load_evidence_file(path: os.PathLike[str] | str) -> dict[str, Any]:
    return validate_evidence(_load_yaml_document(path), str(path))


def load_test_file(path: os.PathLike[str] | str) -> dict[str, Any]:
    data = _load_yaml_document(path)
    _mapping(data, str(path))
    _closed(data, {"apiVersion", "kind", "tests"}, str(path))
    _require(data.get("apiVersion") == TEST_API_VERSION, f"{path}: apiVersion must be {TEST_API_VERSION}")
    _require(data.get("kind") == "PolicyTestSuite", f"{path}: kind must be PolicyTestSuite")
    tests = _nonempty_list(data.get("tests"), f"{path}.tests")
    names: set[str] = set()
    for index, test in enumerate(tests):
        where = f"{path}.tests[{index}]"
        _mapping(test, where)
        _closed(test, {"name", "evidence", "expect"}, where)
        name = _string(test.get("name"), f"{where}.name")
        _require(name not in names, f"{where}.name duplicates {name!r}")
        names.add(name)
        validate_evidence(test.get("evidence"), f"{where}.evidence")
        expect = _mapping(test.get("expect"), f"{where}.expect")
        _closed(expect, {"violations"}, f"{where}.expect")
        violations = expect.get("violations")
        _require(isinstance(violations, list), f"{where}.expect.violations must be a list")
        for item_index, rule_id in enumerate(violations):
            _stable_id(rule_id, f"{where}.expect.violations[{item_index}]")
        _require(len(violations) == len(set(violations)), f"{where}.expect.violations contains duplicates")
    return data


def validate_policy(data: Any, source: str = "<policy>") -> dict[str, Any]:
    policy = _mapping(data, source)
    _closed(policy, {"apiVersion", "kind", "metadata", "spec"}, source)
    _require(policy.get("apiVersion") == POLICY_API_VERSION, f"{source}: apiVersion must be {POLICY_API_VERSION}")
    _require(policy.get("kind") in {"RepositoryPolicy", "TaskPolicy"}, f"{source}: invalid policy kind")
    metadata = _mapping(policy.get("metadata"), f"{source}.metadata")
    _closed(metadata, {"id"}, f"{source}.metadata")
    _stable_id(metadata.get("id"), f"{source}.metadata.id")
    spec = _mapping(policy.get("spec"), f"{source}.spec")
    _closed(spec, {"rules"}, f"{source}.spec")
    rules = _nonempty_list(spec.get("rules"), f"{source}.spec.rules")
    for index, rule in enumerate(rules):
        _validate_rule(rule, f"{source}.spec.rules[{index}]")
    return policy


def validate_evidence(data: Any, source: str = "<evidence>") -> dict[str, Any]:
    evidence = _mapping(data, source)
    _closed(
        evidence,
        {"schema", "candidate_tree", "git_changes", "source_dependencies", "manifest_delta", "check_results", "control_integrity"},
        source,
    )
    _require(evidence.get("schema") == EVIDENCE_SCHEMA, f"{source}.schema must be {EVIDENCE_SCHEMA}")
    candidate = _mapping(evidence.get("candidate_tree"), f"{source}.candidate_tree")
    _closed(candidate, {"sha256"}, f"{source}.candidate_tree")
    _sha256(candidate.get("sha256"), f"{source}.candidate_tree.sha256")

    git_changes = _optional_list(evidence.get("git_changes"), f"{source}.git_changes")
    evidence["git_changes"] = git_changes
    for index, change in enumerate(git_changes):
        where = f"{source}.git_changes[{index}]"
        _mapping(change, where)
        _closed(change, {"status", "path", "old_path"}, where)
        _require(change.get("status") in _CHANGE_STATUSES, f"{where}.status is invalid")
        _repo_path(change.get("path"), f"{where}.path")
        if "old_path" in change:
            _repo_path(change["old_path"], f"{where}.old_path")

    source_dependencies = _optional_list(evidence.get("source_dependencies"), f"{source}.source_dependencies")
    evidence["source_dependencies"] = source_dependencies
    for index, edge in enumerate(source_dependencies):
        where = f"{source}.source_dependencies[{index}]"
        _mapping(edge, where)
        _closed(edge, {"relation", "source", "target", "line"}, where)
        _stable_id(edge.get("relation"), f"{where}.relation")
        _repo_path(edge.get("source"), f"{where}.source")
        _repo_path(edge.get("target"), f"{where}.target")
        if "line" in edge:
            _positive_int(edge["line"], f"{where}.line")

    manifest_delta = _optional_list(evidence.get("manifest_delta"), f"{source}.manifest_delta")
    evidence["manifest_delta"] = manifest_delta
    for index, delta in enumerate(manifest_delta):
        where = f"{source}.manifest_delta[{index}]"
        _mapping(delta, where)
        _closed(delta, {"manifest", "added", "removed"}, where)
        _repo_path(delta.get("manifest"), f"{where}.manifest")
        delta["added"] = _string_list(_optional_list(delta.get("added"), f"{where}.added"), f"{where}.added")
        delta["removed"] = _string_list(_optional_list(delta.get("removed"), f"{where}.removed"), f"{where}.removed")

    seen_checks: set[str] = set()
    check_results = _optional_list(evidence.get("check_results"), f"{source}.check_results")
    evidence["check_results"] = check_results
    for index, result in enumerate(check_results):
        where = f"{source}.check_results[{index}]"
        _mapping(result, where)
        _closed(result, {"check", "status", "candidate_tree_sha256", "tool_id", "input_sha256", "evidence"}, where)
        check_id = _stable_id(result.get("check"), f"{where}.check")
        _require(check_id not in seen_checks, f"{where}.check duplicates {check_id!r}")
        seen_checks.add(check_id)
        _require(result.get("status") in _CHECK_STATUSES, f"{where}.status is invalid")
        _sha256(result.get("candidate_tree_sha256"), f"{where}.candidate_tree_sha256")
        _stable_id(result.get("tool_id"), f"{where}.tool_id")
        _sha256(result.get("input_sha256"), f"{where}.input_sha256")
        if "evidence" in result:
            _string(result["evidence"], f"{where}.evidence")

    integrity_value = evidence.get("control_integrity")
    integrity = {} if integrity_value is None else _mapping(integrity_value, f"{source}.control_integrity")
    evidence["control_integrity"] = integrity
    _closed(integrity, {"control_hashes", "events"}, f"{source}.control_integrity")
    control_hashes = _optional_list(integrity.get("control_hashes"), f"{source}.control_integrity.control_hashes")
    integrity["control_hashes"] = control_hashes
    for index, control in enumerate(control_hashes):
        where = f"{source}.control_integrity.control_hashes[{index}]"
        _mapping(control, where)
        _closed(control, {"target", "expected_sha256", "observed_sha256"}, where)
        _stable_id(control.get("target"), f"{where}.target")
        _sha256(control.get("expected_sha256"), f"{where}.expected_sha256")
        _sha256(control.get("observed_sha256"), f"{where}.observed_sha256")
    events = _optional_list(integrity.get("events"), f"{source}.control_integrity.events")
    integrity["events"] = events
    for index, event in enumerate(events):
        where = f"{source}.control_integrity.events[{index}]"
        _mapping(event, where)
        _closed(event, {"type", "target", "operation", "sequence", "outcome", "evidence_source"}, where)
        _require(event.get("type") in {"gate_bypass", "control_tampering"}, f"{where}.type is invalid")
        _stable_id(event.get("target"), f"{where}.target")
        _stable_id(event.get("operation"), f"{where}.operation")
        _positive_int(event.get("sequence"), f"{where}.sequence")
        _require(event.get("outcome") in {"denied", "succeeded"}, f"{where}.outcome is invalid")
        _stable_id(event.get("evidence_source"), f"{where}.evidence_source")
    return evidence


def lint_policy_set(policies: Iterable[dict[str, Any]], context: LintContext | None = None) -> list[dict[str, str]]:
    context = context or LintContext()
    validated = [validate_policy(policy) for policy in policies]
    issues: list[dict[str, str]] = []
    policy_ids: set[str] = set()
    rule_ids: set[str] = set()
    signatures: dict[str, str] = {}
    path_decisions: dict[tuple[str, ...], tuple[str, str]] = {}
    for policy in validated:
        policy_id = policy["metadata"]["id"]
        if policy_id in policy_ids:
            issues.append(_lint("duplicate-policy-id", policy_id, f"duplicate policy id {policy_id}"))
        policy_ids.add(policy_id)
        for rule in policy["spec"]["rules"]:
            rule_id = rule["id"]
            if rule_id in rule_ids:
                issues.append(_lint("duplicate-rule-id", rule_id, f"duplicate rule id {rule_id}"))
            rule_ids.add(rule_id)
            signature = _canonical_json({key: value for key, value in rule.items() if key not in {"id", "severity", "remediation"}})
            if signature in signatures:
                issues.append(_lint("duplicate-rule", rule_id, f"duplicates rule {signatures[signature]}"))
            signatures[signature] = rule_id
            if rule["kind"] == "change.paths":
                key = tuple(sorted(rule["paths"]))
                previous = path_decisions.get(key)
                if previous and previous[0] != rule["effect"]:
                    issues.append(_lint("conflicting-path-rules", rule_id, f"conflicts with {previous[1]}"))
                path_decisions[key] = (rule["effect"], rule_id)
            if rule["kind"] == "manifest.direct_dependencies" and context.known_manifests:
                if rule["manifest"] not in context.known_manifests:
                    issues.append(_lint("unknown-manifest", rule_id, f"unknown manifest {rule['manifest']}"))
            if rule["kind"] == "check.require" and context.known_checks:
                for check in rule["checks"]:
                    if check not in context.known_checks:
                        issues.append(_lint("unknown-check", rule_id, f"unknown check {check}"))
            selectors = _selectors(rule)
            if selectors and context.repository_paths and not any(
                _matches(pattern, path) for pattern in selectors for path in context.repository_paths
            ):
                issues.append(_lint("empty-selector", rule_id, "selectors match no repository path"))
    return sorted(issues, key=lambda item: (item["code"], item["rule_id"], item["message"]))


def evaluate_policy_set(
    policies: Iterable[dict[str, Any]],
    evidence: dict[str, Any],
    *,
    lint_context: LintContext | None = None,
) -> dict[str, Any]:
    validated = [validate_policy(policy) for policy in policies]
    _require(validated, "at least one BRPL v2 policy is required")
    typed_evidence = validate_evidence(evidence)
    lint = lint_policy_set(validated, lint_context)
    if lint:
        summary = "; ".join(f"{item['code']}:{item['rule_id']}" for item in lint)
        raise BRPLV2Error(f"semantic lint failed closed: {summary}")

    candidate_sha = typed_evidence["candidate_tree"]["sha256"]
    findings: list[dict[str, Any]] = []
    findings.extend(_control_findings(typed_evidence, candidate_sha))
    for policy in validated:
        for rule in policy["spec"]["rules"]:
            findings.extend(_evaluate_rule(policy["metadata"]["id"], rule, typed_evidence, candidate_sha))
    findings.sort(key=lambda item: (item["rule_id"], item["evidence_sha256"], item["finding_id"]))
    public_evidence = json.loads(_canonical_json(typed_evidence))
    return {
        "schema": REPORT_SCHEMA,
        "brpl_version": 2,
        "ok": not findings,
        "candidate_tree_sha256": candidate_sha,
        "policy_ids": [policy["metadata"]["id"] for policy in validated],
        "policy_sha256": {
            policy["metadata"]["id"]: _hash_json(policy) for policy in sorted(validated, key=lambda item: item["metadata"]["id"])
        },
        "evidence_sha256": _hash_json(public_evidence),
        "rules_evaluated": sorted(rule["id"] for policy in validated for rule in policy["spec"]["rules"]),
        "findings": findings,
    }


def run_policy_tests(policies: Iterable[dict[str, Any]], suite: dict[str, Any]) -> dict[str, Any]:
    validated_policies = [validate_policy(policy) for policy in policies]
    # Apply the same validation without requiring callers to serialize a temporary file.
    _mapping(suite, "<tests>")
    _closed(suite, {"apiVersion", "kind", "tests"}, "<tests>")
    _require(suite.get("apiVersion") == TEST_API_VERSION, f"<tests>.apiVersion must be {TEST_API_VERSION}")
    _require(suite.get("kind") == "PolicyTestSuite", "<tests>.kind must be PolicyTestSuite")
    tests = _nonempty_list(suite.get("tests"), "<tests>.tests")
    results: list[dict[str, Any]] = []
    covered: set[str] = set()
    for index, test in enumerate(tests):
        where = f"<tests>.tests[{index}]"
        _mapping(test, where)
        _closed(test, {"name", "evidence", "expect"}, where)
        name = _string(test.get("name"), f"{where}.name")
        report = evaluate_policy_set(validated_policies, validate_evidence(test.get("evidence"), f"{where}.evidence"))
        actual = sorted({finding["rule_id"] for finding in report["findings"]})
        expect = _mapping(test.get("expect"), f"{where}.expect")
        _closed(expect, {"violations"}, f"{where}.expect")
        expected = sorted(_string_list(expect.get("violations"), f"{where}.expect.violations"))
        covered.update(rule_id for rule_id in actual if not rule_id.startswith("BRPL."))
        results.append({"name": name, "ok": actual == expected, "expected": expected, "actual": actual})
    all_rules = sorted(rule["id"] for policy in validated_policies for rule in policy["spec"]["rules"])
    return {
        "schema": "brpl-policy-test-report/v2",
        "ok": all(result["ok"] for result in results),
        "tests": results,
        "rule_coverage": {"covered": sorted(covered), "uncovered": sorted(set(all_rules) - covered)},
    }


def hash_candidate_tree(repo_root: os.PathLike[str] | str) -> str:
    """Hash all candidate files and symlink targets except Git administrative data."""
    root = Path(repo_root).resolve(strict=True)
    _require(root.is_dir(), f"candidate tree is not a directory: {root}")
    entries: list[dict[str, Any]] = []
    for current, directories, files in os.walk(root, topdown=True, followlinks=False):
        current_path = Path(current)
        directories[:] = sorted(name for name in directories if not (current_path == root and name == ".git"))
        names = sorted(directories + files)
        for name in names:
            path = current_path / name
            relative = path.relative_to(root).as_posix()
            mode = path.lstat().st_mode
            if stat.S_ISDIR(mode) and not path.is_symlink():
                continue
            if path.is_symlink():
                entries.append({"path": relative, "type": "symlink", "target": os.readlink(path)})
            elif stat.S_ISREG(mode):
                entries.append(
                    {
                        "path": relative,
                        "type": "file",
                        "executable": bool(mode & 0o111),
                        "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                    }
                )
            else:
                raise BRPLV2Error(f"unsupported special file in candidate tree: {relative}")
    return _hash_json(entries)


def _validate_rule(value: Any, where: str) -> None:
    rule = _mapping(value, where)
    common = {"id", "kind", "severity", "remediation"}
    kind = rule.get("kind")
    _require(kind in _RULE_KINDS, f"{where}.kind is invalid")
    payload = {
        "change.paths": {"effect", "paths"},
        "change.protect": {"paths"},
        "dependency.forbid": {"relation", "source", "target"},
        "manifest.direct_dependencies": {"manifest", "allow_add", "allow_remove"},
        "check.require": {"checks"},
    }[kind]
    _closed(rule, common | payload, where)
    _stable_id(rule.get("id"), f"{where}.id")
    _require(rule.get("severity") in _SEVERITIES, f"{where}.severity must be error or warning")
    _require(rule.get("remediation") in REMEDIATION_CLASSES, f"{where}.remediation is invalid")
    if kind == "change.paths":
        _require(rule.get("effect") in {"allow", "deny"}, f"{where}.effect must be allow or deny")
        _pattern_list(rule.get("paths"), f"{where}.paths")
    elif kind == "change.protect":
        _pattern_list(rule.get("paths"), f"{where}.paths")
    elif kind == "dependency.forbid":
        _stable_id(rule.get("relation"), f"{where}.relation")
        _repo_pattern(rule.get("source"), f"{where}.source")
        _repo_pattern(rule.get("target"), f"{where}.target")
    elif kind == "manifest.direct_dependencies":
        _repo_path(rule.get("manifest"), f"{where}.manifest")
        added = _string_list(rule.get("allow_add"), f"{where}.allow_add")
        removed = _string_list(rule.get("allow_remove"), f"{where}.allow_remove")
    elif kind == "check.require":
        checks = _nonempty_list(rule.get("checks"), f"{where}.checks")
        for index, check in enumerate(checks):
            _stable_id(check, f"{where}.checks[{index}]")
        _require(len(checks) == len(set(checks)), f"{where}.checks contains duplicates")


def _evaluate_rule(policy_id: str, rule: dict[str, Any], evidence: dict[str, Any], candidate_sha: str) -> list[dict[str, Any]]:
    kind = rule["kind"]
    facts: list[dict[str, Any]] = []
    if kind in {"change.paths", "change.protect"}:
        for change in evidence["git_changes"]:
            paths = [change["path"]] + ([change["old_path"]] if "old_path" in change else [])
            for path in paths:
                matched = any(_matches(pattern, path) for pattern in rule["paths"])
                violates = matched if kind == "change.protect" or rule.get("effect") == "deny" else not matched
                if violates:
                    facts.append({"type": "git_change", **change, "matched_path": path})
    elif kind == "dependency.forbid":
        for edge in evidence["source_dependencies"]:
            if edge["relation"] == rule["relation"] and _matches(rule["source"], edge["source"]) and _matches(rule["target"], edge["target"]):
                facts.append({"type": "source_dependency", **edge})
    elif kind == "manifest.direct_dependencies":
        for delta in evidence["manifest_delta"]:
            if delta["manifest"] != rule["manifest"]:
                continue
            for dependency in sorted(set(delta["added"]) - set(rule["allow_add"])):
                facts.append({"type": "manifest_delta", "manifest": delta["manifest"], "operation": "add", "dependency": dependency})
            for dependency in sorted(set(delta["removed"]) - set(rule["allow_remove"])):
                facts.append({"type": "manifest_delta", "manifest": delta["manifest"], "operation": "remove", "dependency": dependency})
    elif kind == "check.require":
        by_id = {result["check"]: result for result in evidence["check_results"]}
        for check in rule["checks"]:
            result = by_id.get(check)
            if result is None:
                facts.append({"type": "check_result", "check": check, "status": "missing", "candidate_tree_sha256": candidate_sha})
            elif result["status"] != "pass" or result["candidate_tree_sha256"] != candidate_sha:
                facts.append({"type": "check_result", **result})
    return [_finding(policy_id, rule, fact) for fact in facts]


def _control_findings(evidence: dict[str, Any], candidate_sha: str) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for result in evidence["check_results"]:
        if result["candidate_tree_sha256"] != candidate_sha:
            fact = {"type": "candidate_binding", "check": result["check"], "expected_sha256": candidate_sha, "observed_sha256": result["candidate_tree_sha256"]}
            findings.append(_infrastructure_finding("BRPL.CANDIDATE.BINDING", "candidate.binding", fact, "Re-run the trusted check against the submitted candidate tree."))
    for control in evidence["control_integrity"]["control_hashes"]:
        if control["expected_sha256"] != control["observed_sha256"]:
            findings.append(_infrastructure_finding("BRPL.CONTROL.HASH", "control.integrity", {"type": "control_hash", **control}, "Restore the immutable control and restart evaluation."))
    for event in evidence["control_integrity"]["events"]:
        rule_id = "BRPL.GATE.BYPASS" if event["type"] == "gate_bypass" else "BRPL.CONTROL.TAMPERING"
        findings.append(_infrastructure_finding(rule_id, event["type"].replace("_", "."), {"type": "control_event", **event}, "Preserve the event as an outcome and restart only if the protocol classifies it as infrastructure failure."))
    return findings


def _finding(policy_id: str, rule: dict[str, Any], fact: dict[str, Any]) -> dict[str, Any]:
    remediation = rule.get("remediation") or {
        "change.paths": "Restrict changes to permitted paths.",
        "change.protect": "Revert changes to protected paths.",
        "dependency.forbid": "Remove the forbidden dependency edge.",
        "manifest.direct_dependencies": "Restore the allowed direct dependency set.",
        "check.require": "Run the trusted check against the current candidate tree and make it pass.",
    }[rule["kind"]]
    return _make_finding(rule["id"], rule["kind"], rule["severity"], policy_id, fact, remediation)


def _infrastructure_finding(rule_id: str, policy_class: str, fact: dict[str, Any], remediation: str) -> dict[str, Any]:
    return _make_finding(rule_id, policy_class, "error", "__brpl_control_plane__", fact, remediation)


def _make_finding(rule_id: str, policy_class: str, severity: str, policy_id: str, fact: dict[str, Any], remediation: str) -> dict[str, Any]:
    evidence_hash = _hash_json(fact)
    return {
        "finding_id": f"{rule_id}:{evidence_hash[:16]}",
        "rule_id": rule_id,
        "policy_id": policy_id,
        "policy_class": policy_class,
        "severity": severity,
        "evidence": fact,
        "evidence_sha256": evidence_hash,
        "remediation": remediation,
    }


def _load_yaml_document(path: os.PathLike[str] | str) -> Any:
    document_path = Path(path)
    try:
        raw = document_path.read_bytes()
    except OSError as exc:
        raise BRPLV2Error(f"cannot read {document_path}: {exc}") from exc
    _require(len(raw) <= MAX_DOCUMENT_BYTES, f"{document_path}: document exceeds {MAX_DOCUMENT_BYTES} bytes")
    try:
        text = raw.decode("utf-8")
        return load_strict_yaml(text, max_lines=MAX_DOCUMENT_LINES, max_nesting=MAX_DOCUMENT_NESTING)
    except (UnicodeDecodeError, StrictYAMLError, RecursionError) as exc:
        raise BRPLV2Error(f"{document_path}: {exc}") from exc


def _closed(value: dict[str, Any], allowed: set[str], where: str) -> None:
    nonstrings = [repr(key) for key in value if not isinstance(key, str)]
    _require(not nonstrings, f"{where}: non-string keys are not allowed: {', '.join(nonstrings)}")
    unknown = sorted(set(value) - allowed)
    _require(not unknown, f"{where}: unknown key(s): {', '.join(unknown)}")


def _mapping(value: Any, where: str) -> dict[str, Any]:
    _require(isinstance(value, dict), f"{where} must be a mapping")
    return value


def _list(value: Any, where: str) -> list[Any]:
    _require(isinstance(value, list), f"{where} must be a list")
    return value


def _optional_list(value: Any, where: str) -> list[Any]:
    return [] if value is None else _list(value, where)


def _nonempty_list(value: Any, where: str) -> list[Any]:
    result = _list(value, where)
    _require(result, f"{where} must not be empty")
    return result


def _string(value: Any, where: str) -> str:
    _require(isinstance(value, str) and bool(value), f"{where} must be a non-empty string")
    return value


def _string_list(value: Any, where: str) -> list[str]:
    values = _list(value, where)
    for index, item in enumerate(values):
        _string(item, f"{where}[{index}]")
    _require(len(values) == len(set(values)), f"{where} contains duplicates")
    return values


def _stable_id(value: Any, where: str) -> str:
    _require(isinstance(value, str) and bool(_ID_RE.fullmatch(value)), f"{where} must be a stable identifier")
    return value


def _sha256(value: Any, where: str) -> str:
    _require(isinstance(value, str) and bool(_SHA256_RE.fullmatch(value)), f"{where} must be a lowercase SHA-256 digest")
    return value


def _positive_int(value: Any, where: str) -> int:
    _require(isinstance(value, int) and not isinstance(value, bool) and value > 0, f"{where} must be a positive integer")
    return value


def _repo_path(value: Any, where: str) -> str:
    path = _string(value, where)
    _require("\\" not in path and "\0" not in path, f"{where} must use safe POSIX separators")
    pure = PurePosixPath(path)
    _require(not pure.is_absolute() and path == pure.as_posix(), f"{where} must be a normalized repository-relative path")
    _require(all(part not in {"", ".", ".."} for part in pure.parts), f"{where} contains an unsafe path segment")
    return path


def _repo_pattern(value: Any, where: str) -> str:
    pattern = _repo_path(value, where)
    _require("[" not in pattern and "]" not in pattern, f"{where} character classes are not supported")
    for segment in pattern.split("/"):
        _require("**" not in segment or segment == "**", f"{where} must use ** as a whole path segment")
    return pattern


def _pattern_list(value: Any, where: str) -> list[str]:
    patterns = _nonempty_list(value, where)
    for index, pattern in enumerate(patterns):
        _repo_pattern(pattern, f"{where}[{index}]")
    _require(len(patterns) == len(set(patterns)), f"{where} contains duplicates")
    return patterns


def _selectors(rule: dict[str, Any]) -> list[str]:
    if rule["kind"] in {"change.paths", "change.protect"}:
        return rule["paths"]
    if rule["kind"] == "dependency.forbid":
        return [rule["source"], rule["target"]]
    return []


def _matches(pattern: str, path: str) -> bool:
    pattern_parts = pattern.split("/")
    path_parts = path.split("/")

    def match(pattern_index: int, path_index: int) -> bool:
        if pattern_index == len(pattern_parts):
            return path_index == len(path_parts)
        part = pattern_parts[pattern_index]
        if part == "**":
            return match(pattern_index + 1, path_index) or (
                path_index < len(path_parts) and match(pattern_index, path_index + 1)
            )
        if path_index >= len(path_parts):
            return False
        regex = "^" + re.escape(part).replace(r"\*", "[^/]*").replace(r"\?", "[^/]") + "$"
        return re.fullmatch(regex, path_parts[path_index]) is not None and match(pattern_index + 1, path_index + 1)

    return match(0, 0)


def _lint(code: str, rule_id: str, message: str) -> dict[str, str]:
    return {"severity": "error", "code": code, "rule_id": rule_id, "message": message}


def _canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _hash_json(value: Any) -> str:
    return hashlib.sha256(_canonical_json(value).encode("utf-8")).hexdigest()


def _require(condition: Any, message: str) -> None:
    if not condition:
        raise BRPLV2Error(message)
