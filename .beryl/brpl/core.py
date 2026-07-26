"""BRPL v1 policy loading, validation, evaluation, and reports."""

from __future__ import annotations

import ast
import hashlib
import json
import os
import re
import subprocess
import tomllib
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any

from .strict_yaml import StrictYAMLError, load_strict_yaml


CHECKER_VERSION = "1.0.0"
REPORT_SCHEMA = "brpl-report/v1"
MAX_POLICY_BYTES = 64 * 1024
MAX_POLICY_LINES = 2000
MAX_POLICY_NESTING = 24
MAX_CHECK_TIMEOUT_SECONDS = 600


class BRPLSchemaError(ValueError):
    pass


class BRPLConfigError(RuntimeError):
    pass


class BRPLEvaluationError(RuntimeError):
    pass


@dataclass(frozen=True)
class EvaluationConfig:
    repo_root: Path
    base_ref: str
    check_registry_path: Path | None = None
    execute_checks: bool = True
    check_results: dict[str, dict[str, str]] | None = None


@dataclass(frozen=True)
class Change:
    status: str
    path: str
    old_path: str | None = None

    @property
    def paths(self) -> tuple[str, ...]:
        if self.old_path:
            return (self.old_path, self.path)
        return (self.path,)


_ID_RE = re.compile(r"^[A-Za-z0-9_.:-]+$")
_PEP503_RE = re.compile(r"[-_.]+")
_KIND_VALUES = {"repository", "task"}
_PRIVATE_PREFIX = "__brpl_"
_SCHEMA_PATH = Path(__file__).with_name("schemas") / "brpl-v1.schema.json"
_BUNDLED_SCHEMA: dict[str, Any] | None = None
_TOP_KEYS = {
    "version",
    "policy_id",
    "kind",
    "change_scope",
    "protected_paths",
    "architecture",
    "new_dependencies",
    "required_checks",
}
_CHANGE_SCOPE_RULE_KEYS = {"id", "allow", "deny"}
_RULE_ID_KEYS = {"id"}


def load_policy_file(path: os.PathLike[str] | str) -> dict[str, Any]:
    policy_path = Path(path)
    try:
        raw = policy_path.read_bytes()
    except OSError as exc:
        raise BRPLConfigError(f"cannot read policy {policy_path}: {exc}") from exc
    if len(raw) > MAX_POLICY_BYTES:
        raise BRPLSchemaError(f"{policy_path}: policy exceeds {MAX_POLICY_BYTES} bytes")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise BRPLSchemaError(f"{policy_path}: policy must be UTF-8: {exc}") from exc
    try:
        data = load_strict_yaml(
            text,
            max_lines=MAX_POLICY_LINES,
            max_nesting=MAX_POLICY_NESTING,
        )
    except (StrictYAMLError, RecursionError) as exc:
        raise BRPLSchemaError(f"{policy_path}: {exc}") from exc
    policy = validate_policy(data, str(policy_path))
    policy[_PRIVATE_PREFIX + "source"] = str(policy_path)
    policy[_PRIVATE_PREFIX + "raw_hash"] = _sha256_hex(raw)
    policy[_PRIVATE_PREFIX + "semantic_hash"] = _semantic_policy_hash(policy)
    return policy


def validate_policy(data: Any, source: str = "<policy>") -> dict[str, Any]:
    if not isinstance(data, dict):
        raise BRPLSchemaError(f"{source}: policy must be a mapping")
    _validate_against_bundled_schema(data, source)
    _reject_unknown_keys(data, _TOP_KEYS, source)
    _require(data.get("version") == 1, f"{source}: version must be 1")
    _require(_valid_id(data.get("policy_id")), f"{source}: policy_id must be a stable identifier")
    _require(data.get("kind") in _KIND_VALUES, f"{source}: kind must be repository or task")

    if "change_scope" in data:
        _validate_change_scope(data["change_scope"], source)
    if "protected_paths" in data:
        _validate_pattern_rules(data["protected_paths"], f"{source}: protected_paths")
    if "architecture" in data:
        _validate_architecture(data["architecture"], source)
    if "new_dependencies" in data:
        _validate_new_dependencies(data["new_dependencies"], source)
    if "required_checks" in data:
        _validate_required_checks(data["required_checks"], source)
    return data


def evaluate_policy_set(policies: list[dict[str, Any]], config: EvaluationConfig) -> dict[str, Any]:
    if not policies:
        raise BRPLConfigError("at least one BRPL policy is required")
    if not config.base_ref:
        raise BRPLConfigError("explicit git baseline is required")

    repo_root = config.repo_root.resolve()
    baseline_sha = _git_text(repo_root, ["rev-parse", "--verify", f"{config.base_ref}^{{commit}}"]).strip()
    _validate_policy_set_uniqueness(policies)
    rules = _collect_rules(policies)
    changes = _collect_changes(repo_root, config.base_ref)
    changed_paths = sorted({path for change in changes for path in change.paths})
    final_source_paths = _collect_final_source_paths(repo_root)
    module_index = _build_python_module_index(repo_root, final_source_paths)

    violations: list[dict[str, Any]] = []
    for policy in policies:
        violations.extend(_evaluate_change_scope(policy, changed_paths))
        violations.extend(_evaluate_protected_paths(policy, changes))
        violations.extend(_evaluate_architecture(policy, repo_root, final_source_paths, module_index))
        violations.extend(_evaluate_new_dependencies(policy, repo_root, config.base_ref))

    required_check_ids = sorted({rule["check"] for rule in rules if rule["family"] == "required_checks"})
    check_results = _resolve_check_results(required_check_ids, config)
    for policy in policies:
        violations.extend(_evaluate_required_checks(policy, check_results))

    violations = sorted(
        violations,
        key=lambda item: (
            item["rule_id"],
            item.get("file", ""),
            item["evidence_hash_prefix"],
            item["violation_id"],
        ),
    )
    return {
        "schema": REPORT_SCHEMA,
        "checker_version": CHECKER_VERSION,
        "brpl_version": 1,
        "ok": not violations,
        "baseline": {"ref": config.base_ref, "sha": baseline_sha},
        "policy_ids": [policy["policy_id"] for policy in policies],
        "policy_hashes": {
            "raw_sha256": {
                policy["policy_id"]: policy.get(_PRIVATE_PREFIX + "raw_hash", _semantic_policy_hash(policy))
                for policy in policies
            },
            "semantic_sha256": {
                policy["policy_id"]: policy.get(_PRIVATE_PREFIX + "semantic_hash", _semantic_policy_hash(policy))
                for policy in policies
            },
        },
        "rules_evaluated": sorted(rules, key=lambda item: (item["rule_id"], item["family"])),
        "changed_files": changed_paths,
        "violations": violations,
        "check_results": {key: check_results[key] for key in sorted(check_results)},
    }


def report_to_json(report: dict[str, Any]) -> str:
    return json.dumps(report, indent=2, sort_keys=True) + "\n"


def report_to_human(report: dict[str, Any]) -> str:
    baseline = report["baseline"]
    lines = [
        f"BRPL v{report['brpl_version']} policy report",
        f"schema: {report['schema']}",
        f"checker: {report['checker_version']}",
        f"baseline: {baseline['ref']} ({baseline['sha']})",
        "policies: " + ", ".join(report["policy_ids"]),
        f"rules evaluated: {len(report['rules_evaluated'])}",
        f"changed files: {len(report['changed_files'])}",
    ]
    if report["ok"]:
        lines.append("status: PASS")
        return "\n".join(lines) + "\n"
    lines.append("status: FAIL")
    for violation in report["violations"]:
        file_part = f" file={violation['file']}" if violation.get("file") else ""
        evidence_text = violation["evidence"]["text"]
        lines.append(
            f"- {violation['severity']} {violation['rule_id']} {violation['violation_id']}{file_part}: {evidence_text}"
        )
        lines.append(f"  remediation: {violation['remediation']}")
    return "\n".join(lines) + "\n"


def _validate_change_scope(value: Any, source: str) -> None:
    _require(isinstance(value, list), f"{source}: change_scope must be a list")
    for index, rule in enumerate(value):
        where = f"{source}: change_scope[{index}]"
        _require(isinstance(rule, dict), f"{where} must be a rule mapping")
        _reject_unknown_keys(rule, _CHANGE_SCOPE_RULE_KEYS, where)
        _require(_valid_id(rule.get("id")), f"{where}.id must be a stable identifier")
        _require("allow" in rule or "deny" in rule, f"{where} must include allow or deny")
        if "allow" in rule:
            _validate_pattern_list(rule["allow"], f"{where}.allow")
        if "deny" in rule:
            _validate_pattern_list(rule["deny"], f"{where}.deny")


def _validate_pattern_list(value: Any, source: str) -> None:
    _require(isinstance(value, list), f"{source} must be a list")
    for index, pattern in enumerate(value):
        where = f"{source}[{index}]"
        _require(isinstance(pattern, str), f"{where} must be a string")
        _validate_repo_pattern(pattern, where)


def _validate_pattern_rules(value: Any, source: str) -> None:
    _require(isinstance(value, list), f"{source} must be a list")
    for index, rule in enumerate(value):
        where = f"{source}[{index}]"
        _require(isinstance(rule, dict), f"{where} must be a rule mapping")
        _reject_unknown_keys(rule, _RULE_ID_KEYS | {"pattern"}, where)
        _require(_valid_id(rule.get("id")), f"{where}.id must be a stable identifier")
        _require(isinstance(rule.get("pattern"), str), f"{where}.pattern must be a string")
        _validate_repo_pattern(rule["pattern"], f"{where}.pattern")


def _validate_architecture(value: Any, source: str) -> None:
    _require(isinstance(value, dict), f"{source}: architecture must be a mapping")
    _reject_unknown_keys(value, {"forbid_imports"}, f"{source}: architecture")
    if "forbid_imports" not in value:
        return
    rules = value["forbid_imports"]
    _require(isinstance(rules, list), f"{source}: architecture.forbid_imports must be a list")
    for index, rule in enumerate(rules):
        where = f"{source}: architecture.forbid_imports[{index}]"
        _require(isinstance(rule, dict), f"{where} must be a rule mapping")
        _reject_unknown_keys(rule, _RULE_ID_KEYS | {"from", "to"}, where)
        _require(_valid_id(rule.get("id")), f"{where}.id must be a stable identifier")
        _require(isinstance(rule.get("from"), str), f"{where}.from must be a string")
        _require(isinstance(rule.get("to"), str), f"{where}.to must be a string")
        _validate_repo_pattern(rule["from"], f"{where}.from")
        _validate_repo_pattern(rule["to"], f"{where}.to")


def _validate_new_dependencies(value: Any, source: str) -> None:
    _require(isinstance(value, dict), f"{source}: new_dependencies must be a rule mapping")
    _reject_unknown_keys(value, _RULE_ID_KEYS | {"manifest", "allow"}, f"{source}: new_dependencies")
    _require(_valid_id(value.get("id")), f"{source}: new_dependencies.id must be a stable identifier")
    _require(isinstance(value.get("manifest"), str), f"{source}: new_dependencies.manifest must be a string")
    _validate_repo_path(value["manifest"], f"{source}: new_dependencies.manifest")
    _require(value.get("allow") is False, f"{source}: new_dependencies.allow must be false in BRPL v1")


def _validate_required_checks(value: Any, source: str) -> None:
    _require(isinstance(value, list), f"{source}: required_checks must be a list")
    for index, rule in enumerate(value):
        where = f"{source}: required_checks[{index}]"
        _require(isinstance(rule, dict), f"{where} must be a rule mapping")
        _reject_unknown_keys(rule, _RULE_ID_KEYS | {"check"}, where)
        _require(_valid_id(rule.get("id")), f"{where}.id must be a stable identifier")
        _require(_valid_id(rule.get("check")), f"{where}.check must name a trusted check id")


def _reject_unknown_keys(data: dict[str, Any], allowed: set[str], source: str) -> None:
    nonstring = [repr(key) for key in data if not isinstance(key, str)]
    if nonstring:
        raise BRPLSchemaError(f"{source}: non-string key(s): {', '.join(nonstring)}")
    reserved = sorted(key for key in data if str(key).startswith(_PRIVATE_PREFIX))
    if reserved:
        raise BRPLSchemaError(f"{source}: reserved key(s): {', '.join(reserved)}")
    unknown = sorted(key for key in data if key not in allowed)
    if unknown:
        raise BRPLSchemaError(f"{source}: unknown key(s): {', '.join(unknown)}")


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise BRPLSchemaError(message)


def _valid_id(value: Any) -> bool:
    return isinstance(value, str) and bool(_ID_RE.fullmatch(value))


def _validate_against_bundled_schema(data: Any, source: str) -> None:
    _validate_json_schema(data, _bundled_policy_schema(), source, _bundled_policy_schema())


def _bundled_policy_schema() -> dict[str, Any]:
    global _BUNDLED_SCHEMA
    if _BUNDLED_SCHEMA is None:
        try:
            raw = _SCHEMA_PATH.read_text(encoding="utf-8")
            schema = json.loads(raw)
        except (OSError, json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise BRPLConfigError(f"cannot load bundled BRPL schema {_SCHEMA_PATH}: {exc}") from exc
        if not isinstance(schema, dict):
            raise BRPLConfigError(f"bundled BRPL schema must be a JSON object: {_SCHEMA_PATH}")
        _BUNDLED_SCHEMA = schema
    return _BUNDLED_SCHEMA


def _validate_json_schema(instance: Any, schema: dict[str, Any], source: str, root: dict[str, Any]) -> None:
    if "$ref" in schema:
        _validate_json_schema(instance, _resolve_schema_ref(schema["$ref"], root), source, root)
        return
    if "allOf" in schema:
        for item in schema["allOf"]:
            _validate_json_schema(instance, item, source, root)
    if "anyOf" in schema:
        if not any(_json_schema_accepts(instance, item, root) for item in schema["anyOf"]):
            raise BRPLSchemaError(f"{source}: value does not match any allowed schema shape")
    if "not" in schema and _json_schema_accepts(instance, schema["not"], root):
        raise BRPLSchemaError(f"{source}: value is rejected by the bundled schema")
    if "const" in schema and instance != schema["const"]:
        raise BRPLSchemaError(f"{source}: value must be {schema['const']!r}")
    if "enum" in schema and instance not in schema["enum"]:
        raise BRPLSchemaError(f"{source}: value must be one of {', '.join(map(repr, schema['enum']))}")
    if "type" in schema:
        _validate_schema_type(instance, schema["type"], source)
    if isinstance(instance, str):
        if "minLength" in schema and len(instance) < schema["minLength"]:
            raise BRPLSchemaError(f"{source}: string is shorter than {schema['minLength']}")
        if "pattern" in schema and re.search(schema["pattern"], instance) is None:
            raise BRPLSchemaError(f"{source}: string does not match required pattern")
    if isinstance(instance, list) and "items" in schema:
        item_schema = schema["items"]
        for index, item in enumerate(instance):
            _validate_json_schema(item, item_schema, f"{source}[{index}]", root)
    if isinstance(instance, dict):
        nonstring = [repr(key) for key in instance if not isinstance(key, str)]
        if nonstring:
            raise BRPLSchemaError(f"{source}: non-string key(s): {', '.join(nonstring)}")
        reserved = sorted(key for key in instance if key.startswith(_PRIVATE_PREFIX))
        if reserved:
            raise BRPLSchemaError(f"{source}: reserved key(s): {', '.join(reserved)}")
        properties = schema.get("properties", {})
        if schema.get("additionalProperties") is False:
            unknown = sorted(key for key in instance if key not in properties)
            if unknown:
                raise BRPLSchemaError(f"{source}: unknown key(s): {', '.join(unknown)}")
        for required_key in schema.get("required", []):
            if required_key not in instance:
                raise BRPLSchemaError(f"{source}: missing required key {required_key}")
        for key, value in instance.items():
            if key in properties:
                _validate_json_schema(value, properties[key], f"{source}.{key}", root)


def _json_schema_accepts(instance: Any, schema: dict[str, Any], root: dict[str, Any]) -> bool:
    try:
        _validate_json_schema(instance, schema, "<schema>", root)
    except BRPLSchemaError:
        return False
    return True


def _resolve_schema_ref(ref: Any, root: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(ref, str) or not ref.startswith("#/"):
        raise BRPLConfigError(f"unsupported BRPL schema reference: {ref!r}")
    current: Any = root
    for part in ref[2:].split("/"):
        if not isinstance(current, dict) or part not in current:
            raise BRPLConfigError(f"unresolved BRPL schema reference: {ref!r}")
        current = current[part]
    if not isinstance(current, dict):
        raise BRPLConfigError(f"BRPL schema reference does not resolve to an object: {ref!r}")
    return current


def _validate_schema_type(instance: Any, type_name: str, source: str) -> None:
    checks = {
        "object": lambda value: isinstance(value, dict),
        "array": lambda value: isinstance(value, list),
        "string": lambda value: isinstance(value, str),
        "boolean": lambda value: isinstance(value, bool),
        "integer": lambda value: isinstance(value, int) and not isinstance(value, bool),
    }
    check = checks.get(type_name)
    if check is None:
        raise BRPLConfigError(f"unsupported BRPL schema type: {type_name!r}")
    if not check(instance):
        raise BRPLSchemaError(f"{source}: expected {type_name}")


def _validate_policy_set_uniqueness(policies: list[dict[str, Any]]) -> None:
    policy_ids: set[str] = set()
    rule_ids: set[str] = set()
    for policy in policies:
        policy_id = policy["policy_id"]
        if policy_id in policy_ids:
            raise BRPLConfigError(f"duplicate policy_id {policy_id!r}")
        policy_ids.add(policy_id)
        for rule in _collect_rules_for_policy(policy):
            rule_id = rule["rule_id"]
            if rule_id in rule_ids:
                raise BRPLConfigError(f"duplicate rule id {rule_id!r}")
            rule_ids.add(rule_id)


def _collect_rules(policies: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rules: list[dict[str, Any]] = []
    for policy in policies:
        rules.extend(_collect_rules_for_policy(policy))
    return rules


def _collect_rules_for_policy(policy: dict[str, Any]) -> list[dict[str, Any]]:
    policy_id = policy["policy_id"]
    rules: list[dict[str, Any]] = []
    for rule in policy.get("change_scope", []) or []:
        rules.append(
            {
                "rule_id": rule["id"],
                "policy_id": policy_id,
                "family": "change_scope",
                "allow": list(rule.get("allow") or []),
                "deny": list(rule.get("deny") or []),
            }
        )
    for rule in policy.get("protected_paths", []) or []:
        rules.append(
            {
                "rule_id": rule["id"],
                "policy_id": policy_id,
                "family": "protected_paths",
                "pattern": rule["pattern"],
            }
        )
    for rule in (policy.get("architecture") or {}).get("forbid_imports", []) or []:
        rules.append(
            {
                "rule_id": rule["id"],
                "policy_id": policy_id,
                "family": "architecture.forbid_imports",
                "from": rule["from"],
                "to": rule["to"],
            }
        )
    if policy.get("new_dependencies"):
        rule = policy["new_dependencies"]
        rules.append(
            {
                "rule_id": rule["id"],
                "policy_id": policy_id,
                "family": "new_dependencies",
                "manifest": rule["manifest"],
                "allow": False,
            }
        )
    for rule in policy.get("required_checks", []) or []:
        rules.append(
            {
                "rule_id": rule["id"],
                "policy_id": policy_id,
                "family": "required_checks",
                "check": rule["check"],
            }
        )
    return rules


def _collect_changes(repo_root: Path, base_ref: str) -> list[Change]:
    _git_text(repo_root, ["rev-parse", "--verify", f"{base_ref}^{{commit}}"])
    output = _git_bytes(
        repo_root,
        ["diff", "--name-status", "-z", "--find-renames", "--find-copies", "--find-copies-harder", base_ref],
    )
    tokens = [token for token in output.split(b"\0") if token]
    changes: list[Change] = []
    index = 0
    while index < len(tokens):
        status_token = _decode_git_path(tokens[index])
        index += 1
        status = status_token[:1]
        if status in {"R", "C"}:
            if index + 1 >= len(tokens):
                raise BRPLEvaluationError("malformed git diff --name-status -z output for rename/copy")
            old_path = _normalize_repo_path(_decode_git_path(tokens[index]), "git diff old path")
            new_path = _normalize_repo_path(_decode_git_path(tokens[index + 1]), "git diff new path")
            index += 2
            changes.append(Change(status=status, old_path=old_path, path=new_path))
        else:
            if index >= len(tokens):
                raise BRPLEvaluationError("malformed git diff --name-status -z output")
            path = _normalize_repo_path(_decode_git_path(tokens[index]), "git diff path")
            index += 1
            changes.append(Change(status=status, path=path))

    untracked = _git_bytes(repo_root, ["ls-files", "-z", "--others", "--exclude-standard"])
    for raw_path in [token for token in untracked.split(b"\0") if token]:
        changes.append(Change(status="A", path=_normalize_repo_path(_decode_git_path(raw_path), "git untracked path")))
    return sorted(changes, key=lambda change: (change.path, change.old_path or "", change.status))


def _collect_final_source_paths(repo_root: Path) -> list[str]:
    tracked = _git_bytes(repo_root, ["ls-files", "-z"])
    paths = {
        _normalize_repo_path(_decode_git_path(token), "git ls-files path")
        for token in tracked.split(b"\0")
        if token
    }
    untracked = _git_bytes(repo_root, ["ls-files", "-z", "--others", "--exclude-standard"])
    paths.update(
        _normalize_repo_path(_decode_git_path(token), "git untracked path")
        for token in untracked.split(b"\0")
        if token
    )
    return sorted(path for path in paths if path.endswith(".py") and (repo_root / path).exists())


def _git_text(repo_root: Path, args: list[str]) -> str:
    return _git_bytes(repo_root, args).decode("utf-8", errors="replace")


def _git_bytes(repo_root: Path, args: list[str]) -> bytes:
    try:
        completed = subprocess.run(
            ["git", "-C", str(repo_root), *args],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    except OSError as exc:
        raise BRPLConfigError(f"git is required for BRPL evaluation: {exc}") from exc
    if completed.returncode != 0:
        stderr = completed.stderr.decode("utf-8", errors="replace").strip()
        raise BRPLConfigError(stderr or f"git {' '.join(args)} failed")
    return completed.stdout


def _decode_git_path(raw: bytes) -> str:
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise BRPLEvaluationError(f"git path is not valid UTF-8: {exc}") from exc


def _validate_repo_path(path: str, source: str) -> None:
    _normalize_repo_path(path, source)


def _validate_repo_pattern(pattern: str, source: str) -> None:
    _require(pattern != "", f"{source} must not be empty")
    _require("\0" not in pattern, f"{source} must not contain NUL")
    _require("\\" not in pattern, f"{source} must use / separators")
    _require(not pattern.startswith("/"), f"{source} must be repository-relative")
    _require(not pattern.endswith("/"), f"{source} must match a whole path, not a trailing slash")
    parts = pattern.split("/")
    for segment in parts:
        _require(segment not in {"", ".", ".."}, f"{source} contains unsafe path segment {segment!r}")
        _require("**" not in segment or segment == "**", f"{source}: ** must be a complete path segment")
        _require("[" not in segment and "]" not in segment, f"{source}: character classes are not supported")


def _normalize_repo_path(path: str, source: str) -> str:
    if path == "":
        raise BRPLEvaluationError(f"{source} must not be empty")
    if "\0" in path:
        raise BRPLEvaluationError(f"{source} must not contain NUL")
    if "\\" in path:
        raise BRPLEvaluationError(f"{source} must use / separators")
    rel = PurePosixPath(path)
    if rel.is_absolute():
        raise BRPLEvaluationError(f"{source} must be repository-relative: {path}")
    if any(part in {"", ".", ".."} for part in rel.parts):
        raise BRPLEvaluationError(f"{source} contains unsafe segment: {path}")
    return rel.as_posix()


def _matches(path: str, pattern: str) -> bool:
    path_parts = path.split("/")
    pattern_parts = pattern.split("/")
    return _match_segments(path_parts, pattern_parts)


def _match_segments(path_parts: list[str], pattern_parts: list[str]) -> bool:
    if not pattern_parts:
        return not path_parts
    head = pattern_parts[0]
    if head == "**":
        return any(_match_segments(path_parts[index:], pattern_parts[1:]) for index in range(len(path_parts) + 1))
    if not path_parts:
        return False
    if not _match_segment(path_parts[0], head):
        return False
    return _match_segments(path_parts[1:], pattern_parts[1:])


def _match_segment(text: str, pattern: str) -> bool:
    regex = ["^"]
    for char in pattern:
        if char == "*":
            regex.append("[^/]*")
        elif char == "?":
            regex.append("[^/]")
        else:
            regex.append(re.escape(char))
    regex.append("$")
    return re.match("".join(regex), text) is not None


def _evaluate_change_scope(policy: dict[str, Any], changed_paths: list[str]) -> list[dict[str, Any]]:
    violations: list[dict[str, Any]] = []
    for rule in policy.get("change_scope", []) or []:
        allow_patterns = rule.get("allow") or []
        deny_patterns = rule.get("deny") or []
        if allow_patterns:
            for path in changed_paths:
                if any(_matches(path, pattern) for pattern in allow_patterns):
                    continue
                violations.append(
                    _violation(
                        policy,
                        rule["id"],
                        "change_scope",
                        path,
                        {
                            "type": "path_scope",
                            "path": path,
                            "allow": allow_patterns,
                            "text": f"{path} is outside allowed change scope {rule['id']}",
                        },
                        "Move the change under an allowed path or update the policy before changing code.",
                    )
                )
        for path in changed_paths:
            matched_denies = [pattern for pattern in deny_patterns if _matches(path, pattern)]
            if matched_denies:
                violations.append(
                    _violation(
                        policy,
                        rule["id"],
                        "change_scope",
                        path,
                        {
                            "type": "path_scope",
                            "path": path,
                            "deny": matched_denies,
                            "text": f"{path} matches denied change scope {rule['id']}",
                        },
                        "Remove the denied change or use an approved task policy.",
                    )
                )
    return violations


def _evaluate_protected_paths(policy: dict[str, Any], changes: list[Change]) -> list[dict[str, Any]]:
    rules = policy.get("protected_paths") or []
    violations: list[dict[str, Any]] = []
    for rule in rules:
        for change in changes:
            for path in change.paths:
                if _matches(path, rule["pattern"]):
                    violations.append(
                        _violation(
                            policy,
                            rule["id"],
                            "protected_paths",
                            path,
                            {
                                "type": "protected_path",
                                "status": change.status,
                                "path": path,
                                "pattern": rule["pattern"],
                                "text": f"{change.status} change touches protected path {path}",
                            },
                            "Restore the protected path and make the change through an allowed interface.",
                        )
                    )
    return violations


def _evaluate_architecture(
    policy: dict[str, Any],
    repo_root: Path,
    final_source_paths: list[str],
    module_index: dict[str, set[str]],
) -> list[dict[str, Any]]:
    rules = (policy.get("architecture") or {}).get("forbid_imports") or []
    violations: list[dict[str, Any]] = []
    for rule in rules:
        from_pattern = rule["from"]
        to_pattern = rule["to"]
        for path in final_source_paths:
            if not _matches(path, from_pattern):
                continue
            full_path = repo_root / path
            if full_path.is_symlink():
                raise BRPLEvaluationError(f"matched Python source is a symlink: {path}")
            try:
                imports = _python_import_targets(full_path, path)
            except (SyntaxError, UnicodeDecodeError) as exc:
                raise BRPLEvaluationError(f"cannot parse Python imports in {path}: {exc}") from exc
            for target in sorted(imports):
                resolved_paths = _resolve_module_paths(target, module_index)
                matched_paths = sorted(candidate for candidate in resolved_paths if _matches(candidate, to_pattern))
                if matched_paths:
                    violations.append(
                        _violation(
                            policy,
                            rule["id"],
                            "architecture.forbid_imports",
                            path,
                            {
                                "type": "python_import",
                                "source": path,
                                "import": target,
                                "resolved_paths": matched_paths,
                                "from": from_pattern,
                                "to": to_pattern,
                                "text": f"{path} imports {target}, forbidden by {from_pattern} -> {to_pattern}",
                            },
                            "Depend on the public boundary or move the dependency behind an adapter.",
                        )
                    )
    return violations


def _build_python_module_index(repo_root: Path, source_paths: list[str]) -> dict[str, set[str]]:
    index: dict[str, set[str]] = {}
    for path in source_paths:
        full_path = repo_root / path
        if full_path.is_symlink():
            continue
        module = _module_name_for_path(path)
        index.setdefault(module, set()).add(path)
        if path.endswith("/__init__.py"):
            index.setdefault(module + ".__init__", set()).add(path)
    return index


def _module_name_for_path(path: str) -> str:
    without_suffix = path[:-3]
    if without_suffix.endswith("/__init__"):
        without_suffix = without_suffix[: -len("/__init__")]
    return without_suffix.replace("/", ".")


def _python_import_targets(path: Path, repo_path: str) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    current_module = _module_name_for_path(repo_path)
    current_package = current_module if repo_path.endswith("/__init__.py") else current_module.rsplit(".", 1)[0]
    targets: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                targets.add(alias.name)
        elif isinstance(node, ast.ImportFrom):
            base = _resolve_import_from_base(current_package, node.level, node.module)
            if base:
                targets.add(base)
            for alias in node.names:
                if alias.name == "*":
                    continue
                targets.add(f"{base}.{alias.name}" if base else alias.name)
    return targets


def _resolve_import_from_base(current_package: str, level: int, module: str | None) -> str:
    if level == 0:
        return module or ""
    parts = current_package.split(".") if current_package else []
    if level > len(parts) + 1:
        return module or ""
    base_parts = parts[: len(parts) - level + 1]
    if module:
        base_parts.extend(module.split("."))
    return ".".join(part for part in base_parts if part)


def _resolve_module_paths(module: str, module_index: dict[str, set[str]]) -> set[str]:
    resolved: set[str] = set()
    parts = module.split(".")
    for end in range(len(parts), 0, -1):
        candidate = ".".join(parts[:end])
        resolved.update(module_index.get(candidate, set()))
    return resolved


def _evaluate_new_dependencies(policy: dict[str, Any], repo_root: Path, base_ref: str) -> list[dict[str, Any]]:
    rule = policy.get("new_dependencies")
    if not rule:
        return []
    manifest = rule["manifest"]
    current = _read_current_dependencies(repo_root, manifest)
    baseline = _read_baseline_dependencies(repo_root, base_ref, manifest)
    added = sorted(current - baseline)
    return [
        _violation(
            policy,
            rule["id"],
            "new_dependencies",
            manifest,
            {
                "type": "dependency",
                "manifest": manifest,
                "dependency": name,
                "text": f"new direct dependency {name} is not allowed",
            },
            "Remove the dependency addition or update the approved policy before adding it.",
        )
        for name in added
    ]


def _read_baseline_dependencies(repo_root: Path, base_ref: str, manifest: str) -> set[str]:
    object_ref = f"{base_ref}:{manifest}"
    object_type = _git_text(repo_root, ["cat-file", "-t", object_ref]).strip()
    if object_type != "blob":
        raise BRPLEvaluationError(f"baseline dependency manifest must be a regular file: {manifest}")
    text = _decode_dependency_manifest(_git_bytes(repo_root, ["show", object_ref]), f"baseline {manifest}")
    return _dependencies_from_toml(text, f"baseline {manifest}")


def _read_current_dependencies(repo_root: Path, manifest: str) -> set[str]:
    path = repo_root / manifest
    if path.is_symlink():
        raise BRPLEvaluationError(f"dependency manifest must be a regular file: {manifest}")
    if not path.exists():
        raise BRPLEvaluationError(f"dependency manifest is missing: {manifest}")
    if not path.is_file():
        raise BRPLEvaluationError(f"dependency manifest must be a regular file: {manifest}")
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise BRPLEvaluationError(f"cannot read dependency manifest {manifest}: {exc}") from exc
    return _dependencies_from_toml(_decode_dependency_manifest(raw, manifest), manifest)


def _decode_dependency_manifest(raw: bytes, source: str) -> str:
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise BRPLEvaluationError(f"{source} must be UTF-8: {exc}") from exc


def _dependencies_from_toml(text: str, source: str) -> set[str]:
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError as exc:
        raise BRPLEvaluationError(f"cannot parse {source}: {exc}") from exc
    project = data.get("project", {})
    if not isinstance(project, dict):
        raise BRPLEvaluationError(f"{source}: [project] must be a table")
    dependencies = project.get("dependencies", [])
    optional_dependencies = project.get("optional-dependencies", {})
    names = _dependency_names_from_list(dependencies, f"{source}: project.dependencies")
    if optional_dependencies is None:
        optional_dependencies = {}
    if not isinstance(optional_dependencies, dict):
        raise BRPLEvaluationError(f"{source}: project.optional-dependencies must be a table")
    for group, group_dependencies in optional_dependencies.items():
        if not isinstance(group, str):
            raise BRPLEvaluationError(f"{source}: optional dependency group names must be strings")
        names.update(_dependency_names_from_list(group_dependencies, f"{source}: project.optional-dependencies.{group}"))
    return names


def _dependency_names_from_list(value: Any, source: str) -> set[str]:
    if value is None:
        return set()
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise BRPLEvaluationError(f"{source} must be a list of strings")
    return {_normalize_dependency_name(item) for item in value}


def _normalize_dependency_name(requirement: str) -> str:
    name = re.split(r"[\[<>=~!;()\s]", requirement.strip(), maxsplit=1)[0]
    if not name:
        raise BRPLEvaluationError(f"dependency requirement has no package name: {requirement!r}")
    return _PEP503_RE.sub("-", name).lower()


def _resolve_check_results(required_check_ids: list[str], config: EvaluationConfig) -> dict[str, dict[str, str]]:
    if config.check_results is not None:
        return config.check_results
    if not required_check_ids:
        return {}
    if not config.execute_checks:
        return {check_id: {"status": "missing", "evidence": "check execution disabled"} for check_id in required_check_ids}
    if config.check_registry_path is None:
        raise BRPLConfigError("required_checks need a trusted check registry")
    registry = _load_check_registry(config.check_registry_path)
    results: dict[str, dict[str, str]] = {}
    for check_id in required_check_ids:
        if check_id not in registry:
            raise BRPLConfigError(f"required check {check_id!r} is not in the trusted registry")
        results[check_id] = _run_check_adapter(config.repo_root, registry[check_id])
    return results


def _load_check_registry(path: Path) -> dict[str, dict[str, Any]]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_reject_duplicate_json_keys)
    except OSError as exc:
        raise BRPLConfigError(f"cannot read trusted check registry {path}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise BRPLConfigError(f"trusted check registry is not valid JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise BRPLConfigError("trusted check registry must be a JSON object")
    _reject_unknown_registry_keys(data, {"version", "checks"}, "trusted check registry")
    if data.get("version") != 1 or not isinstance(data.get("checks"), list):
        raise BRPLConfigError("trusted check registry must contain version=1 and checks list")
    registry: dict[str, dict[str, Any]] = {}
    for index, check in enumerate(data["checks"]):
        if not isinstance(check, dict):
            raise BRPLConfigError(f"trusted check registry entry {index} must be a mapping")
        _reject_unknown_registry_keys(check, {"id", "command", "cwd", "timeout_seconds"}, f"trusted check registry entry {index}")
        check_id = check.get("id")
        command = check.get("command")
        cwd = check.get("cwd", "")
        timeout = check.get("timeout_seconds")
        if not _valid_id(check_id):
            raise BRPLConfigError(f"trusted check registry entry {index} has invalid id")
        if check_id in registry:
            raise BRPLConfigError(f"duplicate trusted check id {check_id!r}")
        if not isinstance(command, list) or not command or not all(isinstance(item, str) and item for item in command):
            raise BRPLConfigError(f"trusted check registry entry {check_id} needs a command argv list")
        if not isinstance(cwd, str):
            raise BRPLConfigError(f"trusted check registry entry {check_id} has unsafe cwd")
        if cwd:
            _validate_repo_path(cwd, f"trusted check registry entry {check_id} cwd")
        if not isinstance(timeout, int) or isinstance(timeout, bool) or timeout <= 0 or timeout > MAX_CHECK_TIMEOUT_SECONDS:
            raise BRPLConfigError(
                f"trusted check registry entry {check_id} needs positive timeout_seconds <= {MAX_CHECK_TIMEOUT_SECONDS}"
            )
        registry[check_id] = {"command": command, "cwd": cwd, "timeout_seconds": timeout}
    return registry


def _reject_duplicate_json_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise BRPLConfigError(f"duplicate JSON key {key!r}")
        result[key] = value
    return result


def _reject_unknown_registry_keys(data: dict[str, Any], allowed: set[str], source: str) -> None:
    unknown = sorted(set(data) - allowed)
    if unknown:
        raise BRPLConfigError(f"{source}: unknown key(s): {', '.join(unknown)}")


def _run_check_adapter(repo_root: Path, check: dict[str, Any]) -> dict[str, str]:
    try:
        completed = subprocess.run(
            check["command"],
            cwd=str(repo_root / check["cwd"]),
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            shell=False,
            timeout=check["timeout_seconds"],
        )
    except subprocess.TimeoutExpired as exc:
        evidence = f"timeout after {check['timeout_seconds']}s"
        if exc.stdout:
            evidence = f"{evidence}: {str(exc.stdout).strip()[:240]}"
        return {"status": "timeout", "evidence": evidence}
    except OSError as exc:
        return {"status": "error", "evidence": str(exc)}
    evidence = (completed.stdout + completed.stderr).strip().splitlines()
    short_evidence = evidence[-1] if evidence else f"exit {completed.returncode}"
    return {
        "status": "pass" if completed.returncode == 0 else "fail",
        "evidence": short_evidence[:300],
    }


def _evaluate_required_checks(policy: dict[str, Any], check_results: dict[str, dict[str, str]]) -> list[dict[str, Any]]:
    violations: list[dict[str, Any]] = []
    for rule in policy.get("required_checks", []):
        check_id = rule["check"]
        result = check_results.get(check_id, {"status": "missing", "evidence": "no result"})
        if result.get("status") != "pass":
            status = result.get("status", "missing")
            evidence_text = result.get("evidence", "")
            violations.append(
                _violation(
                    policy,
                    rule["id"],
                    "required_checks",
                    "",
                    {
                        "type": "required_check",
                        "check": check_id,
                        "status": status,
                        "adapter_evidence": evidence_text,
                        "text": f"required check {check_id} status is {status}: {evidence_text}",
                    },
                    "Run and repair the trusted check before completing the task.",
                )
            )
    return violations


def _violation(
    policy: dict[str, Any],
    rule_id: str,
    family: str,
    file_path: str,
    evidence: dict[str, Any],
    remediation: str,
    severity: str = "error",
) -> dict[str, Any]:
    canonical_evidence = _canonical_json(evidence)
    evidence_hash = _sha256_hex(canonical_evidence.encode("utf-8"))
    prefix = evidence_hash[:16]
    return {
        "violation_id": f"{rule_id}:{prefix}",
        "rule_id": rule_id,
        "policy_id": policy["policy_id"],
        "family": family,
        "severity": severity,
        "file": file_path,
        "evidence": evidence,
        "evidence_sha256": evidence_hash,
        "evidence_hash_prefix": prefix,
        "remediation": remediation,
    }


def _semantic_policy_hash(policy: dict[str, Any]) -> str:
    return _sha256_hex(_canonical_json(_public_policy(policy)).encode("utf-8"))


def _public_policy(policy: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in policy.items() if not str(key).startswith(_PRIVATE_PREFIX)}


def _canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def cli_error_report(message: str) -> str:
    payload = {
        "schema": REPORT_SCHEMA,
        "checker_version": CHECKER_VERSION,
        "brpl_version": 1,
        "ok": False,
        "errors": [{"severity": "error", "evidence": {"type": "error", "text": message}}],
    }
    return json.dumps(payload, indent=2, sort_keys=True) + "\n"
