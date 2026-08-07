"""Dependency-free reference compiler for the prospective BRPL v3 language."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Iterable


PLAN_SCHEMA = "brpl-plan/v3"
CAPABILITY_SCHEMA = "brpl-capabilities/v2"
# These limits bound parser work before tokenization.  They are deliberately
# conservative: v3 contracts describe repository policy, not generated data.
MAX_CONTRACT_BYTES = 64 * 1024
MAX_CONTRACT_LINES = 1_000
MAX_CONTRACT_STATEMENTS = 500
MAX_LINE_CHARACTERS = 4_096
MAX_TOKENS_PER_STATEMENT = 128
MAX_STRING_CHARACTERS = 2_048
_NAME_RE = re.compile(r"^[a-z][a-z0-9-]*$")
_RULE_RE = re.compile(r"^[A-Z][A-Z0-9-]{2,63}$")
_ABOUT_KEYS = {
    "purpose", "architecture", "entrypoint", "owner", "release",
    "data-classification", "compatibility", "documentation",
}
_TECHNOLOGY_KINDS = {
    "language", "runtime", "framework", "dependency", "package-manager",
    "formatter", "linter", "type-checker", "test-framework", "build-system",
    "database", "message-broker", "deployment", "code-generator",
    "security-tool", "observability",
}
_REMEDIATION = {
    "changes": "remove_or_move_change",
    "protect": "restore_protected_path",
    "generated": "update_generator_source",
    "forbid-edge": "change_dependency",
    "dependencies": "restore_dependency_set",
    "require": "make_required_check_pass",
}


class BRPLCompileError(ValueError):
    """A stable, source-located compiler diagnostic."""

    def __init__(self, code: str, message: str, source: str = "<source>", line: int = 0):
        self.code = code
        self.source = source
        self.line = line
        location = f"{source}:{line}" if line else source
        super().__init__(f"{location}: {code}: {message}")


@dataclass(frozen=True)
class Token:
    value: str
    quoted: bool = False


@dataclass(frozen=True)
class Statement:
    kind: str
    data: dict[str, Any]
    source: str
    line: int


@dataclass(frozen=True)
class Contract:
    policy_kind: str
    policy_id: str
    statements: tuple[Statement, ...]
    source: str


def parse_contract(text: str, source: str = "<source>") -> Contract:
    """Parse and locally validate one BRPL v3 contract."""
    encoded_size = len(text.encode("utf-8"))
    if encoded_size > MAX_CONTRACT_BYTES:
        raise BRPLCompileError("E005", f"contract exceeds {MAX_CONTRACT_BYTES} UTF-8 bytes", source)
    physical_lines = text.count("\n") + (1 if text else 0)
    if physical_lines > MAX_CONTRACT_LINES:
        raise BRPLCompileError("E006", f"contract exceeds {MAX_CONTRACT_LINES} physical lines", source)
    logical: list[tuple[int, list[Token]]] = []
    for number, line in enumerate(text.splitlines(), 1):
        if len(line) > MAX_LINE_CHARACTERS:
            raise BRPLCompileError("E008", f"line exceeds {MAX_LINE_CHARACTERS} characters", source, number)
        tokens = _tokenize(line, source, number)
        if tokens:
            logical.append((number, tokens))
            if len(logical) > MAX_CONTRACT_STATEMENTS + 1:
                raise BRPLCompileError("E007", f"contract exceeds {MAX_CONTRACT_STATEMENTS} statements", source, number)
    if not logical:
        raise BRPLCompileError("E001", "contract is empty", source)
    header_line, header = logical[0]
    if len(header) != 4:
        raise BRPLCompileError("E002", 'header must be: brpl 3 repository|task "id"', source, header_line)
    if header[0].value != "brpl" or header[1].value != "3":
        raise BRPLCompileError("E002", 'header must be: brpl 3 repository|task "id"', source, header_line)
    policy_kind = header[2].value
    if policy_kind not in {"repository", "task"} or not header[3].quoted:
        raise BRPLCompileError("E002", 'header must be: brpl 3 repository|task "id"', source, header_line)
    policy_id = _name(header[3].value, source, header_line, "policy id")
    statements = tuple(_parse_statement(tokens, source, line) for line, tokens in logical[1:])
    repo_count = sum(statement.kind == "repo" for statement in statements)
    if policy_kind == "repository" and repo_count != 1:
        raise BRPLCompileError("E003", "repository contract must contain exactly one repo statement", source)
    if policy_kind == "task" and repo_count:
        raise BRPLCompileError("E004", "task contract must not contain a repo statement", source)
    return Contract(policy_kind, policy_id, statements, source)


def load_capabilities(value: str | Path | dict[str, Any]) -> dict[str, Any]:
    """Load and strictly validate the compiler's trusted symbol table."""
    if isinstance(value, dict):
        data = value
    else:
        path = Path(value)
        try:
            data = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_unique_pairs)
        except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
            raise BRPLCompileError("E200", f"cannot load capabilities: {exc}", str(path)) from exc
    if not isinstance(data, dict) or set(data) != {"schema", "changes", "relations", "manifests", "checks"}:
        raise BRPLCompileError("E201", "capabilities must contain only schema, changes, relations, manifests, and checks", "<capabilities>")
    if data["schema"] != CAPABILITY_SCHEMA:
        raise BRPLCompileError("E202", f"capability schema must be {CAPABILITY_SCHEMA}", "<capabilities>")
    if not isinstance(data["changes"], dict) or set(data["changes"]) != {"adapter", "sha256"}:
        raise BRPLCompileError("E203", "changes must contain only adapter and sha256", "<capabilities>")
    changes = _binding(data["changes"], "changes")
    relations = _capability_entries(data["relations"], "relations")
    manifests = _capability_entries(data["manifests"], "manifests")
    if not isinstance(data["checks"], list):
        raise BRPLCompileError("E203", "checks must be a list", "<capabilities>")
    checks: dict[str, dict[str, str]] = {}
    for index, item in enumerate(data["checks"]):
        if not isinstance(item, dict) or set(item) != {"id", "summary", "adapter", "sha256"}:
            raise BRPLCompileError("E204", f"checks[{index}] must contain only id, summary, adapter, and sha256", "<capabilities>")
        check_id = item["id"]
        summary = item["summary"]
        if not isinstance(check_id, str) or not _NAME_RE.fullmatch(check_id):
            raise BRPLCompileError("E205", f"checks[{index}].id is invalid", "<capabilities>")
        if not isinstance(summary, str) or not summary:
            raise BRPLCompileError("E206", f"checks[{index}].summary must be a non-empty string", "<capabilities>")
        if check_id in checks:
            raise BRPLCompileError("E207", f"duplicate check {check_id!r}", "<capabilities>")
        checks[check_id] = _binding(item, f"checks[{index}]") | {"summary": summary}
    return {
        "schema": CAPABILITY_SCHEMA,
        "changes": changes,
        "relations": [relations[key] for key in sorted(relations)],
        "manifests": [manifests[key] for key in sorted(manifests)],
        "checks": [{"id": key, **checks[key]} for key in sorted(checks)],
    }


def compile_contracts(contracts: Iterable[Contract], capabilities: dict[str, Any]) -> dict[str, Any]:
    """Compose contracts and lower them to a canonical verifier plan."""
    items = list(contracts)
    if not items:
        raise BRPLCompileError("E300", "at least one contract is required")
    capabilities = load_capabilities(capabilities)
    repositories = [item for item in items if item.policy_kind == "repository"]
    if len(repositories) != 1:
        raise BRPLCompileError("E301", "exactly one repository contract is required")
    policy_ids = [item.policy_id for item in items]
    if len(policy_ids) != len(set(policy_ids)):
        raise BRPLCompileError("E302", "policy identifiers must be unique")

    ordered = repositories + sorted((item for item in items if item.policy_kind == "task"), key=lambda item: item.policy_id)
    areas: dict[str, list[str]] = {}
    context: list[dict[str, Any]] = []
    raw_rules: list[tuple[Contract, Statement]] = []
    repository: dict[str, str] | None = None
    rule_ids: set[str] = set()

    for contract in ordered:
        for statement in contract.statements:
            data = statement.data
            if statement.kind == "repo":
                repository = {"name": data["name"], "root": data["root"]}
            elif statement.kind in {"about", "uses"}:
                entry = {"kind": statement.kind, **data}
                if entry in context:
                    _fail("E303", "duplicate context statement", statement)
                context.append(entry)
            elif statement.kind == "area":
                name = data["name"]
                if name in areas:
                    _fail("E304", f"area {name!r} is redefined", statement)
                areas[name] = sorted(set(data["paths"]))
            else:
                rule_id = data["id"]
                if rule_id in rule_ids:
                    _fail("E305", f"rule id {rule_id!r} is duplicated", statement)
                rule_ids.add(rule_id)
                raw_rules.append((contract, statement))
    if repository is None:
        raise BRPLCompileError("E306", "repository identity is missing")

    relations = {item["id"]: item for item in capabilities["relations"]}
    manifests = {item["id"]: item for item in capabilities["manifests"]}
    checks = {item["id"]: item for item in capabilities["checks"]}
    used: dict[tuple[str, str], dict[str, str]] = {}
    rules: list[dict[str, Any]] = []
    for contract, statement in raw_rules:
        data = statement.data
        common = {
            "id": data["id"],
            "policy_id": contract.policy_id,
            "policy_kind": contract.policy_kind,
            "severity": "error",
            "remediation": _REMEDIATION[statement.kind],
        }
        if statement.kind == "changes":
            paths = _expand_selectors(data["selectors"], areas, statement)
            operation = "changed_paths_within" if data["mode"] == "only" else "changed_paths_exclude"
            rules.append({**common, "class": "change", "operation": operation, "paths": paths})
            used[("evidence", "changes")] = {"kind": "evidence", "id": "changes", **capabilities["changes"]}
        elif statement.kind in {"protect", "generated"}:
            paths = _expand_selectors(data["selectors"], areas, statement)
            operation = "protected_paths_unchanged" if statement.kind == "protect" else "generated_paths_unchanged"
            rules.append({**common, "class": statement.kind, "operation": operation, "paths": paths})
            used[("evidence", "changes")] = {"kind": "evidence", "id": "changes", **capabilities["changes"]}
        elif statement.kind == "forbid-edge":
            relation = data["relation"]
            if relation not in relations:
                _fail("E307", f"relation capability {relation!r} is unavailable", statement)
            source_paths = _area(data["from"], areas, statement)
            target_paths = _area(data["to"], areas, statement)
            rules.append({**common, "class": "architecture", "operation": "edge_absent", "relation": relation, "source_paths": source_paths, "target_paths": target_paths})
            used[("relation", relation)] = {"kind": "relation", **relations[relation]}
        elif statement.kind == "dependencies":
            manifest = data["manifest"]
            if manifest not in manifests:
                _fail("E308", f"manifest capability {manifest!r} is unavailable", statement)
            rules.append({**common, "class": "dependencies", "operation": "direct_dependency_delta", "manifest": manifest, "allow_add": sorted(set(data["allow_add"])), "allow_remove": sorted(set(data["allow_remove"]))})
            used[("manifest", manifest)] = {"kind": "manifest", **manifests[manifest]}
        elif statement.kind == "require":
            check = data["check"]
            if check not in checks:
                _fail("E309", f"check capability {check!r} is unavailable", statement)
            if data["means"] != checks[check]["summary"]:
                _fail("E310", f"check summary does not match trusted summary for {check!r}", statement)
            rules.append({**common, "class": "required-check", "operation": "check_pass", "check": check, "summary": data["means"]})
            used[("check", check)] = {"kind": "check", **checks[check]}

    plan: dict[str, Any] = {
        "schema": PLAN_SCHEMA,
        "brpl_version": 3,
        "policies": [{"id": item.policy_id, "kind": item.policy_kind} for item in ordered],
        "repository": repository,
        "context": sorted(context, key=canonical_json),
        "areas": [{"name": key, "paths": areas[key]} for key in sorted(areas)],
        "rules": sorted(rules, key=lambda item: item["id"]),
        "capabilities": [used[key] for key in sorted(used)],
    }
    plan["semantic_sha256"] = hashlib.sha256(canonical_json(plan).encode("utf-8")).hexdigest()
    validate_plan(plan)
    return plan


def validate_plan(value: Any) -> dict[str, Any]:
    """Fail closed on malformed or tampered compiler output before verification."""
    if not isinstance(value, dict):
        raise BRPLCompileError("E400", "plan must be an object", "<plan>")
    required = {"schema", "brpl_version", "policies", "repository", "context", "areas", "rules", "capabilities", "semantic_sha256"}
    if set(value) != required or value.get("schema") != PLAN_SCHEMA or value.get("brpl_version") != 3:
        raise BRPLCompileError("E401", "plan has an invalid schema or fields", "<plan>")
    digest = value.get("semantic_sha256")
    if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
        raise BRPLCompileError("E402", "plan semantic_sha256 is invalid", "<plan>")
    unsigned = {key: item for key, item in value.items() if key != "semantic_sha256"}
    expected = hashlib.sha256(canonical_json(unsigned).encode("utf-8")).hexdigest()
    if digest != expected:
        raise BRPLCompileError("E403", "plan semantic_sha256 does not match its contents", "<plan>")
    if not all(isinstance(item, dict) and set(item) >= {"kind", "id", "adapter", "sha256"} and isinstance(item["adapter"], str) and _NAME_RE.fullmatch(item["adapter"]) and isinstance(item["sha256"], str) and re.fullmatch(r"[0-9a-f]{64}", item["sha256"]) for item in value["capabilities"]):
        raise BRPLCompileError("E404", "plan capabilities must contain pinned adapter bindings", "<plan>")
    if not all(isinstance(item, dict) and item.get("operation") in {"changed_paths_within", "changed_paths_exclude", "protected_paths_unchanged", "generated_paths_unchanged", "edge_absent", "direct_dependency_delta", "check_pass"} for item in value["rules"]):
        raise BRPLCompileError("E405", "plan contains an invalid rule operation", "<plan>")
    return value


def canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Compile BRPL v3 contracts into a canonical verifier plan.")
    parser.add_argument("contracts", nargs="+")
    parser.add_argument("--capabilities", required=True)
    parser.add_argument("--pretty", action="store_true")
    args = parser.parse_args(argv)
    try:
        contracts = [parse_contract(Path(path).read_text(encoding="utf-8"), path) for path in args.contracts]
        plan = compile_contracts(contracts, load_capabilities(args.capabilities))
    except (OSError, UnicodeDecodeError, BRPLCompileError) as exc:
        sys.stderr.write(f"BRPL v3 compile error: {exc}\n")
        return 2
    if args.pretty:
        sys.stdout.write(json.dumps(plan, ensure_ascii=False, sort_keys=True, indent=2) + "\n")
    else:
        sys.stdout.write(canonical_json(plan) + "\n")
    return 0


def _parse_statement(tokens: list[Token], source: str, line: int) -> Statement:
    keyword = tokens[0].value
    values = [token.value for token in tokens]
    if keyword == "repo":
        _shape(tokens, 4, source, line, 'repo "name" root "."')
        _literal(values[2] == "root" and tokens[1].quoted and tokens[3].quoted, "E010", "invalid repo statement", source, line)
        _literal(values[3] == ".", "E011", 'v3 repository root must be "."', source, line)
        _text(values[1], source, line, "repository name")
        return Statement(keyword, {"name": values[1], "root": values[3]}, source, line)
    if keyword == "about":
        _shape(tokens, 3, source, line, 'about key "value"')
        _literal(values[1] in _ABOUT_KEYS and tokens[2].quoted, "E012", "invalid about statement", source, line)
        _text(values[2], source, line, "about value")
        return Statement(keyword, {"key": values[1], "value": values[2]}, source, line)
    if keyword == "uses":
        _literal(len(tokens) >= 3 and values[1] in _TECHNOLOGY_KINDS and tokens[2].quoted, "E013", "invalid uses statement", source, line)
        _text(values[2], source, line, "technology name")
        data: dict[str, Any] = {"technology": values[1], "name": values[2]}
        index = 3
        prior = -1
        order = {"major": 0, "from": 1, "role": 2}
        while index < len(tokens):
            clause = values[index]
            _literal(clause in order and index + 1 < len(tokens) and tokens[index + 1].quoted, "E014", "invalid uses clause", source, line)
            _literal(order[clause] > prior and clause not in data, "E015", "uses clauses must be unique and ordered major, from, role", source, line)
            _text(values[index + 1], source, line, f"uses {clause} value")
            data[clause] = values[index + 1]
            prior = order[clause]
            index += 2
        if "from" in data:
            _path(data["from"], source, line)
        return Statement(keyword, data, source, line)
    if keyword == "area":
        _literal(len(tokens) >= 4 and values[2] == "paths", "E016", "invalid area statement", source, line)
        name = _name(values[1], source, line, "area name")
        paths = [_selector(token, source, line, allow_reference=False) for token in tokens[3:]]
        return Statement(keyword, {"name": name, "paths": paths}, source, line)
    if keyword == "changes":
        _literal(len(tokens) >= 4 and values[2] in {"only", "deny"}, "E017", "invalid changes statement", source, line)
        return Statement(keyword, {"id": _rule(values[1], source, line), "mode": values[2], "selectors": [_selector(token, source, line) for token in tokens[3:]]}, source, line)
    if keyword in {"protect", "generated"}:
        _literal(len(tokens) >= 4 and values[2] == "paths", "E018", f"invalid {keyword} statement", source, line)
        return Statement(keyword, {"id": _rule(values[1], source, line), "selectors": [_selector(token, source, line) for token in tokens[3:]]}, source, line)
    if keyword == "forbid-edge":
        _shape(tokens, 8, source, line, 'forbid-edge ID relation "name" from @area to @area')
        _literal(values[2] == "relation" and tokens[3].quoted and values[4] == "from" and values[6] == "to", "E019", "invalid forbid-edge statement", source, line)
        _text(values[3], source, line, "relation capability")
        return Statement(keyword, {"id": _rule(values[1], source, line), "relation": values[3], "from": _area_ref(tokens[5], source, line), "to": _area_ref(tokens[7], source, line)}, source, line)
    if keyword == "dependencies":
        _literal(len(tokens) >= 8 and values[2] == "manifest" and tokens[3].quoted and values[4] == "allow-add", "E020", "invalid dependencies statement", source, line)
        try:
            split = values.index("allow-remove", 5)
        except ValueError as exc:
            raise BRPLCompileError("E020", "dependencies statement needs allow-remove", source, line) from exc
        allow_add = _string_list(tokens[5:split], source, line)
        allow_remove = _string_list(tokens[split + 1 :], source, line)
        _path(values[3], source, line)
        return Statement(keyword, {"id": _rule(values[1], source, line), "manifest": values[3], "allow_add": allow_add, "allow_remove": allow_remove}, source, line)
    if keyword == "require":
        _shape(tokens, 6, source, line, 'require ID check "id" means "summary"')
        _literal(values[2] == "check" and tokens[3].quoted and values[4] == "means" and tokens[5].quoted, "E021", "invalid require statement", source, line)
        _text(values[3], source, line, "check capability")
        _text(values[5], source, line, "check summary")
        return Statement(keyword, {"id": _rule(values[1], source, line), "check": values[3], "means": values[5]}, source, line)
    raise BRPLCompileError("E022", f"unknown statement {keyword!r}", source, line)


def _tokenize(line: str, source: str, number: int) -> list[Token]:
    if "\t" in line:
        raise BRPLCompileError("E100", "tabs are not permitted", source, number)
    result: list[Token] = []
    index = 0
    decoder = json.JSONDecoder()
    while index < len(line):
        while index < len(line) and line[index].isspace():
            index += 1
        if index == len(line) or line[index] == "#":
            break
        if line[index] == '"':
            try:
                value, end = decoder.raw_decode(line, index)
            except json.JSONDecodeError as exc:
                raise BRPLCompileError("E101", f"invalid JSON string: {exc.msg}", source, number) from exc
            if not isinstance(value, str):
                raise BRPLCompileError("E101", "quoted value must be a JSON string", source, number)
            if len(value) > MAX_STRING_CHARACTERS:
                raise BRPLCompileError("E112", f"string exceeds {MAX_STRING_CHARACTERS} characters", source, number)
            result.append(Token(value, True))
            if len(result) > MAX_TOKENS_PER_STATEMENT:
                raise BRPLCompileError("E009", f"statement exceeds {MAX_TOKENS_PER_STATEMENT} tokens", source, number)
            index = end
            if index < len(line) and not line[index].isspace() and line[index] != "#":
                raise BRPLCompileError("E102", "tokens must be separated by whitespace", source, number)
        else:
            end = index
            while end < len(line) and not line[end].isspace() and line[end] != "#":
                end += 1
            result.append(Token(line[index:end]))
            if len(result) > MAX_TOKENS_PER_STATEMENT:
                raise BRPLCompileError("E009", f"statement exceeds {MAX_TOKENS_PER_STATEMENT} tokens", source, number)
            index = end
    return result


def _selector(token: Token, source: str, line: int, allow_reference: bool = True) -> str:
    if token.quoted:
        return _path(token.value, source, line)
    if allow_reference and token.value.startswith("@"):
        return "@" + _name(token.value[1:], source, line, "area reference")
    raise BRPLCompileError("E103", "selector must be a quoted path or @area reference", source, line)


def _path(value: str, source: str, line: int) -> str:
    pure = PurePosixPath(value)
    invalid = (
        not value or value == "." or "\\" in value or "\0" in value or pure.is_absolute()
        or value != pure.as_posix() or any(part in {"", ".", ".."} for part in pure.parts)
        or any(char in value for char in "[]{}!")
        or any("**" in part and part != "**" for part in value.split("/"))
    )
    if invalid:
        raise BRPLCompileError("E104", f"unsafe or unsupported repository path {value!r}", source, line)
    return value


def _name(value: str, source: str, line: int, label: str) -> str:
    if not _NAME_RE.fullmatch(value):
        raise BRPLCompileError("E105", f"{label} must match {_NAME_RE.pattern}", source, line)
    return value


def _rule(value: str, source: str, line: int) -> str:
    if not _RULE_RE.fullmatch(value):
        raise BRPLCompileError("E106", f"rule id must match {_RULE_RE.pattern}", source, line)
    return value


def _text(value: str, source: str, line: int, label: str) -> str:
    if not value:
        raise BRPLCompileError("E111", f"{label} must be non-empty", source, line)
    return value


def _area_ref(token: Token, source: str, line: int) -> str:
    if token.quoted or not token.value.startswith("@"):
        raise BRPLCompileError("E107", "expected @area reference", source, line)
    return _name(token.value[1:], source, line, "area reference")


def _string_list(tokens: list[Token], source: str, line: int) -> list[str]:
    if len(tokens) == 1 and not tokens[0].quoted and tokens[0].value == "none":
        return []
    if not tokens or any(not token.quoted for token in tokens):
        raise BRPLCompileError("E108", "dependency list must be none or one or more quoted names", source, line)
    values = [token.value for token in tokens]
    if any(not value for value in values) or len(values) != len(set(values)):
        raise BRPLCompileError("E109", "dependency names must be non-empty and unique", source, line)
    return values


def _expand_selectors(selectors: list[str], areas: dict[str, list[str]], statement: Statement) -> list[str]:
    paths: set[str] = set()
    for selector in selectors:
        if selector.startswith("@"):
            paths.update(_area(selector[1:], areas, statement))
        else:
            paths.add(selector)
    if not paths:
        _fail("E311", "selector set is empty", statement)
    return sorted(paths)


def _area(name: str, areas: dict[str, list[str]], statement: Statement) -> list[str]:
    if name not in areas:
        _fail("E312", f"area {name!r} is unresolved", statement)
    return areas[name]


def _shape(tokens: list[Token], length: int, source: str, line: int, shape: str) -> None:
    if len(tokens) != length:
        raise BRPLCompileError("E110", f"expected {shape}", source, line)


def _literal(condition: bool, code: str, message: str, source: str, line: int) -> None:
    if not condition:
        raise BRPLCompileError(code, message, source, line)


def _fail(code: str, message: str, statement: Statement) -> None:
    raise BRPLCompileError(code, message, statement.source, statement.line)


def _unique_strings(value: Any, label: str) -> list[str]:
    if not isinstance(value, list) or not all(isinstance(item, str) and item for item in value):
        raise BRPLCompileError("E208", f"{label} must be a list of non-empty strings", "<capabilities>")
    if len(value) != len(set(value)):
        raise BRPLCompileError("E209", f"{label} contains duplicates", "<capabilities>")
    return value


def _binding(item: dict[str, Any], where: str) -> dict[str, str]:
    adapter, digest = item.get("adapter"), item.get("sha256")
    if not isinstance(adapter, str) or not _NAME_RE.fullmatch(adapter):
        raise BRPLCompileError("E210", f"{where}.adapter is invalid", "<capabilities>")
    if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
        raise BRPLCompileError("E211", f"{where}.sha256 must be a lowercase SHA-256 digest", "<capabilities>")
    return {"adapter": adapter, "sha256": digest}


def _capability_entries(value: Any, label: str) -> dict[str, dict[str, str]]:
    if not isinstance(value, list):
        raise BRPLCompileError("E208", f"{label} must be a list", "<capabilities>")
    result: dict[str, dict[str, str]] = {}
    for index, item in enumerate(value):
        if not isinstance(item, dict) or set(item) != {"id", "adapter", "sha256"}:
            raise BRPLCompileError("E208", f"{label}[{index}] must contain only id, adapter, and sha256", "<capabilities>")
        identifier = item.get("id")
        if not isinstance(identifier, str) or not identifier:
            raise BRPLCompileError("E208", f"{label}[{index}].id must be a non-empty string", "<capabilities>")
        if identifier in result:
            raise BRPLCompileError("E209", f"{label} contains duplicates", "<capabilities>")
        result[identifier] = {"id": identifier, **_binding(item, f"{label}[{index}]")}
    return result


def _unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key {key!r}")
        result[key] = value
    return result


if __name__ == "__main__":
    raise SystemExit(main())
