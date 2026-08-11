"""Closed, host-neutral compiler for the explicitly selected BRPL v4 language.

Policies and adapter catalogs are JSON data.  This module deliberately has no
knowledge of a programming language, package manager, Git, or executable
adapter.  Those concerns belong to trusted producers of normalized evidence.
"""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any, Iterable

POLICY_SCHEMA = "brpl-policy/v4"
CATALOG_SCHEMA = "brpl-adapter-catalog/v4"
PLAN_SCHEMA = "brpl-plan/v4"
_ID = re.compile(r"^[A-Za-z][A-Za-z0-9_.-]{0,127}$")
_RULE_ID = re.compile(r"^[A-Z][A-Z0-9-]{2,63}$")
_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_RULE_KINDS = {"changes", "protect", "generated", "forbid-edge", "forbid-path", "component-adjacency", "acyclic", "dependencies", "require", "threshold"}
_REMEDIATION = {"changes": "remove_or_move_change", "protect": "restore_protected_path", "generated": "update_generator_source", "forbid-edge": "remove_direct_dependency", "forbid-path": "break_dependency_path", "component-adjacency": "change_component_dependency", "acyclic": "break_dependency_cycle", "dependencies": "restore_dependency_set", "require": "make_required_check_pass", "threshold": "reduce_or_raise_metric"}


class BRPLCompileError(ValueError):
    """A stable fail-closed compiler error with a machine-readable code."""
    def __init__(self, code: str, message: str) -> None:
        self.code = code
        super().__init__(f"{code}: {message}")


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _load(value: str | Path | dict[str, Any], label: str) -> dict[str, Any]:
    if isinstance(value, dict):
        data = value
    else:
        try:
            data = json.loads(Path(value).read_text(encoding="utf-8"), object_pairs_hook=_pairs)
        except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
            raise BRPLCompileError("E400", f"cannot load {label}: {exc}") from exc
    if not isinstance(data, dict):
        raise BRPLCompileError("E401", f"{label} must be a JSON object")
    return data


def _pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in items:
        if key in result:
            raise ValueError(f"duplicate JSON key {key!r}")
        result[key] = value
    return result


def _id(value: Any, label: str, rule: bool = False) -> str:
    pattern = _RULE_ID if rule else _ID
    if not isinstance(value, str) or not pattern.fullmatch(value):
        raise BRPLCompileError("E402", f"{label} is invalid")
    return value


def _strings(value: Any, label: str, minimum: int = 0) -> list[str]:
    if not isinstance(value, list) or len(value) < minimum or any(not isinstance(item, str) or not item for item in value):
        raise BRPLCompileError("E403", f"{label} must be a list of {minimum or 'zero or more'} non-empty strings")
    return sorted(set(value))


def _strict_keys(value: dict[str, Any], keys: set[str], label: str, required: set[str]) -> None:
    if set(value) - keys or required - set(value):
        raise BRPLCompileError("E404", f"{label} has unknown or missing fields")


def parse_policy(value: str | Path | dict[str, Any]) -> dict[str, Any]:
    """Load one strict, non-executable v4 repository or task policy."""
    data = _load(value, "policy")
    _strict_keys(data, {"schema", "kind", "id", "repository", "areas", "components", "rules"}, "policy", {"schema", "kind", "id", "rules"})
    if data["schema"] != POLICY_SCHEMA:
        raise BRPLCompileError("E405", f"policy.schema must be {POLICY_SCHEMA}")
    if data["kind"] not in {"repository", "task"}:
        raise BRPLCompileError("E406", "policy.kind must be repository or task")
    _id(data["id"], "policy.id")
    if not isinstance(data["rules"], list):
        raise BRPLCompileError("E407", "policy.rules must be a list")
    if data["kind"] == "repository":
        repository = data.get("repository")
        if not isinstance(repository, dict):
            raise BRPLCompileError("E408", "repository policy requires repository")
        _strict_keys(repository, {"name", "root"}, "repository", {"name", "root"})
        if not all(isinstance(repository[key], str) and repository[key] for key in repository):
            raise BRPLCompileError("E409", "repository values must be non-empty strings")
    elif "repository" in data:
        raise BRPLCompileError("E410", "task policy must not contain repository")
    for group in ("areas", "components"):
        entries = data.get(group, [])
        if not isinstance(entries, list):
            raise BRPLCompileError("E411", f"policy.{group} must be a list")
        seen: set[str] = set()
        for entry in entries:
            if not isinstance(entry, dict):
                raise BRPLCompileError("E412", f"policy.{group} entries must be objects")
            _strict_keys(entry, {"id", "paths"}, group, {"id", "paths"})
            name = _id(entry["id"], f"{group}.id")
            if name in seen:
                raise BRPLCompileError("E413", f"duplicate {group} id {name!r}")
            seen.add(name)
            _strings(entry["paths"], f"{group}.paths", 1)
    ids: set[str] = set()
    for index, rule in enumerate(data["rules"]):
        if not isinstance(rule, dict):
            raise BRPLCompileError("E414", f"rules[{index}] must be an object")
        _validate_rule(rule)
        if rule["id"] in ids:
            raise BRPLCompileError("E415", f"duplicate rule id {rule['id']!r}")
        ids.add(rule["id"])
    return _normal(data)


def _validate_rule(rule: dict[str, Any]) -> None:
    if not isinstance(rule.get("kind"), str) or rule["kind"] not in _RULE_KINDS:
        raise BRPLCompileError("E416", "rule.kind is invalid")
    _id(rule.get("id"), "rule.id", rule=True)
    if "severity" in rule and rule["severity"] not in {"error", "warning"}:
        raise BRPLCompileError("E417", "rule.severity must be error or warning")
    kind = rule["kind"]
    common = {"id", "kind", "severity"}
    required: set[str]
    allowed: set[str]
    if kind == "changes":
        required, allowed = {"mode", "selectors"}, {"mode", "selectors"}
        if rule.get("mode") not in {"only", "deny"}: raise BRPLCompileError("E418", "changes.mode is invalid")
        _strings(rule.get("selectors"), "changes.selectors", 1)
    elif kind in {"protect", "generated"}:
        required, allowed = {"selectors"}, {"selectors"}; _strings(rule.get("selectors"), f"{kind}.selectors", 1)
    elif kind in {"forbid-edge", "forbid-path"}:
        required, allowed = {"relation", "from", "to"}, {"relation", "from", "to"}
        _id(rule.get("relation"), f"{kind}.relation")
        for key in ("from", "to"):
            value = rule.get(key)
            if not isinstance(value, str) or not value or value.startswith("/") or ".." in value.split("/"):
                raise BRPLCompileError("E402", f"{kind}.{key} is invalid")
    elif kind == "component-adjacency":
        required, allowed = {"relation", "allowed"}, {"relation", "allowed"}; _id(rule.get("relation"), "component-adjacency.relation")
        if not isinstance(rule.get("allowed"), list) or any(not isinstance(edge, dict) or set(edge) != {"from", "to"} for edge in rule["allowed"]): raise BRPLCompileError("E419", "component-adjacency.allowed is invalid")
        for edge in rule["allowed"]: _id(edge["from"], "component edge source"); _id(edge["to"], "component edge target")
    elif kind == "acyclic":
        required, allowed = {"relation"}, {"relation", "selectors"}; _id(rule.get("relation"), "acyclic.relation")
        if "selectors" in rule: _strings(rule["selectors"], "acyclic.selectors", 1)
    elif kind == "dependencies":
        required, allowed = {"manifest"}, {"manifest", "allow_add", "allow_remove"}; _id(rule.get("manifest"), "dependencies.manifest")
        for key in ("allow_add", "allow_remove"):
            if key in rule: _strings(rule[key], f"dependencies.{key}")
    elif kind == "require":
        required, allowed = {"check", "summary"}, {"check", "summary"}; _id(rule.get("check"), "require.check")
        if not isinstance(rule.get("summary"), str) or not rule["summary"]: raise BRPLCompileError("E420", "require.summary is invalid")
    else:
        required, allowed = {"metric", "operator", "value", "unit", "summary"}, {"metric", "operator", "value", "unit", "summary"}
        _id(rule.get("metric"), "threshold.metric")
        if rule.get("operator") not in {"at-most", "at-least"}: raise BRPLCompileError("E421", "threshold.operator is invalid")
        if not isinstance(rule.get("value"), (int, str)) or isinstance(rule.get("value"), bool): raise BRPLCompileError("E422", "threshold.value must be an integer or decimal string")
        if not isinstance(rule.get("unit"), str) or not rule["unit"] or not isinstance(rule.get("summary"), str) or not rule["summary"]: raise BRPLCompileError("E423", "threshold unit and summary are required")
    _strict_keys(rule, common | allowed, f"{kind} rule", {"id", "kind"} | required)


def load_catalog(value: str | Path | dict[str, Any]) -> dict[str, Any]:
    """Load the external trusted adapter catalog without importing adapters."""
    data = _load(value, "adapter catalog")
    _strict_keys(data, {"schema", "adapters"}, "adapter catalog", {"schema", "adapters"})
    if data["schema"] != CATALOG_SCHEMA or not isinstance(data["adapters"], list):
        raise BRPLCompileError("E424", f"adapter catalog must be {CATALOG_SCHEMA} with adapters")
    seen: set[str] = set()
    normal: list[dict[str, Any]] = []
    for item in data["adapters"]:
        if not isinstance(item, dict): raise BRPLCompileError("E425", "adapter entries must be objects")
        required = {"id", "kind", "binding", "digest", "public_summary"}
        allowed = required | {"relation", "source_universe", "target_universe", "completeness"}
        _strict_keys(item, allowed, "adapter", required)
        adapter_id = _id(item["id"], "adapter.id")
        if adapter_id in seen: raise BRPLCompileError("E426", f"duplicate adapter {adapter_id!r}")
        seen.add(adapter_id)
        if item["kind"] not in {"changes", "relation", "manifest", "check", "metric"}: raise BRPLCompileError("E427", "adapter.kind is invalid")
        if not isinstance(item["binding"], str) or not item["binding"] or not isinstance(item["digest"], str) or not _DIGEST.fullmatch(item["digest"]): raise BRPLCompileError("E428", "adapter binding or digest is invalid")
        if not isinstance(item["public_summary"], str) or not item["public_summary"]: raise BRPLCompileError("E429", "adapter public_summary is invalid")
        if item["kind"] == "relation":
            for key in ("relation", "source_universe", "target_universe", "completeness"):
                if not isinstance(item.get(key), str) or not item[key]: raise BRPLCompileError("E430", f"relation adapter requires {key}")
            if item["completeness"] not in {"complete", "partial"}: raise BRPLCompileError("E431", "relation completeness is invalid")
        elif set(item) - required:
            raise BRPLCompileError("E432", "only relation adapters may declare graph metadata")
        normal.append(_normal(item))
    return {"schema": CATALOG_SCHEMA, "adapters": sorted(normal, key=lambda item: item["id"])}


def compile_policies(policies: Iterable[dict[str, Any] | str | Path], catalog: dict[str, Any] | str | Path) -> dict[str, Any]:
    """Compile conjunctive policies into one canonical, host-neutral plan."""
    items = [parse_policy(policy) for policy in policies]
    if len([p for p in items if p["kind"] == "repository"]) != 1: raise BRPLCompileError("E433", "exactly one repository policy is required")
    ids = [p["id"] for p in items]
    if len(ids) != len(set(ids)): raise BRPLCompileError("E434", "policy ids must be unique")
    catalog_data = load_catalog(catalog)
    adapters = {item["id"]: item for item in catalog_data["adapters"]}
    ordered = sorted(items, key=lambda item: (0 if item["kind"] == "repository" else 1, item["id"]))
    areas: dict[str, list[str]] = {}; components: dict[str, list[str]] = {}; rules: list[dict[str, Any]] = []; used: dict[str, dict[str, Any]] = {}; rule_ids: set[str] = set()
    for policy in ordered:
        for group, target in (("areas", areas), ("components", components)):
            for entry in policy.get(group, []):
                if entry["id"] in target: raise BRPLCompileError("E435", f"{group} id {entry['id']!r} is redefined")
                target[entry["id"]] = entry["paths"]
        for rule in policy["rules"]:
            if rule["id"] in rule_ids: raise BRPLCompileError("E436", f"rule id {rule['id']!r} is duplicated")
            rule_ids.add(rule["id"])
            rules.append(_lower(rule, policy, areas, components, adapters, used))
    repository = next(p["repository"] for p in ordered if p["kind"] == "repository")
    plan: dict[str, Any] = {"schema": PLAN_SCHEMA, "brpl_version": 4, "policies": [{"id": p["id"], "kind": p["kind"]} for p in ordered], "repository": repository, "areas": [{"id": key, "paths": areas[key]} for key in sorted(areas)], "components": [{"id": key, "paths": components[key]} for key in sorted(components)], "rules": sorted(rules, key=lambda item: item["id"]), "capabilities": [used[key] for key in sorted(used)]}
    plan["semantic_sha256"] = hashlib.sha256(canonical_json(plan).encode()).hexdigest()
    return plan


def _lower(rule: dict[str, Any], policy: dict[str, Any], areas: dict[str, list[str]], components: dict[str, list[str]], adapters: dict[str, dict[str, Any]], used: dict[str, dict[str, Any]]) -> dict[str, Any]:
    kind = rule["kind"]
    result: dict[str, Any] = {"id": rule["id"], "policy_id": policy["id"], "policy_kind": policy["kind"], "kind": kind, "severity": rule.get("severity", "error"), "policy_class": _class(kind), "remediation": _REMEDIATION[kind]}
    if kind in {"changes", "protect", "generated"}:
        result["paths"] = _selectors(rule["selectors"], areas, f"{kind}.selectors")
        if kind == "changes": result["mode"] = rule["mode"]
        _use(adapters, used, "changes", "changes")
    elif kind in {"forbid-edge", "forbid-path"}:
        result.update({"relation": rule["relation"], "source_paths": _selectors([rule["from"]], areas, f"{kind}.from"), "target_paths": _selectors([rule["to"]], areas, f"{kind}.to")})
        _use(adapters, used, rule["relation"], "relation")
    elif kind == "component-adjacency":
        if not components: raise BRPLCompileError("E437", "component-adjacency requires components")
        for edge in rule["allowed"]:
            if edge["from"] not in components or edge["to"] not in components: raise BRPLCompileError("E438", "component-adjacency references unknown component")
        result.update({"relation": rule["relation"], "components": [{"id": key, "paths": components[key]} for key in sorted(components)], "allowed": sorted(rule["allowed"], key=canonical_json)})
        _use(adapters, used, rule["relation"], "relation")
    elif kind == "acyclic":
        result["relation"] = rule["relation"]
        if "selectors" in rule: result["paths"] = _selectors(rule["selectors"], areas, "acyclic.selectors")
        _use(adapters, used, rule["relation"], "relation")
    elif kind == "dependencies":
        result.update({"manifest": rule["manifest"], "allow_add": rule.get("allow_add", []), "allow_remove": rule.get("allow_remove", [])}); _use(adapters, used, rule["manifest"], "manifest")
    elif kind == "require":
        result.update({"check": rule["check"], "summary": rule["summary"]}); _use(adapters, used, rule["check"], "check")
    else:
        result.update({"metric": rule["metric"], "operator": rule["operator"], "value": str(rule["value"]), "unit": rule["unit"], "summary": rule["summary"]}); _use(adapters, used, rule["metric"], "metric")
    return result


def _use(adapters: dict[str, dict[str, Any]], used: dict[str, dict[str, Any]], identifier: str, kind: str) -> None:
    item = adapters.get(identifier)
    if item is None or item["kind"] != kind: raise BRPLCompileError("E439", f"trusted {kind} capability {identifier!r} is unavailable")
    used[identifier] = item


def _selectors(values: list[str], areas: dict[str, list[str]], label: str) -> list[str]:
    result: list[str] = []
    for value in values:
        if value.startswith("@"):
            name = value[1:]
            if name not in areas: raise BRPLCompileError("E440", f"{label} references unknown area {name!r}")
            result.extend(areas[name])
        elif value.startswith("/") or ".." in value.split("/") or not value: raise BRPLCompileError("E441", f"{label} contains an invalid repository selector")
        else: result.append(value)
    return sorted(set(result))


def _class(kind: str) -> str:
    return {"changes": "change_scope", "protect": "protected_paths", "generated": "generated_paths", "forbid-edge": "architecture.direct_edge", "forbid-path": "architecture.transitive_path", "component-adjacency": "architecture.component_adjacency", "acyclic": "architecture.acyclic", "dependencies": "dependencies", "require": "required_check", "threshold": "quantitative_threshold"}[kind]


def _normal(value: Any) -> Any:
    return json.loads(canonical_json(value))


def validate_plan(value: dict[str, Any]) -> dict[str, Any]:
    """Check the canonical plan integrity before a verifier accepts it."""
    if not isinstance(value, dict) or value.get("schema") != PLAN_SCHEMA or value.get("brpl_version") != 4 or not isinstance(value.get("semantic_sha256"), str): raise BRPLCompileError("E442", "plan schema is invalid")
    unsigned = dict(value); digest = unsigned.pop("semantic_sha256")
    expected = hashlib.sha256(canonical_json(unsigned).encode()).hexdigest()
    if digest != expected: raise BRPLCompileError("E443", "plan semantic hash does not match contents")
    # Recompile the normalized policy-shaped data is intentionally not possible:
    # plans are the closed verifier interface.  Check the minimal structural shape.
    for key in ("policies", "repository", "areas", "components", "rules", "capabilities"):
        if key not in value: raise BRPLCompileError("E444", f"plan lacks {key}")
    if not isinstance(value["rules"], list) or not isinstance(value["capabilities"], list): raise BRPLCompileError("E445", "plan rules/capabilities are invalid")
    return _normal(value)
