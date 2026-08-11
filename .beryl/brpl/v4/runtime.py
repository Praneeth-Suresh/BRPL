"""Deterministic, host-neutral BRPL v4 verifier over normalized evidence."""
from __future__ import annotations

import hashlib
import json
import re
from decimal import Decimal, InvalidOperation
from typing import Any

from .compiler import BRPLCompileError, canonical_json, validate_plan

EVIDENCE_SCHEMA = "brpl-evidence/v4"
REPORT_SCHEMA = "brpl-report/v4"
_DIGEST = re.compile(r"^[0-9a-f]{64}$")


class BRPLVerificationError(ValueError):
    """Stable fail-closed verification error."""
    def __init__(self, code: str, message: str) -> None:
        self.code = code
        super().__init__(f"{code}: {message}")


def validate_evidence(value: Any) -> dict[str, Any]:
    """Validate evidence as data; no adapters or commands are executed here."""
    if not isinstance(value, dict) or set(value) != {"schema", "candidate_tree", "changes", "graphs", "manifest_deltas", "checks", "metrics"}:
        raise BRPLVerificationError("V400", "evidence has invalid fields")
    if value["schema"] != EVIDENCE_SCHEMA:
        raise BRPLVerificationError("V401", f"evidence.schema must be {EVIDENCE_SCHEMA}")
    candidate = value["candidate_tree"]
    if not isinstance(candidate, dict) or set(candidate) != {"sha256"} or not isinstance(candidate["sha256"], str) or not _DIGEST.fullmatch(candidate["sha256"]):
        raise BRPLVerificationError("V402", "candidate_tree must contain a SHA-256")
    for key in ("changes", "graphs", "manifest_deltas", "checks", "metrics"):
        if not isinstance(value[key], list): raise BRPLVerificationError("V403", f"evidence.{key} must be a list")
    for graph in value["graphs"]: _validate_graph(graph, candidate["sha256"])
    return _normal(value)


def _validate_graph(graph: Any, candidate: str) -> None:
    required = {"relation", "source_universe", "target_universe", "completeness", "adapter_binding", "candidate_tree_sha256", "edges"}
    if not isinstance(graph, dict) or set(graph) != required: raise BRPLVerificationError("V404", "graph evidence has invalid fields")
    if any(not isinstance(graph[key], str) or not graph[key] for key in required - {"edges"}): raise BRPLVerificationError("V405", "graph evidence metadata is invalid")
    if graph["completeness"] not in {"complete", "partial", "indeterminate"}: raise BRPLVerificationError("V406", "graph completeness is invalid")
    if graph["candidate_tree_sha256"] != candidate: raise BRPLVerificationError("V407", "graph candidate hash does not match evidence")
    if not isinstance(graph["edges"], list) or any(not isinstance(edge, dict) or set(edge) != {"source", "target"} or not all(isinstance(edge[key], str) and edge[key] for key in edge) for edge in graph["edges"]): raise BRPLVerificationError("V408", "graph edges are invalid")


def evaluate_plan(plan: dict[str, Any], evidence: dict[str, Any]) -> dict[str, Any]:
    """Return all rule statuses and stable findings for the same candidate tree."""
    try:
        plan = validate_plan(plan)
    except BRPLCompileError as exc:
        raise BRPLVerificationError("V409", str(exc)) from exc
    evidence = validate_evidence(evidence)
    candidate = evidence["candidate_tree"]["sha256"]
    capabilities = {item["id"]: item for item in plan["capabilities"]}
    graph_by_relation = {item["relation"]: item for item in evidence["graphs"]}
    findings: list[dict[str, Any]] = []; catalog: list[dict[str, Any]] = []
    for rule in plan["rules"]:
        facts, status, evaluation_error = _evaluate_rule(rule, evidence, graph_by_relation, capabilities, candidate)
        catalog.append({"rule_id": rule["id"], "policy_id": rule["policy_id"], "policy_class": rule["policy_class"], "family": rule["policy_class"].split(".")[0], "enforcement_severity": rule["severity"], "status": status, "applicable": True, "remediation": rule["remediation"]})
        if evaluation_error:
            findings.append(_finding(rule, {"type": "evaluation_error", "code": evaluation_error, "candidate_tree_sha256": candidate}, "evaluation_error"))
        for fact in facts:
            findings.append(_finding(rule, fact, "violation"))
    findings.sort(key=lambda item: (item["rule_id"], item["kind"], item["evidence_sha256"]))
    failed = [item for item in catalog if item["status"] != "satisfied"]
    return {"schema": REPORT_SCHEMA, "brpl_version": 4, "outcome": "pass" if not failed else "blocked", "ok": not failed, "candidate_tree_sha256": candidate, "plan_sha256": plan["semantic_sha256"], "policy_ids": [item["id"] for item in plan["policies"]], "rules_evaluated": [item["id"] for item in plan["rules"]], "rules": catalog, "findings": findings, "violations": [item for item in findings if item["kind"] == "violation"], "errors": [item for item in findings if item["kind"] == "evaluation_error"]}


def _evaluate_rule(rule: dict[str, Any], evidence: dict[str, Any], graphs: dict[str, dict[str, Any]], capabilities: dict[str, dict[str, Any]], candidate: str) -> tuple[list[dict[str, Any]], str, str | None]:
    kind = rule["kind"]
    if kind in {"changes", "protect", "generated"}:
        facts = []
        for change in evidence["changes"]:
            if not isinstance(change, dict) or not isinstance(change.get("path"), str): return [], "indeterminate", "V410"
            paths = [change["path"]] + ([change["old_path"]] if isinstance(change.get("old_path"), str) else [])
            for path in paths:
                matched = any(_matches(pattern, path) for pattern in rule["paths"])
                violation = (kind == "changes" and ((rule["mode"] == "only" and not matched) or (rule["mode"] == "deny" and matched))) or (kind in {"protect", "generated"} and matched)
                if violation: facts.append({"type": "change", **change, "matched_path": path, "candidate_tree_sha256": candidate})
        return facts, "violated" if facts else "satisfied", None
    if kind in {"forbid-edge", "forbid-path", "component-adjacency", "acyclic"}:
        graph = graphs.get(rule["relation"])
        error = _graph_ready(graph, capabilities.get(rule["relation"]), candidate)
        if error: return [], "indeterminate", error
        assert graph is not None
        if kind == "forbid-edge": facts = [dict(type="graph_edge", relation=rule["relation"], source=edge["source"], target=edge["target"], candidate_tree_sha256=candidate) for edge in graph["edges"] if _in(rule["source_paths"], edge["source"]) and _in(rule["target_paths"], edge["target"])]
        elif kind == "forbid-path": facts = _forbidden_paths(rule, graph, candidate)
        elif kind == "component-adjacency": facts = _component_violations(rule, graph, candidate)
        else: facts = _cycles(rule, graph, candidate)
        return facts, "violated" if facts else "satisfied", None
    if kind == "dependencies":
        facts = []
        for delta in evidence["manifest_deltas"]:
            if not isinstance(delta, dict) or delta.get("manifest") != rule["manifest"]: continue
            if delta.get("candidate_tree_sha256") != candidate: return [], "indeterminate", "V411"
            for name in sorted(set(delta.get("added", [])) - set(rule["allow_add"])): facts.append({"type": "manifest_delta", "manifest": rule["manifest"], "operation": "add", "dependency": name, "candidate_tree_sha256": candidate})
            for name in sorted(set(delta.get("removed", [])) - set(rule["allow_remove"])): facts.append({"type": "manifest_delta", "manifest": rule["manifest"], "operation": "remove", "dependency": name, "candidate_tree_sha256": candidate})
        return facts, "violated" if facts else "satisfied", None
    if kind == "require":
        result = next((item for item in evidence["checks"] if isinstance(item, dict) and item.get("check") == rule["check"]), None)
        if not isinstance(result, dict) or result.get("candidate_tree_sha256") != candidate: return [], "indeterminate", "V412"
        facts = [] if result.get("status") == "pass" else [{"type": "check", "check": rule["check"], "status": result.get("status", "missing"), "candidate_tree_sha256": candidate}]
        return facts, "violated" if facts else "satisfied", None
    result = next((item for item in evidence["metrics"] if isinstance(item, dict) and item.get("metric") == rule["metric"]), None)
    if not isinstance(result, dict) or result.get("candidate_tree_sha256") != candidate or result.get("unit") != rule["unit"]: return [], "indeterminate", "V413"
    try: measured, threshold = _decimal(result.get("value")), _decimal(rule["value"])
    except (InvalidOperation, ValueError): return [], "indeterminate", "V414"
    passes = measured <= threshold if rule["operator"] == "at-most" else measured >= threshold
    if passes: return [], "satisfied", None
    return [{"type": "metric", "metric": rule["metric"], "value": _plain(measured), "threshold": _plain(threshold), "operator": rule["operator"], "unit": rule["unit"], "distance": _plain(abs(measured - threshold)), "summary": rule["summary"], "candidate_tree_sha256": candidate}], "violated", None


def _graph_ready(graph: dict[str, Any] | None, capability: dict[str, Any] | None, candidate: str) -> str | None:
    if graph is None or capability is None: return "V415"
    if graph["completeness"] != "complete": return "V416"
    if graph["adapter_binding"] != capability["binding"] or graph["candidate_tree_sha256"] != candidate: return "V417"
    if graph["source_universe"] != capability["source_universe"] or graph["target_universe"] != capability["target_universe"]: return "V418"
    return None


def _forbidden_paths(rule: dict[str, Any], graph: dict[str, Any], candidate: str) -> list[dict[str, Any]]:
    edges = graph["edges"]; adjacency: dict[str, list[str]] = {}
    for edge in edges: adjacency.setdefault(edge["source"], []).append(edge["target"])
    facts = []
    for source in sorted({edge["source"] for edge in edges if _in(rule["source_paths"], edge["source"])}):
        queue = [(source, [source])]; seen = {source}
        while queue:
            node, path = queue.pop(0)
            for target in sorted(adjacency.get(node, [])):
                next_path = path + [target]
                if _in(rule["target_paths"], target): facts.append({"type": "graph_path", "relation": rule["relation"], "path": next_path, "candidate_tree_sha256": candidate}); continue
                if target not in seen: seen.add(target); queue.append((target, next_path))
    return facts


def _component_violations(rule: dict[str, Any], graph: dict[str, Any], candidate: str) -> list[dict[str, Any]]:
    components = rule["components"]; allowed = {(item["from"], item["to"]) for item in rule["allowed"]}; facts = []
    for edge in graph["edges"]:
        sources = [item["id"] for item in components if _in(item["paths"], edge["source"])]
        targets = [item["id"] for item in components if _in(item["paths"], edge["target"])]
        for source in sources:
            for target in targets:
                if source != target and (source, target) not in allowed: facts.append({"type": "component_edge", "relation": rule["relation"], "source_component": source, "target_component": target, "source": edge["source"], "target": edge["target"], "candidate_tree_sha256": candidate})
    return facts


def _cycles(rule: dict[str, Any], graph: dict[str, Any], candidate: str) -> list[dict[str, Any]]:
    edges = [edge for edge in graph["edges"] if "paths" not in rule or (_in(rule["paths"], edge["source"]) and _in(rule["paths"], edge["target"]))]; adjacency: dict[str, list[str]] = {}
    for edge in edges: adjacency.setdefault(edge["source"], []).append(edge["target"])
    facts: list[dict[str, Any]] = []; emitted: set[tuple[str, ...]] = set()
    for start in sorted(adjacency):
        stack = [(start, [start])]
        while stack:
            node, path = stack.pop()
            for target in sorted(adjacency.get(node, [])):
                if target == start:
                    cycle = tuple(path + [start]); key = tuple(sorted(cycle[:-1]))
                    if key not in emitted: emitted.add(key); facts.append({"type": "graph_cycle", "relation": rule["relation"], "cycle": list(cycle), "candidate_tree_sha256": candidate})
                elif target not in path and len(path) <= len(adjacency): stack.append((target, path + [target]))
    return facts


def _finding(rule: dict[str, Any], evidence: dict[str, Any], kind: str) -> dict[str, Any]:
    digest = hashlib.sha256(canonical_json(evidence).encode()).hexdigest()
    return {"finding_id": f"{rule['id']}:{kind}:{digest[:16]}", "kind": kind, "rule_id": rule["id"], "policy_id": rule["policy_id"], "policy_class": rule["policy_class"], "severity": rule["severity"], "evidence": evidence, "evidence_sha256": digest, "remediation": rule["remediation"]}


def cli_error_report(message: str) -> str:
    return json.dumps({"schema": REPORT_SCHEMA, "brpl_version": 4, "outcome": "blocked_evaluation_error", "ok": False, "rules_evaluated": [], "rules": [], "findings": [], "violations": [], "errors": [{"kind": "evaluation_error", "evidence": {"type": "error", "text": message}}]}, sort_keys=True, indent=2) + "\n"


def _decimal(value: Any) -> Decimal:
    if isinstance(value, bool) or not isinstance(value, (str, int)): raise ValueError("not exact decimal")
    result = Decimal(str(value))
    if not result.is_finite(): raise ValueError("not finite")
    return result


def _plain(value: Decimal) -> str: return format(value, "f")
def _in(patterns: list[str], value: str) -> bool: return any(_matches(item, value) for item in patterns)
def _matches(pattern: str, path: str) -> bool:
    parts, values = pattern.split("/"), path.split("/")
    def match(index: int, position: int) -> bool:
        if index == len(parts): return position == len(values)
        if parts[index] == "**": return match(index + 1, position) or (position < len(values) and match(index, position + 1))
        if position >= len(values): return False
        expr = "^" + re.escape(parts[index]).replace(r"\*", "[^/]*").replace(r"\?", "[^/]") + "$"
        return re.fullmatch(expr, values[position]) is not None and match(index + 1, position + 1)
    return match(0, 0)
def _normal(value: Any) -> Any: return json.loads(canonical_json(value))
