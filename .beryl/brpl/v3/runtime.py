"""Data-only BRPL v3 plan verifier.

This module deliberately accepts evidence as data.  Repository/language adapters
are trusted producers of that evidence and are selected only through the pinned
bindings embedded in a validated plan.
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any

from .compiler import BRPLCompileError, canonical_json, validate_plan


REPORT_SCHEMA = "brpl-report/v3"
EVIDENCE_SCHEMA = "brpl-evidence/v3"


class BRPLVerificationError(ValueError):
    pass


def validate_evidence(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != {"schema", "candidate_tree", "git_changes", "source_dependencies", "manifest_delta", "check_results"}:
        raise BRPLVerificationError("evidence has an invalid schema or fields")
    if value["schema"] != EVIDENCE_SCHEMA:
        raise BRPLVerificationError(f"evidence.schema must be {EVIDENCE_SCHEMA}")
    candidate = value["candidate_tree"]
    if not isinstance(candidate, dict) or set(candidate) != {"sha256"} or not isinstance(candidate["sha256"], str) or not re.fullmatch(r"[0-9a-f]{64}", candidate["sha256"]):
        raise BRPLVerificationError("evidence candidate_tree must contain a SHA-256")
    for key in ("git_changes", "source_dependencies", "manifest_delta", "check_results"):
        if not isinstance(value[key], list):
            raise BRPLVerificationError(f"evidence.{key} must be a list")
    return value


def evaluate_plan(plan: dict[str, Any], evidence: dict[str, Any]) -> dict[str, Any]:
    """Evaluate a validated, candidate-bound v3 plan deterministically."""
    try:
        plan = validate_plan(plan)
    except BRPLCompileError as exc:
        raise BRPLVerificationError(str(exc)) from exc
    evidence = validate_evidence(evidence)
    findings: list[dict[str, Any]] = []
    by_check = {item.get("check"): item for item in evidence["check_results"] if isinstance(item, dict)}
    for rule in plan["rules"]:
        operation = rule["operation"]
        facts: list[dict[str, Any]] = []
        if operation in {"changed_paths_within", "changed_paths_exclude", "protected_paths_unchanged", "generated_paths_unchanged"}:
            for change in evidence["git_changes"]:
                if not isinstance(change, dict) or not isinstance(change.get("path"), str):
                    raise BRPLVerificationError("git change is malformed")
                paths = [change["path"]] + ([change["old_path"]] if isinstance(change.get("old_path"), str) else [])
                for path in paths:
                    matched = any(_matches(pattern, path) for pattern in rule["paths"])
                    violates = (operation == "changed_paths_within" and not matched) or (operation != "changed_paths_within" and matched)
                    if violates:
                        facts.append({"type": "git_change", **change, "matched_path": path})
        elif operation == "edge_absent":
            for edge in evidence["source_dependencies"]:
                if not isinstance(edge, dict):
                    raise BRPLVerificationError("source dependency is malformed")
                if edge.get("relation") == rule["relation"] and any(_matches(pattern, edge.get("source", "")) for pattern in rule["source_paths"]) and any(_matches(pattern, edge.get("target", "")) for pattern in rule["target_paths"]):
                    facts.append({"type": "source_dependency", **edge})
        elif operation == "direct_dependency_delta":
            for delta in evidence["manifest_delta"]:
                if not isinstance(delta, dict) or delta.get("manifest") != rule["manifest"]:
                    continue
                for name in sorted(set(delta.get("added", [])) - set(rule["allow_add"])):
                    facts.append({"type": "manifest_delta", "manifest": rule["manifest"], "operation": "add", "dependency": name})
                for name in sorted(set(delta.get("removed", [])) - set(rule["allow_remove"])):
                    facts.append({"type": "manifest_delta", "manifest": rule["manifest"], "operation": "remove", "dependency": name})
        elif operation == "check_pass":
            result = by_check.get(rule["check"])
            if not isinstance(result, dict) or result.get("status") != "pass" or result.get("candidate_tree_sha256") != evidence["candidate_tree"]["sha256"]:
                facts.append({"type": "check_result", "check": rule["check"], "status": result.get("status", "missing") if isinstance(result, dict) else "missing", "candidate_tree_sha256": result.get("candidate_tree_sha256") if isinstance(result, dict) else None})
        for fact in facts:
            digest = hashlib.sha256(canonical_json(fact).encode("utf-8")).hexdigest()
            findings.append({"finding_id": f"{rule['id']}:{digest[:16]}", "rule_id": rule["id"], "policy_id": rule["policy_id"], "policy_class": rule["class"], "severity": rule["severity"], "evidence": fact, "evidence_sha256": digest, "remediation": rule["remediation"]})
    findings.sort(key=lambda item: (item["rule_id"], item["evidence_sha256"]))
    return {"schema": REPORT_SCHEMA, "brpl_version": 3, "ok": not findings, "candidate_tree_sha256": evidence["candidate_tree"]["sha256"], "plan_sha256": plan["semantic_sha256"], "policy_ids": [item["id"] for item in plan["policies"]], "rules_evaluated": [item["id"] for item in plan["rules"]], "findings": findings, "violations": findings}


def _matches(pattern: str, path: str) -> bool:
    parts, values = pattern.split("/"), path.split("/")
    def match(index: int, position: int) -> bool:
        if index == len(parts):
            return position == len(values)
        if parts[index] == "**":
            return match(index + 1, position) or (position < len(values) and match(index, position + 1))
        if position >= len(values):
            return False
        expr = "^" + re.escape(parts[index]).replace(r"\*", "[^/]*").replace(r"\?", "[^/]") + "$"
        return re.fullmatch(expr, values[position]) is not None and match(index + 1, position + 1)
    return match(0, 0)
