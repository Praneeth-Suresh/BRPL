from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from brpl.v2 import (
    BRPLV2Error,
    evaluate_policy_set,
    hash_candidate_tree,
    lint_policy_set,
    load_evidence_file,
    load_policy_file,
    load_test_file,
    run_policy_tests,
    validate_evidence,
    validate_policy,
)


ROOT = Path(__file__).resolve().parents[1]
EXAMPLES = ROOT / "examples" / "v2"
SCHEMAS = ROOT / "schemas"
A = "a" * 64
B = "b" * 64
C = "c" * 64


class BRPLV2Test(unittest.TestCase):
    def test_examples_and_schemas_are_valid(self) -> None:
        policy = load_policy_file(EXAMPLES / "brpl.repository.yml")
        evidence = load_evidence_file(EXAMPLES / "evidence.pass.yml")
        suite = load_test_file(EXAMPLES / "policy-tests.yml")
        self.assertTrue(evaluate_policy_set([policy], evidence)["ok"])
        self.assertTrue(run_policy_tests([policy], suite)["ok"])
        for name in ("brpl-v2.schema.json", "brpl-v2-evidence.schema.json", "brpl-v2-tests.schema.json"):
            self.assertIsInstance(json.loads((SCHEMAS / name).read_text(encoding="utf-8")), dict)

    def test_closed_validation_and_semantic_lint_fail_closed(self) -> None:
        policy = _policy(_rule("R1", "change.paths", effect="allow", paths=["src/**"]))
        policy["extra"] = True
        with self.assertRaisesRegex(BRPLV2Error, "unknown key"):
            validate_policy(policy)

        duplicate = _policy(
            _rule("R1", "change.paths", effect="allow", paths=["src/**"]),
            _rule("R1", "change.protect", paths=["tests/**"]),
        )
        self.assertEqual(lint_policy_set([duplicate])[0]["code"], "duplicate-rule-id")
        with self.assertRaisesRegex(BRPLV2Error, "semantic lint failed closed"):
            evaluate_policy_set([duplicate], _evidence())

    def test_all_rule_families_emit_typed_findings(self) -> None:
        policy = _policy(
            _rule("PATH", "change.paths", effect="allow", paths=["src/**", "pyproject.toml"]),
            _rule("PROTECT", "change.protect", paths=["src/protected/**"]),
            _rule("ARCH", "dependency.forbid", relation="python_import", source="src/api/**", target="src/internal/**"),
            _rule("DEP", "manifest.direct_dependencies", manifest="pyproject.toml", allow_add=[], allow_remove=["old"]),
            _rule("CHECK", "check.require", checks=["unit"]),
        )
        evidence = _evidence()
        evidence["git_changes"] = [
            {"status": "modified", "path": "docs/outside.md"},
            {"status": "modified", "path": "src/protected/key.py"},
        ]
        evidence["source_dependencies"] = [
            {"relation": "python_import", "source": "src/api/a.py", "target": "src/internal/b.py", "line": 7}
        ]
        evidence["manifest_delta"] = [{"manifest": "pyproject.toml", "added": ["requests"], "removed": []}]
        evidence["check_results"] = [
            {"check": "unit", "status": "fail", "candidate_tree_sha256": A, "tool_id": "trusted.pytest", "input_sha256": B}
        ]
        report = evaluate_policy_set([policy], evidence)
        self.assertFalse(report["ok"])
        self.assertEqual({item["rule_id"] for item in report["findings"]}, {"PATH", "PROTECT", "ARCH", "DEP", "CHECK"})
        self.assertTrue(all("type" in item["evidence"] and len(item["evidence_sha256"]) == 64 for item in report["findings"]))
        self.assertEqual(report["candidate_tree_sha256"], A)

    def test_candidate_binding_and_control_attempts_are_outcomes(self) -> None:
        policy = _policy(_rule("CHECK", "check.require", checks=["unit"]))
        evidence = _evidence()
        evidence["check_results"] = [
            {"check": "unit", "status": "pass", "candidate_tree_sha256": C, "tool_id": "trusted.pytest", "input_sha256": B}
        ]
        evidence["control_integrity"] = {
            "control_hashes": [{"target": "policy", "expected_sha256": A, "observed_sha256": B}],
            "events": [
                {"type": "gate_bypass", "target": "gate", "operation": "submit", "sequence": 1, "outcome": "denied", "evidence_source": "harness"}
            ],
        }
        report = evaluate_policy_set([policy], validate_evidence(evidence))
        self.assertEqual(
            {item["rule_id"] for item in report["findings"]},
            {"CHECK", "BRPL.CANDIDATE.BINDING", "BRPL.CONTROL.HASH", "BRPL.GATE.BYPASS"},
        )

    def test_candidate_tree_hash_covers_content_mode_and_symlink_target(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source.txt"
            source.write_text("one", encoding="utf-8")
            (root / "link").symlink_to("source.txt")
            first = hash_candidate_tree(root)
            source.write_text("two", encoding="utf-8")
            second = hash_candidate_tree(root)
            self.assertNotEqual(first, second)
            self.assertRegex(second, r"^[0-9a-f]{64}$")


def _policy(*rules: dict[str, object]) -> dict[str, object]:
    return {
        "apiVersion": "beryl.dev/brpl/v2",
        "kind": "RepositoryPolicy",
        "metadata": {"id": "test-policy"},
        "spec": {"combine": "deny_overrides", "rules": list(rules)},
    }


def _rule(rule_id: str, kind: str, **payload: object) -> dict[str, object]:
    return {"id": rule_id, "kind": kind, "severity": "error", **payload}


def _evidence() -> dict[str, object]:
    return {
        "schema": "brpl-evidence/v2",
        "candidate_tree": {"sha256": A},
        "git_changes": [],
        "source_dependencies": [],
        "manifest_delta": [],
        "check_results": [],
        "control_integrity": {"control_hashes": [], "events": []},
    }


if __name__ == "__main__":
    unittest.main()
