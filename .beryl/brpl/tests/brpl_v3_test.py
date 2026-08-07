from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from brpl.v3 import BRPLCompileError, canonical_json, compile_contracts, load_capabilities, parse_contract, validate_plan
from brpl.v3.cli import main as cli_main
from brpl.v3.runtime import evaluate_plan
from brpl.v3.compiler import (
    MAX_CONTRACT_BYTES,
    MAX_CONTRACT_LINES,
    MAX_CONTRACT_STATEMENTS,
    MAX_LINE_CHARACTERS,
    MAX_STRING_CHARACTERS,
    MAX_TOKENS_PER_STATEMENT,
)


ROOT = Path(__file__).resolve().parents[1]
EXAMPLES = ROOT / "examples" / "v3"


class BRPLV3CompilerTest(unittest.TestCase):
    def test_multilingual_contract_compiles_to_canonical_plan(self) -> None:
        repository = parse_contract((EXAMPLES / "repository.brpl").read_text(encoding="utf-8"), "repository.brpl")
        task = parse_contract((EXAMPLES / "task.brpl").read_text(encoding="utf-8"), "task.brpl")
        capabilities = load_capabilities(EXAMPLES / "capabilities.json")
        plan = compile_contracts([task, repository], capabilities)

        self.assertEqual(plan["schema"], "brpl-plan/v3")
        self.assertEqual(plan["repository"], {"name": "Acme service", "root": "."})
        self.assertEqual(plan["policies"], [
            {"id": "acme-service", "kind": "repository"},
            {"id": "add-order-validation", "kind": "task"},
        ])
        self.assertEqual(
            {rule["operation"] for rule in plan["rules"]},
            {
                "changed_paths_within", "changed_paths_exclude",
                "protected_paths_unchanged", "generated_paths_unchanged",
                "edge_absent", "direct_dependency_delta", "check_pass",
            },
        )
        self.assertRegex(plan["semantic_sha256"], r"^[0-9a-f]{64}$")
        self.assertEqual(plan, compile_contracts([repository, task], capabilities))
        self.assertEqual(json.loads(canonical_json(plan)), plan)
        self.assertTrue(all("adapter" in item and "sha256" in item for item in plan["capabilities"]))

    def test_context_is_explicitly_non_enforcing(self) -> None:
        contract = parse_contract(
            'brpl 3 repository "context-only"\n'
            'repo "Context only" root "."\n'
            'about data-classification "restricted"\n'
            'uses security-tool "example scanner"\n'
        )
        plan = compile_contracts([contract], _capabilities())
        self.assertEqual(plan["rules"], [])
        self.assertEqual(len(plan["context"]), 2)

    def test_area_references_expand_and_overlays_conjoin(self) -> None:
        repository = parse_contract(
            'brpl 3 repository "repo"\n'
            'repo "Repo" root "."\n'
            'area source paths "src/**"\n'
            'changes SCOPE-001 only @source\n'
        )
        task = parse_contract(
            'brpl 3 task "task"\n'
            'area feature paths "src/feature/**"\n'
            'changes SCOPE-002 only @feature\n'
        )
        plan = compile_contracts([repository, task], _capabilities())
        rules = {rule["id"]: rule for rule in plan["rules"]}
        self.assertEqual(rules["SCOPE-001"]["paths"], ["src/**"])
        self.assertEqual(rules["SCOPE-002"]["paths"], ["src/feature/**"])

    def test_invalid_syntax_paths_and_references_fail_closed(self) -> None:
        with self.assertRaisesRegex(BRPLCompileError, "E022"):
            parse_contract('brpl 3 repository "repo"\nrepo "Repo" root "."\nexecute "tests"\n')
        with self.assertRaisesRegex(BRPLCompileError, "E104"):
            parse_contract('brpl 3 repository "repo"\nrepo "Repo" root "."\narea bad paths "../outside"\n')
        with self.assertRaisesRegex(BRPLCompileError, "E104"):
            parse_contract('brpl 3 repository "repo"\nrepo "Repo" root "."\narea bad paths "."\n')
        unresolved = parse_contract(
            'brpl 3 repository "repo"\nrepo "Repo" root "."\nchanges SCOPE-001 only @missing\n'
        )
        with self.assertRaisesRegex(BRPLCompileError, "E312"):
            compile_contracts([unresolved], _capabilities())

    def test_capabilities_and_public_summaries_are_linked(self) -> None:
        unavailable = parse_contract(
            'brpl 3 repository "repo"\nrepo "Repo" root "."\n'
            'area a paths "a/**"\narea b paths "b/**"\n'
            'forbid-edge EDGE-001 relation "unknown" from @a to @b\n'
        )
        with self.assertRaisesRegex(BRPLCompileError, "E307"):
            compile_contracts([unavailable], _capabilities())

        drift = parse_contract(
            'brpl 3 repository "repo"\nrepo "Repo" root "."\n'
            'require TEST-001 check "test" means "A different promise"\n'
        )
        with self.assertRaisesRegex(BRPLCompileError, "E310"):
            compile_contracts([drift], _capabilities())

    def test_task_cannot_redefine_repository_area_or_rule(self) -> None:
        repository = parse_contract(
            'brpl 3 repository "repo"\nrepo "Repo" root "."\n'
            'area source paths "src/**"\nprotect PATH-001 paths @source\n'
        )
        area_task = parse_contract('brpl 3 task "task"\narea source paths "lib/**"\n')
        with self.assertRaisesRegex(BRPLCompileError, "E304"):
            compile_contracts([repository, area_task], _capabilities())
        rule_task = parse_contract('brpl 3 task "task-two"\nprotect PATH-001 paths "tests/**"\n')
        with self.assertRaisesRegex(BRPLCompileError, "E305"):
            compile_contracts([repository, rule_task], _capabilities())

    def test_plan_validation_tampering_fails_closed(self) -> None:
        plan = compile_contracts([parse_contract('brpl 3 repository "repo"\nrepo "Repo" root "."\n')], _capabilities())
        plan["repository"]["name"] = "Tampered"
        with self.assertRaisesRegex(BRPLCompileError, "E403"):
            validate_plan(plan)

    def test_native_runtime_preserves_generated_class_and_selector_unions(self) -> None:
        contract = parse_contract(
            'brpl 3 repository "repo"\nrepo "Repo" root "."\n'
            'area a paths "src/a/**" "src/common/**"\narea b paths "src/b/**" "src/shared/**"\n'
            'generated GEN-001 paths "generated/**"\n'
            'forbid-edge EDGE-001 relation "source.import" from @a to @b\n'
        )
        plan = compile_contracts([contract], _capabilities())
        evidence = {
            "schema": "brpl-evidence/v3", "candidate_tree": {"sha256": "a" * 64},
            "git_changes": [{"status": "modified", "path": "generated/client.py"}],
            "source_dependencies": [{"relation": "source.import", "source": "src/common/x.py", "target": "src/shared/y.py"}],
            "manifest_delta": [], "check_results": [],
        }
        report = evaluate_plan(plan, evidence)
        self.assertFalse(report["ok"])
        self.assertEqual({item["rule_id"] for item in report["findings"]}, {"GEN-001", "EDGE-001"})
        self.assertEqual(next(item for item in report["findings"] if item["rule_id"] == "GEN-001")["policy_class"], "generated")

    def test_contextual_strings_must_be_semantically_non_empty(self) -> None:
        cases = [
            ('brpl 3 repository "repo"\nrepo "" root "."\n', "repository name"),
            ('brpl 3 repository "repo"\nrepo "Repo" root "."\nabout purpose ""\n', "about value"),
            ('brpl 3 repository "repo"\nrepo "Repo" root "."\nuses language ""\n', "technology name"),
            ('brpl 3 repository "repo"\nrepo "Repo" root "."\nuses language "Python" major ""\n', "uses major value"),
            ('brpl 3 repository "repo"\nrepo "Repo" root "."\nrequire TEST-001 check "test" means ""\n', "check summary"),
        ]
        for source, label in cases:
            with self.subTest(label=label), self.assertRaisesRegex(BRPLCompileError, f"E111.*{label}"):
                parse_contract(source)

    def test_contract_resource_limits_fail_closed(self) -> None:
        with self.assertRaisesRegex(BRPLCompileError, "E005"):
            parse_contract("#" + "x" * MAX_CONTRACT_BYTES)
        with self.assertRaisesRegex(BRPLCompileError, "E006"):
            parse_contract("\n" * MAX_CONTRACT_LINES + 'brpl 3 repository "repo"\n')
        with self.assertRaisesRegex(BRPLCompileError, "E008"):
            parse_contract('brpl 3 repository "repo"\n' + "#" + "x" * MAX_LINE_CHARACTERS)
        with self.assertRaisesRegex(BRPLCompileError, "E007"):
            parse_contract('brpl 3 repository "repo"\n' + ('about purpose "x"\n' * (MAX_CONTRACT_STATEMENTS + 1)))
        with self.assertRaisesRegex(BRPLCompileError, "E009"):
            parse_contract('brpl 3 repository "repo"\narea source paths ' + ('"x" ' * (MAX_TOKENS_PER_STATEMENT - 2)))
        with self.assertRaisesRegex(BRPLCompileError, "E112"):
            parse_contract('brpl 3 repository "repo"\nrepo "' + ("x" * (MAX_STRING_CHARACTERS + 1)) + '" root "."\n')

    def test_cli_persists_structured_error_report(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "repo"
            root.mkdir()
            report = Path(temporary) / "report.json"
            code = cli_main([
                "--repo-root", str(root), "--base", "HEAD",
                "--policy", str(root / "missing.brpl"),
                "--capabilities", str(root / "capabilities.json"),
                "--json-report", str(report),
            ])
            self.assertEqual(code, 2)
            value = json.loads(report.read_text(encoding="utf-8"))
            self.assertEqual(value["outcome"], "blocked_evaluation_error")
            self.assertFalse(value["ok"])


def _capabilities() -> dict[str, object]:
    return {
        "schema": "brpl-capabilities/v2",
        "changes": {"adapter": "git-changes", "sha256": "a" * 64},
        "relations": [{"id": "source.import", "adapter": "python-imports", "sha256": "b" * 64}],
        "manifests": [{"id": "package.json", "adapter": "package-json", "sha256": "c" * 64}],
        "checks": [{"id": "test", "summary": "The trusted test suite must pass", "adapter": "trusted-check", "sha256": "d" * 64}],
    }


if __name__ == "__main__":
    unittest.main()
