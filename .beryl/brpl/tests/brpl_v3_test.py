from __future__ import annotations

import json
import unittest
from pathlib import Path

from brpl.v3 import BRPLCompileError, canonical_json, compile_contracts, load_capabilities, parse_contract


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


def _capabilities() -> dict[str, object]:
    return {
        "schema": "brpl-capabilities/v1",
        "relations": ["source.import"],
        "manifests": ["package.json"],
        "checks": [{"id": "test", "summary": "The trusted test suite must pass"}],
    }


if __name__ == "__main__":
    unittest.main()
