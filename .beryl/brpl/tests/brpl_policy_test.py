from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path

from brpl import EvaluationConfig, evaluate_policy_set, load_policy_file
from brpl.core import (
    BRPLConfigError,
    BRPLEvaluationError,
    BRPLSchemaError,
    CHECKER_VERSION,
    _bundled_policy_schema,
    _validate_against_bundled_schema,
    _validate_supported_schema,
    validate_policy,
)
from brpl.strict_yaml import StrictYAMLError, load_strict_yaml
from brpl.v2.runtime import _dependencies


class BRPLPolicyTest(unittest.TestCase):
    def test_checker_version_records_diagnostic_contract_change(self) -> None:
        self.assertEqual(CHECKER_VERSION, "1.1.0")

    def test_all_rule_families_report_stable_explicit_ids(self) -> None:
        with repo_fixture() as repo:
            write(
                repo / ".beryl/policy/brpl.repository.yml",
                """
                version: 1
                policy_id: repo
                kind: repository
                change_scope:
                  - id: deny-generated
                    deny:
                      - "generated/**"
                protected_paths:
                  - id: protect-regression
                    pattern: "tests/regression/**"
                architecture:
                  forbid_imports:
                    - id: no-domain-infra
                      from: "src/domain/**"
                      to: "src/infrastructure/**"
                new_dependencies:
                  id: no-new-deps
                  manifest: "pyproject.toml"
                  allow: false
                required_checks:
                  - id: require-unit
                    check: "unit"
                """,
            )
            write(repo / "generated/out.txt", "manual edit\n")
            write(repo / "tests/regression/test_contract.py", "changed\n")
            write(repo / "src/domain/model.py", "import src.infrastructure.db as database\n")
            write(
                repo / "pyproject.toml",
                """
                [project]
                name = "demo"
                version = "0.1.0"
                dependencies = ["requests>=2"]
                """,
            )

            report = evaluate_policy_set(
                [load_policy_file(repo / ".beryl/policy/brpl.repository.yml")],
                EvaluationConfig(
                    repo_root=repo,
                    base_ref="HEAD",
                    check_results={"unit": {"status": "fail", "evidence": "unit failed"}},
                ),
            )

            rule_ids = {violation["rule_id"] for violation in report["violations"]}
            self.assertFalse(report["ok"])
            self.assertEqual(report["schema"], "brpl-report/v1")
            self.assertIn("checker_version", report)
            self.assertRegex(report["baseline"]["sha"], r"^[0-9a-f]{40}$")
            self.assertIn("repo", report["policy_hashes"]["raw_sha256"])
            self.assertIn("repo", report["policy_hashes"]["semantic_sha256"])
            self.assertIn("deny-generated", rule_ids)
            self.assertIn("protect-regression", rule_ids)
            self.assertIn("no-domain-infra", rule_ids)
            self.assertIn("no-new-deps", rule_ids)
            self.assertIn("require-unit", rule_ids)
            for violation in report["violations"]:
                self.assertTrue(violation["violation_id"].startswith(violation["rule_id"] + ":"))
                self.assertRegex(violation["evidence_hash_prefix"], r"^[0-9a-f]{16}$")
                self.assertIsInstance(violation["evidence"], dict)
                self.assertIn("type", violation["evidence"])

    def test_change_scope_rules_report_declared_rule_id_and_overlay_conjunction(self) -> None:
        with repo_fixture() as repo:
            write(
                repo / ".beryl/policy/repo.yml",
                """
                version: 1
                policy_id: repo
                kind: repository
                change_scope:
                  - id: repo-scope
                    allow:
                      - "src/**"
                      - "tests/**"
                    deny:
                      - "src/domain/blocked.py"
                """,
            )
            write(
                repo / ".beryl/policy/task.yml",
                """
                version: 1
                policy_id: task
                kind: task
                change_scope:
                  - id: task-scope
                    allow:
                      - "src/domain/**"
                """,
            )
            write(repo / "src/domain/blocked.py", "x = 1\n")
            write(repo / "src/infrastructure/allowed-by-repo.py", "x = 1\n")

            report = evaluate_policy_set(
                [load_policy_file(repo / ".beryl/policy/repo.yml"), load_policy_file(repo / ".beryl/policy/task.yml")],
                EvaluationConfig(repo_root=repo, base_ref="HEAD", check_results={}),
            )

            violations = {(violation["rule_id"], violation["file"]) for violation in report["violations"]}
            self.assertIn(("repo-scope", "src/domain/blocked.py"), violations)
            self.assertIn(("task-scope", "src/infrastructure/allowed-by-repo.py"), violations)
            self.assertNotIn("src/**", {violation["rule_id"] for violation in report["violations"]})

    def test_duplicate_policy_and_rule_ids_are_rejected_across_overlays(self) -> None:
        with repo_fixture() as repo:
            write_policy(repo, "repo.yml", "repo", extra_required_id="same-rule")
            write_policy(repo, "task.yml", "repo", kind="task", extra_required_id="other-rule")
            with self.assertRaisesRegex(BRPLConfigError, "duplicate policy_id"):
                evaluate_policy_set(
                    [load_policy_file(repo / ".beryl/policy/repo.yml"), load_policy_file(repo / ".beryl/policy/task.yml")],
                    EvaluationConfig(repo_root=repo, base_ref="HEAD", check_results={}),
                )

            write_policy(repo, "task.yml", "task", kind="task", extra_required_id="same-rule")
            with self.assertRaisesRegex(BRPLConfigError, "duplicate rule id"):
                evaluate_policy_set(
                    [load_policy_file(repo / ".beryl/policy/repo.yml"), load_policy_file(repo / ".beryl/policy/task.yml")],
                    EvaluationConfig(repo_root=repo, base_ref="HEAD", check_results={}),
                )

    def test_legacy_array_rules_without_ids_are_rejected(self) -> None:
        with repo_fixture() as repo:
            write(
                repo / ".beryl/policy/legacy.yml",
                """
                version: 1
                policy_id: legacy
                kind: repository
                protected_paths:
                  - "tests/**"
                """,
            )
            with self.assertRaises(BRPLSchemaError):
                load_policy_file(repo / ".beryl/policy/legacy.yml")

    def test_double_quoted_unicode_patterns_preserve_paths(self) -> None:
        with repo_fixture() as repo:
            write(
                repo / ".beryl/policy/unicode.yml",
                """
                version: 1
                policy_id: unicode
                kind: repository
                protected_paths:
                  - id: protect-cafe
                    pattern: "café/**"
                """,
            )
            write(repo / "café/menu.txt", "espresso\n")

            report = evaluate_policy_set(
                [load_policy_file(repo / ".beryl/policy/unicode.yml")],
                EvaluationConfig(repo_root=repo, base_ref="HEAD", check_results={}),
            )

            self.assertIn(("protect-cafe", "café/menu.txt"), {(v["rule_id"], v["file"]) for v in report["violations"]})

    def test_strict_yaml_rejects_surrogate_escapes_and_preserves_valid_unicode(self) -> None:
        data = load_strict_yaml('ordinary: "caf\\u00E9"\nnon_bmp: "\\U0001F600"\n')
        self.assertEqual(data["ordinary"], "café")
        self.assertEqual(data["non_bmp"], "😀")

        for escape in ("\\uD800", "\\uDFFF"):
            with self.subTest(escape=escape):
                with self.assertRaisesRegex(StrictYAMLError, "invalid Unicode scalar"):
                    load_strict_yaml(f'value: "{escape}"\n')

    def test_policy_loader_and_cli_reject_surrogate_escapes_as_schema_errors(self) -> None:
        with repo_fixture() as repo:
            write(
                repo / ".beryl/policy/valid-unicode.yml",
                """
                version: 1
                policy_id: valid-unicode
                kind: repository
                protected_paths:
                  - id: protect-valid-unicode
                    pattern: "caf\\u00E9/\\U0001F600/**"
                """,
            )
            write(repo / "café/😀/menu.txt", "espresso\n")
            report = evaluate_policy_set(
                [load_policy_file(repo / ".beryl/policy/valid-unicode.yml")],
                EvaluationConfig(repo_root=repo, base_ref="HEAD", check_results={}),
            )
            self.assertIn(
                ("protect-valid-unicode", "café/😀/menu.txt"),
                {(violation["rule_id"], violation["file"]) for violation in report["violations"]},
            )

            write(
                repo / ".beryl/policy/surrogate.yml",
                """
                version: 1
                policy_id: surrogate
                kind: repository
                protected_paths:
                  - id: reject-surrogate
                    pattern: "\\uD800/**"
                """,
            )
            with self.assertRaisesRegex(BRPLSchemaError, "invalid Unicode scalar"):
                load_policy_file(repo / ".beryl/policy/surrogate.yml")

            result = run_brpl(repo, "--policy", ".beryl/policy/surrogate.yml", "--format", "json")
            self.assertEqual(result.returncode, 2)
            error = json.loads(result.stderr)
            self.assertFalse(error["ok"])
            self.assertEqual(error["schema"], "brpl-report/v1")
            self.assertIn("invalid Unicode scalar", error["errors"][0]["evidence"]["text"])

    def test_segment_aware_globs_are_whole_path_and_double_star_is_segment_only(self) -> None:
        with repo_fixture() as repo:
            write(
                repo / ".beryl/policy/glob.yml",
                """
                version: 1
                policy_id: glob
                kind: repository
                change_scope:
                  - id: deny-py-in-src
                    deny:
                      - "src/*.py"
                  - id: deny-any-generated
                    deny:
                      - "generated/**"
                """,
            )
            write(repo / "src/top.py", "x = 1\n")
            write(repo / "src/nested/deep.py", "x = 1\n")
            write(repo / "generated/nested/out.txt", "x\n")

            report = evaluate_policy_set(
                [load_policy_file(repo / ".beryl/policy/glob.yml")],
                EvaluationConfig(repo_root=repo, base_ref="HEAD", check_results={}),
            )
            evidence_paths = {(v["rule_id"], v["file"]) for v in report["violations"]}
            self.assertIn(("deny-py-in-src", "src/top.py"), evidence_paths)
            self.assertNotIn(("deny-py-in-src", "src/nested/deep.py"), evidence_paths)
            self.assertIn(("deny-any-generated", "generated/nested/out.txt"), evidence_paths)

            write(
                repo / ".beryl/policy/badglob.yml",
                """
                version: 1
                policy_id: badglob
                kind: repository
                change_scope:
                  - id: bad
                    deny:
                      - "src/**.py"
                """,
            )
            with self.assertRaises(BRPLSchemaError):
                load_policy_file(repo / ".beryl/policy/badglob.yml")

    def test_git_status_parser_handles_rename_copy_delete_typechange_and_odd_filenames(self) -> None:
        with repo_fixture() as repo:
            write(
                repo / ".beryl/policy/scope.yml",
                """
                version: 1
                policy_id: scope
                kind: repository
                change_scope:
                  - id: deny-src
                    deny:
                      - "src/**"
                  - id: deny-odd
                    deny:
                      - "odd/**"
                """,
            )
            git(repo, "mv", "src/domain/model.py", "src/domain/renamed.py")
            shutil.copy2(repo / "src/infrastructure/db.py", repo / "src/infrastructure/db_copy.py")
            git(repo, "add", "src/infrastructure/db_copy.py")
            git(repo, "rm", "tests/regression/test_contract.py")
            if hasattr(os, "symlink"):
                git(repo, "rm", "src/infrastructure/db.py")
                os.symlink("../domain/renamed.py", repo / "src/infrastructure/db.py")
                git(repo, "add", "src/infrastructure/db.py")
            write(repo / "odd/name\n\tfile.py", "x = 1\n")

            report = evaluate_policy_set(
                [load_policy_file(repo / ".beryl/policy/scope.yml")],
                EvaluationConfig(repo_root=repo, base_ref="HEAD", check_results={}),
            )
            files = {violation["file"] for violation in report["violations"]}
            self.assertIn("src/domain/model.py", files)
            self.assertIn("src/domain/renamed.py", files)
            self.assertIn("src/infrastructure/db_copy.py", files)
            self.assertIn("odd/name\n\tfile.py", files)
            if hasattr(os, "symlink"):
                self.assertIn("src/infrastructure/db.py", files)

    def test_change_scope_evidence_preserves_rename_delete_and_untracked_status(self) -> None:
        with repo_fixture() as repo:
            write(
                repo / ".beryl/policy/scope-status.yml",
                """
                version: 1
                policy_id: status
                kind: repository
                change_scope:
                  - id: deny-all
                    deny:
                      - "**"
                """,
            )
            git(repo, "mv", "src/domain/model.py", "src/domain/renamed.py")
            git(repo, "rm", "tests/regression/test_contract.py")
            write(repo / "untracked.py", "x = 1\n")

            report = evaluate_policy_set(
                [load_policy_file(repo / ".beryl/policy/scope-status.yml")],
                EvaluationConfig(repo_root=repo, base_ref="HEAD", check_results={}),
            )
            statuses = {
                (violation["file"], violation["evidence"]["status"])
                for violation in report["violations"]
            }
            self.assertIn(("src/domain/model.py", "R"), statuses)
            self.assertIn(("src/domain/renamed.py", "R"), statuses)
            self.assertIn(("tests/regression/test_contract.py", "D"), statuses)
            self.assertIn(("untracked.py", "?"), statuses)
            for violation in report["violations"]:
                self.assertEqual(violation["evidence"]["matched_deny"], ["**"])
                self.assertIn("unintended artifact/change", violation["remediation"])

    def test_protected_path_copy_detects_unchanged_source_and_new_path(self) -> None:
        with repo_fixture() as repo:
            write(
                repo / ".beryl/policy/protected.yml",
                """
                version: 1
                policy_id: protected
                kind: repository
                protected_paths:
                  - id: protect-regression
                    pattern: "tests/regression/**"
                  - id: protect-copies
                    pattern: "copies/**"
                """,
            )
            (repo / "copies").mkdir()
            shutil.copy2(repo / "tests/regression/test_contract.py", repo / "copies/test_contract.py")
            git(repo, "add", "copies/test_contract.py")

            report = evaluate_policy_set(
                [load_policy_file(repo / ".beryl/policy/protected.yml")],
                EvaluationConfig(repo_root=repo, base_ref="HEAD", check_results={}),
            )

            violations = {(violation["rule_id"], violation["file"], violation["evidence"]["status"]) for violation in report["violations"]}
            self.assertIn(("protect-regression", "tests/regression/test_contract.py", "C"), violations)
            self.assertIn(("protect-copies", "copies/test_contract.py", "C"), violations)

    def test_invalid_utf8_git_path_fails_closed_and_cli_returns_structured_exit_2(self) -> None:
        if os.name == "nt":
            self.skipTest("invalid UTF-8 path bytes are POSIX-specific")
        with repo_fixture() as repo:
            write(
                repo / ".beryl/policy/scope.yml",
                """
                version: 1
                policy_id: scope
                kind: repository
                change_scope:
                  - id: deny-all
                    deny:
                      - "**"
                """,
            )
            raw_repo = os.fsencode(repo)
            raw_dir = os.path.join(raw_repo, b"bad")
            os.mkdir(raw_dir)
            raw_file = os.path.join(raw_dir, b"\xff.py")
            fd = os.open(raw_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
            try:
                os.write(fd, b"x = 1\n")
            finally:
                os.close(fd)

            policy = load_policy_file(repo / ".beryl/policy/scope.yml")
            with self.assertRaisesRegex(BRPLEvaluationError, "not valid UTF-8"):
                evaluate_policy_set([policy], EvaluationConfig(repo_root=repo, base_ref="HEAD", check_results={}))

            result = run_brpl(repo, "--policy", ".beryl/policy/scope.yml", "--format", "json")
            self.assertEqual(result.returncode, 2)
            error = json.loads(result.stderr)
            self.assertFalse(error["ok"])
            self.assertIn("not valid UTF-8", error["errors"][0]["evidence"]["text"])

    def test_architecture_scans_full_final_tree_and_resolves_relative_imports(self) -> None:
        with repo_fixture() as repo:
            write(repo / "src/domain/sub/thing.py", "from ...infrastructure import db\n")
            write(
                repo / ".beryl/policy/arch.yml",
                """
                version: 1
                policy_id: arch
                kind: repository
                architecture:
                  forbid_imports:
                    - id: no-relative-infra
                      from: "src/domain/**"
                      to: "src/infrastructure/**"
                """,
            )
            git(repo, "add", ".")
            git(repo, "-c", "user.name=Test", "-c", "user.email=test@example.invalid", "commit", "-m", "relative import")

            report = evaluate_policy_set(
                [load_policy_file(repo / ".beryl/policy/arch.yml")],
                EvaluationConfig(repo_root=repo, base_ref="HEAD", check_results={}),
            )

            self.assertFalse(report["ok"])
            self.assertIn("no-relative-infra", {violation["rule_id"] for violation in report["violations"]})

    def test_architecture_resolves_absolute_imports_from_src_layout(self) -> None:
        with repo_fixture() as repo:
            write(repo / "src/fulfilment/domain/model.py", "from fulfilment.infrastructure import sqlite_store\n")
            write(repo / "src/fulfilment/infrastructure/sqlite_store.py", "connection = object()\n")

            self.assertIn(
                {
                    "relation": "python_import",
                    "source": "src/fulfilment/domain/model.py",
                    "target": "src/fulfilment/infrastructure/sqlite_store.py",
                },
                _dependencies(repo),
            )

    def test_architecture_fails_closed_on_syntax_error_and_matched_symlink(self) -> None:
        with repo_fixture() as repo:
            write_arch_policy(repo)
            write(repo / "src/domain/bad.py", "def broken(:\n")
            with self.assertRaisesRegex(BRPLEvaluationError, "cannot parse Python imports"):
                evaluate_policy_set(
                    [load_policy_file(repo / ".beryl/policy/arch.yml")],
                    EvaluationConfig(repo_root=repo, base_ref="HEAD", check_results={}),
                )

        if hasattr(os, "symlink"):
            with repo_fixture() as repo:
                write_arch_policy(repo)
                target = repo / "src/domain/model.py"
                link = repo / "src/domain/link.py"
                try:
                    os.symlink(target, link)
                except OSError:
                    self.skipTest("symlink creation unavailable")
                with self.assertRaisesRegex(BRPLEvaluationError, "symlink"):
                    evaluate_policy_set(
                        [load_policy_file(repo / ".beryl/policy/arch.yml")],
                        EvaluationConfig(repo_root=repo, base_ref="HEAD", check_results={}),
                    )

    def test_new_dependencies_use_explicit_manifest_optional_groups_and_pep503_normalization(self) -> None:
        with repo_fixture() as repo:
            write(
                repo / ".beryl/policy/deps.yml",
                """
                version: 1
                policy_id: deps
                kind: repository
                new_dependencies:
                  id: no-new-deps
                  manifest: "pyproject.toml"
                  allow: false
                """,
            )
            write(
                repo / "pyproject.toml",
                """
                [project]
                name = "demo"
                version = "0.1.0"
                dependencies = ["Requests>=2"]

                [project.optional-dependencies]
                dev = ["My_Pkg.Name[fast]>=1"]
                """,
            )

            report = evaluate_policy_set(
                [load_policy_file(repo / ".beryl/policy/deps.yml")],
                EvaluationConfig(repo_root=repo, base_ref="HEAD", check_results={}),
            )

            dependencies = {
                violation["evidence"]["dependency"]
                for violation in report["violations"]
                if violation["rule_id"] == "no-new-deps"
            }
            self.assertEqual(dependencies, {"my-pkg-name", "requests"})

    def test_dependency_rule_fails_closed_on_missing_malformed_replaced_and_allow_list(self) -> None:
        with repo_fixture() as repo:
            write(
                repo / ".beryl/policy/deps.yml",
                """
                version: 1
                policy_id: deps
                kind: repository
                new_dependencies:
                  id: no-new-deps
                  manifest: "pyproject.toml"
                  allow: false
                """,
            )
            policy = load_policy_file(repo / ".beryl/policy/deps.yml")
            (repo / "pyproject.toml").unlink()
            with self.assertRaisesRegex(BRPLEvaluationError, "missing"):
                evaluate_policy_set([policy], EvaluationConfig(repo_root=repo, base_ref="HEAD", check_results={}))

        with repo_fixture() as repo:
            write(repo / "pyproject.toml", "[project\n")
            write(
                repo / ".beryl/policy/deps.yml",
                """
                version: 1
                policy_id: deps
                kind: repository
                new_dependencies:
                  id: no-new-deps
                  manifest: "pyproject.toml"
                  allow: false
                """,
            )
            with self.assertRaisesRegex(BRPLEvaluationError, "cannot parse"):
                evaluate_policy_set(
                    [load_policy_file(repo / ".beryl/policy/deps.yml")],
                    EvaluationConfig(repo_root=repo, base_ref="HEAD", check_results={}),
                )

        with repo_fixture() as repo:
            write_raw(repo / "pyproject.toml", b"\xff")
            write(
                repo / ".beryl/policy/deps.yml",
                """
                version: 1
                policy_id: deps
                kind: repository
                new_dependencies:
                  id: no-new-deps
                  manifest: "pyproject.toml"
                  allow: false
                """,
            )
            with self.assertRaisesRegex(BRPLEvaluationError, "pyproject.toml must be UTF-8"):
                evaluate_policy_set(
                    [load_policy_file(repo / ".beryl/policy/deps.yml")],
                    EvaluationConfig(repo_root=repo, base_ref="HEAD", check_results={}),
                )

        with repo_fixture() as repo:
            write(
                repo / ".beryl/policy/deps.yml",
                """
                version: 1
                policy_id: deps
                kind: repository
                new_dependencies:
                  id: no-new-deps
                  manifest: "requirements/pyproject.toml"
                  allow: false
                """,
            )
            write(repo / "requirements/pyproject.toml", "[project]\nname='demo'\nversion='0.1.0'\ndependencies=[]\n")
            with self.assertRaises(BRPLConfigError):
                evaluate_policy_set(
                    [load_policy_file(repo / ".beryl/policy/deps.yml")],
                    EvaluationConfig(repo_root=repo, base_ref="HEAD", check_results={}),
                )

        with repo_fixture() as repo:
            write(repo / "pyproject.toml", "[project\n")
            git(repo, "add", "pyproject.toml")
            git(repo, "-c", "user.name=Test", "-c", "user.email=test@example.invalid", "commit", "-m", "malformed baseline")
            write(repo / "pyproject.toml", "[project]\nname='demo'\nversion='0.1.0'\ndependencies=[]\n")
            write(
                repo / ".beryl/policy/deps.yml",
                """
                version: 1
                policy_id: deps
                kind: repository
                new_dependencies:
                  id: no-new-deps
                  manifest: "pyproject.toml"
                  allow: false
                """,
            )
            with self.assertRaisesRegex(BRPLEvaluationError, "baseline pyproject.toml"):
                evaluate_policy_set(
                    [load_policy_file(repo / ".beryl/policy/deps.yml")],
                    EvaluationConfig(repo_root=repo, base_ref="HEAD", check_results={}),
                )

        with repo_fixture() as repo:
            write_raw(repo / "pyproject.toml", b"\xff")
            git(repo, "add", "pyproject.toml")
            git(repo, "-c", "user.name=Test", "-c", "user.email=test@example.invalid", "commit", "-m", "invalid utf8 baseline")
            write(repo / "pyproject.toml", "[project]\nname='demo'\nversion='0.1.0'\ndependencies=[]\n")
            write(
                repo / ".beryl/policy/deps.yml",
                """
                version: 1
                policy_id: deps
                kind: repository
                new_dependencies:
                  id: no-new-deps
                  manifest: "pyproject.toml"
                  allow: false
                """,
            )
            with self.assertRaisesRegex(BRPLEvaluationError, "baseline pyproject.toml must be UTF-8"):
                evaluate_policy_set(
                    [load_policy_file(repo / ".beryl/policy/deps.yml")],
                    EvaluationConfig(repo_root=repo, base_ref="HEAD", check_results={}),
                )

        if hasattr(os, "symlink"):
            with repo_fixture() as repo:
                write(
                    repo / ".beryl/policy/deps.yml",
                    """
                    version: 1
                    policy_id: deps
                    kind: repository
                    new_dependencies:
                      id: no-new-deps
                      manifest: "pyproject.toml"
                      allow: false
                    """,
                )
                (repo / "pyproject.toml").unlink()
                try:
                    os.symlink("missing.toml", repo / "pyproject.toml")
                except OSError:
                    self.skipTest("symlink creation unavailable")
                with self.assertRaisesRegex(BRPLEvaluationError, "regular file"):
                    evaluate_policy_set(
                        [load_policy_file(repo / ".beryl/policy/deps.yml")],
                        EvaluationConfig(repo_root=repo, base_ref="HEAD", check_results={}),
                    )

        with repo_fixture() as repo:
            write(
                repo / ".beryl/policy/deps.yml",
                """
                version: 1
                policy_id: deps
                kind: repository
                new_dependencies:
                  id: no-new-deps
                  manifest: "pyproject.toml"
                  allow:
                    - "requests"
                """,
            )
            with self.assertRaises(BRPLSchemaError):
                load_policy_file(repo / ".beryl/policy/deps.yml")

    def test_strict_yaml_and_path_safety_rejections_exit_as_schema_errors(self) -> None:
        cases = {
            "absolute.yml": 'version: 1\npolicy_id: p\nkind: repository\nprotected_paths:\n  - id: r\n    pattern: "/abs"\n',
            "backslash.yml": 'version: 1\npolicy_id: p\nkind: repository\nprotected_paths:\n  - id: r\n    pattern: "src\\\\x"\n',
            "dotdot.yml": 'version: 1\npolicy_id: p\nkind: repository\nprotected_paths:\n  - id: r\n    pattern: "src/../x"\n',
            "duplicate.yml": "version: 1\npolicy_id: p\npolicy_id: q\nkind: repository\n",
            "alias.yml": "version: 1\npolicy_id: p\nkind: repository\nprotected_paths:\n  - id: r\n    pattern: *anchor\n",
            "tag.yml": "version: 1\npolicy_id: !tag p\nkind: repository\n",
            "merge.yml": "version: 1\npolicy_id: p\nkind: repository\n<<: {}\n",
            "multidoc.yml": "version: 1\npolicy_id: p\nkind: repository\n---\nkind: task\n",
            "nonstring.yml": "123: value\nversion: 1\npolicy_id: p\nkind: repository\n",
        }
        with repo_fixture() as repo:
            for name, content in cases.items():
                write_raw(repo / ".beryl/policy" / name, content.encode("utf-8"))
                with self.subTest(name=name):
                    with self.assertRaises(BRPLSchemaError):
                        load_policy_file(repo / ".beryl/policy" / name)
            write_raw(repo / ".beryl/policy/nul.yml", b"version: 1\npolicy_id: p\0\nkind: repository\n")
            with self.assertRaises(BRPLSchemaError):
                load_policy_file(repo / ".beryl/policy/nul.yml")
            write(repo / ".beryl/policy/large.yml", "version: 1\n" + ("# filler\n" * 2100))
            with self.assertRaisesRegex(BRPLSchemaError, "lines"):
                load_policy_file(repo / ".beryl/policy/large.yml")
            with self.assertRaisesRegex(BRPLSchemaError, "non-string"):
                validate_policy({1: "value", "version": 1, "policy_id": "p", "kind": "repository"})

    def test_reserved_input_keys_are_rejected_before_metadata_and_schema_parity(self) -> None:
        valid_docs = [
            {"version": 1, "policy_id": "repo", "kind": "repository"},
            {
                "version": 1,
                "policy_id": "task",
                "kind": "task",
                "change_scope": [{"id": "scope", "allow": ["src/**", "tests/**"], "deny": ["generated/**"]}],
            },
        ]
        invalid_docs = [
            {"version": 1, "policy_id": "repo", "kind": "repository", "__brpl_semantic_hash": "forged"},
            {
                "version": 1,
                "policy_id": "repo",
                "kind": "repository",
                "protected_paths": [{"id": "protect", "pattern": "src/**", "__brpl_raw_hash": "forged"}],
            },
            {"version": 1, "policy_id": "repo", "kind": "repository", "change_scope": {"allow": []}},
            {"version": 1, "policy_id": "repo", "kind": "repository", "change_scope": [{"id": "scope"}]},
            {"version": 1, "policy_id": "repo", "kind": "repository", "change_scope": [{"id": "scope", "allow": ["/abs"]}]},
        ]

        for doc in valid_docs:
            with self.subTest(valid=doc["policy_id"]):
                _validate_against_bundled_schema(doc, "<schema>")
                validate_policy(json.loads(json.dumps(doc)))

        for index, doc in enumerate(invalid_docs):
            with self.subTest(invalid=index):
                with self.assertRaises(BRPLSchemaError):
                    _validate_against_bundled_schema(doc, "<schema>")
                with self.assertRaises(BRPLSchemaError):
                    validate_policy(json.loads(json.dumps(doc)))

        with repo_fixture() as repo:
            write(
                repo / ".beryl/policy/private.yml",
                """
                version: 1
                policy_id: private
                kind: repository
                __brpl_semantic_hash: forged
                """,
            )
            with self.assertRaisesRegex(BRPLSchemaError, "reserved key"):
                load_policy_file(repo / ".beryl/policy/private.yml")

    def test_closed_schema_subset_covers_keywords_and_rejects_bad_shapes(self) -> None:
        schema = _bundled_policy_schema()
        _validate_supported_schema(schema, root=schema)
        used = {
            "$ref",
            "allOf",
            "anyOf",
            "not",
            "const",
            "enum",
            "type",
            "minLength",
            "pattern",
            "items",
            "properties",
            "additionalProperties",
            "required",
        }

        def collect(node: object) -> set[str]:
            if isinstance(node, dict):
                keys = set(node) & used
                for value in node.values():
                    keys.update(collect(value))
                return keys
            if isinstance(node, list):
                keys: set[str] = set()
                for value in node:
                    keys.update(collect(value))
                return keys
            return set()

        self.assertEqual(collect(schema), used)
        invalid = [
            {"unsupported": True},
            {"$ref": "https://example.invalid/schema"},
            {"$ref": "#/$defs/missing"},
            {"allOf": {}},
            {"anyOf": []},
            {"not": []},
            {"enum": []},
            {"type": "number"},
            {"minLength": -1},
            {"pattern": "["},
            {"items": []},
            {"properties": []},
            {"additionalProperties": True},
            {"required": ["x", "x"]},
        ]
        for candidate in invalid:
            with self.subTest(candidate=candidate):
                with self.assertRaises(BRPLConfigError):
                    _validate_supported_schema(candidate, root=candidate)

    def test_bundled_schema_passes_draft_2020_12_metaschema_when_available(self) -> None:
        try:
            import jsonschema
        except ImportError:
            self.skipTest("jsonschema is not installed; meta-schema validation recorded as unavailable")
        jsonschema.Draft202012Validator.check_schema(_bundled_policy_schema())

    def test_cli_exit_codes_for_pass_violation_and_schema_error(self) -> None:
        with repo_fixture() as repo:
            write(
                repo / ".beryl/policy/pass.yml",
                """
                version: 1
                policy_id: pass
                kind: repository
                change_scope:
                  - id: allow-work
                    allow:
                      - "src/**"
                      - ".beryl/policy/**"
                """,
            )
            write(repo / "src/domain/model.py", "x = 2\n")
            self.assertEqual(run_brpl(repo, "--policy", ".beryl/policy/pass.yml").returncode, 0)

            write(
                repo / ".beryl/policy/fail.yml",
                """
                version: 1
                policy_id: fail
                kind: repository
                change_scope:
                  - id: allow-tests
                    allow:
                      - "tests/**"
                """,
            )
            failed = run_brpl(repo, "--policy", ".beryl/policy/fail.yml", "--format", "json")
            self.assertEqual(failed.returncode, 1)
            self.assertIn('"rule_id": "allow-tests"', failed.stdout)

            write(
                repo / ".beryl/policy/bad.yml",
                """
                version: 1
                policy_id: bad
                kind: repository
                command: "echo should-not-exist"
                """,
            )
            bad = run_brpl(repo, "--policy", ".beryl/policy/bad.yml", "--format", "json")
            self.assertEqual(bad.returncode, 2)
            self.assertIn("unknown key", bad.stderr)

    def test_cli_rejects_json_report_inside_repo_root(self) -> None:
        with repo_fixture() as repo:
            write_policy(repo, "pass.yml", "pass", extra_required_id="unit-rule")
            result = run_brpl(
                repo,
                "--policy",
                ".beryl/policy/pass.yml",
                "--json-report",
                str(repo / "brpl-report.json"),
                "--format",
                "json",
                "--check-result",
                "unit=pass",
            )
            self.assertEqual(result.returncode, 2)
            self.assertIn("--json-report must be outside", result.stderr)

    def test_required_check_registry_is_strict_and_timeout_blocks(self) -> None:
        with repo_fixture() as repo:
            write(
                repo / ".beryl/policy/check.yml",
                """
                version: 1
                policy_id: checks
                kind: repository
                required_checks:
                  - id: require-unit
                    check: "unit"
                """,
            )
            policy = load_policy_file(repo / ".beryl/policy/check.yml")
            write(repo / ".beryl/policy/check-registry.json", json.dumps({"version": 1, "checks": []}))
            with self.assertRaises(BRPLConfigError):
                evaluate_policy_set(
                    [policy],
                    EvaluationConfig(
                        repo_root=repo,
                        base_ref="HEAD",
                        check_registry_path=repo / ".beryl/policy/check-registry.json",
                    ),
                )

            write(
                repo / ".beryl/policy/check-registry.json",
                json.dumps({"version": 1, "checks": [{"id": "unit", "command": [sys.executable, "-c", "pass"], "cwd": "", "timeout_seconds": 0}]}),
            )
            with self.assertRaisesRegex(BRPLConfigError, "timeout_seconds"):
                evaluate_policy_set(
                    [policy],
                    EvaluationConfig(repo_root=repo, base_ref="HEAD", check_registry_path=repo / ".beryl/policy/check-registry.json"),
                )

            write(
                repo / ".beryl/policy/check-registry.json",
                json.dumps(
                    {
                        "version": 1,
                        "extra": True,
                        "checks": [{"id": "unit", "command": [sys.executable, "-c", "pass"], "cwd": "", "timeout_seconds": 5}],
                    }
                ),
            )
            with self.assertRaisesRegex(BRPLConfigError, "unknown key"):
                evaluate_policy_set(
                    [policy],
                    EvaluationConfig(repo_root=repo, base_ref="HEAD", check_registry_path=repo / ".beryl/policy/check-registry.json"),
                )

            write(
                repo / ".beryl/policy/check-registry.json",
                '{"version":1,"checks":[{"id":"unit","id":"unit","command":["python"],"cwd":".","timeout_seconds":5}]}',
            )
            with self.assertRaisesRegex(BRPLConfigError, "duplicate JSON key"):
                evaluate_policy_set(
                    [policy],
                    EvaluationConfig(repo_root=repo, base_ref="HEAD", check_registry_path=repo / ".beryl/policy/check-registry.json"),
                )

            write(
                repo / ".beryl/policy/check-registry.json",
                json.dumps(
                    {
                        "version": 1,
                        "checks": [
                            {
                                "id": "unit",
                                "command": [sys.executable, "-c", "import time; time.sleep(2)"],
                                "cwd": "",
                                "timeout_seconds": 1,
                            }
                        ],
                    }
                ),
            )
            report = evaluate_policy_set(
                [policy],
                EvaluationConfig(repo_root=repo, base_ref="HEAD", check_registry_path=repo / ".beryl/policy/check-registry.json"),
            )
            self.assertFalse(report["ok"])
            self.assertEqual(report["check_results"]["unit"]["status"], "timeout")
            self.assertIn("timeout", report["violations"][0]["evidence"]["status"])

    def test_check_brpl_enforcement_off_and_enforce_requires_external_policy_pair(self) -> None:
        script = Path(__file__).resolve().parents[2] / "scripts" / "check-brpl.sh"
        off = subprocess.run(
            [str(script)],
            cwd=Path(__file__).resolve().parents[3],
            env={**os.environ, "BRPL_ENFORCEMENT": "off"},
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        self.assertEqual(off.returncode, 0)
        self.assertIn("BRPL_ENFORCEMENT=off", off.stdout)

        with tempfile.TemporaryDirectory() as policy_dir:
            policy_root = Path(policy_dir)
            repo_policy = policy_root / "repo.yml"
            task_policy = policy_root / "task.yml"
            check_registry = policy_root / "check-registry.json"
            write(
                repo_policy,
                """
                version: 1
                policy_id: external-repo
                kind: repository
                required_checks:
                  - id: require-unit
                    check: unit
                """,
            )
            write(task_policy, "version: 1\npolicy_id: external-task\nkind: task\n")
            write(
                check_registry,
                json.dumps(
                    {
                        "version": 1,
                        "checks": [
                            {
                                "id": "unit",
                                "command": [sys.executable, "-c", "pass"],
                                "cwd": "",
                                "timeout_seconds": 5,
                            }
                        ],
                    }
                ),
            )
            env = {
                **os.environ,
                "BRPL_ENFORCEMENT": "enforce",
                "BRPL_REPOSITORY_POLICY": str(repo_policy),
                "BRPL_TASK_POLICY": str(task_policy),
                "BRPL_CHECK_REGISTRY": str(check_registry),
                "BRPL_BASE_REF": "HEAD",
            }

            missing_registry_env = dict(env)
            missing_registry_env.pop("BRPL_CHECK_REGISTRY")
            missing_registry = subprocess.run(
                [str(script)],
                cwd=Path(__file__).resolve().parents[3],
                env=missing_registry_env,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
            )
            self.assertEqual(missing_registry.returncode, 2)
            self.assertIn("requires explicit BRPL_CHECK_REGISTRY", missing_registry.stderr)

            unreadable_registry = policy_root / "unreadable-registry.json"
            write(unreadable_registry, json.dumps({"version": 1, "checks": []}))
            unreadable_registry.chmod(0)
            try:
                unreadable = subprocess.run(
                    [str(script)],
                    cwd=Path(__file__).resolve().parents[3],
                    env={**env, "BRPL_CHECK_REGISTRY": str(unreadable_registry)},
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    check=False,
                )
            finally:
                unreadable_registry.chmod(0o600)
            self.assertEqual(unreadable.returncode, 2)
            self.assertIn("check registry is missing, not a regular file, or unreadable", unreadable.stderr)

            repo_local_registry = Path(__file__).resolve().parents[2] / "brpl/examples/check-registry.json"
            repo_local_registry_result = subprocess.run(
                [str(script)],
                cwd=Path(__file__).resolve().parents[3],
                env={**env, "BRPL_CHECK_REGISTRY": str(repo_local_registry)},
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
            )
            self.assertEqual(repo_local_registry_result.returncode, 2)
            self.assertIn("check registry must be outside the evaluated repository", repo_local_registry_result.stderr)

            enforce = subprocess.run(
                [str(script)],
                cwd=Path(__file__).resolve().parents[3],
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
            )
            self.assertEqual(enforce.returncode, 0, enforce.stderr)

            missing_task = subprocess.run(
                [str(script)],
                cwd=Path(__file__).resolve().parents[3],
                env={**env, "BRPL_TASK_POLICY": str(policy_root / "missing-task.yml")},
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
            )
            self.assertEqual(missing_task.returncode, 2)
            self.assertIn("missing or unreadable", missing_task.stderr)

            write(task_policy, "version: 1\npolicy_id: wrong-kind\nkind: repository\n")
            wrong_kind = subprocess.run(
                [str(script)],
                cwd=Path(__file__).resolve().parents[3],
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
            )
            self.assertEqual(wrong_kind.returncode, 2)
            self.assertIn("expected 'task'", wrong_kind.stderr)

            repo_local_policy = Path(__file__).resolve().parents[2] / "brpl/examples/brpl.repository.yml"
            repo_local = subprocess.run(
                [str(script)],
                cwd=Path(__file__).resolve().parents[3],
                env={**env, "BRPL_REPOSITORY_POLICY": str(repo_local_policy)},
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
            )
            self.assertEqual(repo_local.returncode, 2)
            self.assertIn("must be outside the evaluated repository", repo_local.stderr)


class repo_fixture:
    def __enter__(self) -> Path:
        self._tmp = tempfile.TemporaryDirectory()
        repo = Path(self._tmp.name)
        (repo / ".beryl/policy").mkdir(parents=True)
        (repo / "src/domain").mkdir(parents=True)
        (repo / "src/infrastructure").mkdir(parents=True)
        (repo / "tests/regression").mkdir(parents=True)
        (repo / "generated").mkdir(parents=True)
        write(repo / "src/domain/model.py", "x = 1\n")
        write(repo / "src/infrastructure/db.py", "x = 1\n")
        write(repo / "tests/regression/test_contract.py", "def test_contract(): pass\n")
        write(
            repo / "pyproject.toml",
            """
            [project]
            name = "demo"
            version = "0.1.0"
            dependencies = []
            """,
        )
        git(repo, "init", "-b", "main")
        git(repo, "add", ".")
        git(repo, "-c", "user.name=Test", "-c", "user.email=test@example.invalid", "commit", "-m", "base")
        self.repo = repo
        return repo

    def __exit__(self, exc_type, exc, tb) -> None:
        self._tmp.cleanup()


def write_policy(repo: Path, name: str, policy_id: str, *, kind: str = "repository", extra_required_id: str) -> None:
    write(
        repo / ".beryl/policy" / name,
        f"""
        version: 1
        policy_id: {policy_id}
        kind: {kind}
        required_checks:
          - id: {extra_required_id}
            check: unit
        """,
    )


def write_arch_policy(repo: Path) -> None:
    write(
        repo / ".beryl/policy/arch.yml",
        """
        version: 1
        policy_id: arch
        kind: repository
        architecture:
          forbid_imports:
            - id: no-domain-infra
              from: "src/domain/**"
              to: "src/infrastructure/**"
        """,
    )


def write(path: Path, content: str) -> None:
    write_raw(path, textwrap.dedent(content).lstrip().encode("utf-8"))


def write_raw(path: Path, content: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content)


def git(repo: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(["git", *args], cwd=repo, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)


def run_brpl(repo: Path, *args: str) -> subprocess.CompletedProcess[str]:
    beryl_root = Path(__file__).resolve().parents[2]
    return subprocess.run(
        [sys.executable, "-m", "brpl", "--repo-root", str(repo), "--base", "HEAD", *args],
        cwd=repo,
        env={**os.environ, "PYTHONPATH": str(beryl_root), "PYTHONDONTWRITEBYTECODE": "1"},
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )


if __name__ == "__main__":
    unittest.main()
