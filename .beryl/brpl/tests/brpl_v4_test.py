from __future__ import annotations

import hashlib
import json
import subprocess
import tempfile
import unittest
from unittest.mock import patch
from pathlib import Path

from brpl.v4 import BRPLCompileError, BRPLVerificationError, compile_policies, evaluate_plan, load_catalog, parse_policy
from brpl.v4.cli import main as cli_main


HASH = "a" * 64
ROOT = Path(__file__).resolve().parents[1]


def catalog() -> dict[str, object]:
    return {"schema": "brpl-adapter-catalog/v4", "adapters": [
        {"id": "changes", "kind": "changes", "binding": "trusted.git.v1", "digest": "1" * 64, "public_summary": "Candidate changes"},
        {"id": "imports", "kind": "relation", "binding": "trusted.graph.v1", "digest": "2" * 64, "public_summary": "Complete import graph", "relation": "imports", "source_universe": "candidate-files", "target_universe": "candidate-files", "completeness": "complete"},
        {"id": "manifest", "kind": "manifest", "binding": "trusted.manifest.v1", "digest": "3" * 64, "public_summary": "Direct dependencies"},
        {"id": "tests", "kind": "check", "binding": "trusted.tests.v1", "digest": "4" * 64, "public_summary": "Tests pass"},
        {"id": "complexity", "kind": "metric", "binding": "trusted.metrics.v1", "digest": "5" * 64, "public_summary": "Maximum complexity"},
    ]}


def policy(rules: list[dict[str, object]], components: list[dict[str, object]] | None = None) -> dict[str, object]:
    result: dict[str, object] = {"schema": "brpl-policy/v4", "kind": "repository", "id": "repo", "repository": {"name": "Repository", "root": "."}, "areas": [{"id": "app", "paths": ["src/app/**"]}, {"id": "db", "paths": ["src/db/**"]}], "rules": rules}
    if components is not None: result["components"] = components
    return result


def evidence(graphs: list[dict[str, object]] | None = None, metrics: list[dict[str, object]] | None = None) -> dict[str, object]:
    return {"schema": "brpl-evidence/v4", "candidate_tree": {"sha256": HASH}, "baseline": {"sha256": HASH}, "changes": [], "graphs": graphs or [], "manifest_deltas": [], "checks": [], "metrics": metrics or []}


def graph(edges: list[dict[str, str]], completeness: str = "complete") -> dict[str, object]:
    return {"relation": "imports", "source_universe": "candidate-files", "target_universe": "candidate-files", "completeness": completeness, "adapter_binding": "trusted.graph.v1", "candidate_tree_sha256": HASH, "edges": edges}


class BRPLV4Test(unittest.TestCase):
    def test_explicit_v4_compiles_existing_and_graph_rule_families(self) -> None:
        plan = compile_policies([policy([
            {"id": "SCOPE-001", "kind": "changes", "mode": "only", "selectors": ["@app"]},
            {"id": "PATH-001", "kind": "protect", "selectors": ["README.md"]},
            {"id": "GEN-001", "kind": "generated", "selectors": ["generated/**"]},
            {"id": "EDGE-001", "kind": "forbid-edge", "relation": "imports", "from": "app", "to": "db"},
            {"id": "PATH-002", "kind": "forbid-path", "relation": "imports", "from": "app", "to": "db"},
            {"id": "CYCLE-001", "kind": "acyclic", "relation": "imports"},
            {"id": "DEP-001", "kind": "dependencies", "manifest": "manifest"},
            {"id": "CHECK-001", "kind": "require", "check": "tests", "summary": "Tests pass"},
            {"id": "METRIC-001", "kind": "threshold", "metric": "complexity", "operator": "at-most", "value": "10.25", "unit": "branches", "summary": "Maximum complexity"},
        ])], catalog())
        self.assertEqual(plan["schema"], "brpl-plan/v4")
        self.assertEqual(len(plan["rules"]), 9)
        self.assertIn("semantic_sha256", plan)

    def test_direct_and_transitive_graph_rules_report_concrete_evidence(self) -> None:
        direct = compile_policies([policy([{"id": "EDGE-001", "kind": "forbid-edge", "relation": "imports", "from": "@app", "to": "@db"}])], catalog())
        transitive = compile_policies([policy([{"id": "PATH-001", "kind": "forbid-path", "relation": "imports", "from": "@app", "to": "@db"}])], catalog())
        facts = graph([{"source": "src/app/a", "target": "src/mid/m"}, {"source": "src/mid/m", "target": "src/db/b"}, {"source": "src/app/direct", "target": "src/db/b"}])
        self.assertEqual(evaluate_plan(direct, evidence([facts]))["violations"][0]["evidence"]["type"], "graph_edge")
        report = evaluate_plan(transitive, evidence([facts]))
        self.assertIn(["src/app/a", "src/mid/m", "src/db/b"], [item["evidence"]["path"] for item in report["violations"]])

    def test_component_adjacency_and_acyclic_rules(self) -> None:
        components = [{"id": "application", "paths": ["src/app/**"]}, {"id": "database", "paths": ["src/db/**"]}]
        plan = compile_policies([policy([{"id": "COMP-001", "kind": "component-adjacency", "relation": "imports", "allowed": []}, {"id": "CYCLE-001", "kind": "acyclic", "relation": "imports"}], components)], catalog())
        report = evaluate_plan(plan, evidence([graph([{"source": "src/app/a", "target": "src/db/b"}, {"source": "src/db/b", "target": "src/app/a"}])]))
        self.assertEqual({item["rule_id"] for item in report["violations"]}, {"COMP-001", "CYCLE-001"})

    def test_graph_coverage_and_adapter_binding_fail_closed(self) -> None:
        plan = compile_policies([policy([{"id": "EDGE-001", "kind": "forbid-edge", "relation": "imports", "from": "app", "to": "db"}])], catalog())
        report = evaluate_plan(plan, evidence([graph([], "partial")]))
        self.assertFalse(report["ok"])
        self.assertEqual(report["rules"][0]["status"], "indeterminate")
        self.assertEqual(report["errors"][0]["evidence"]["code"], "V416")

    def test_exact_decimal_threshold_reports_value_threshold_unit_and_distance(self) -> None:
        plan = compile_policies([policy([{"id": "METRIC-001", "kind": "threshold", "metric": "complexity", "operator": "at-most", "value": "1.10", "unit": "branches", "summary": "Maximum complexity"}])], catalog())
        passing = evidence(metrics=[{"metric": "complexity", "value": "1.10", "unit": "branches", "candidate_tree_sha256": HASH}])
        self.assertTrue(evaluate_plan(plan, passing)["ok"])
        failing = evidence(metrics=[{"metric": "complexity", "value": "1.11", "unit": "branches", "candidate_tree_sha256": HASH}])
        fact = evaluate_plan(plan, failing)["violations"][0]["evidence"]
        self.assertEqual({key: fact[key] for key in ("value", "threshold", "unit", "distance")}, {"value": "1.11", "threshold": "1.10", "unit": "branches", "distance": "0.01"})

    def test_report_catalog_includes_satisfied_and_indeterminate_rules(self) -> None:
        plan = compile_policies([policy([{"id": "PATH-001", "kind": "protect", "selectors": ["README.md"]}, {"id": "EDGE-001", "kind": "forbid-edge", "relation": "imports", "from": "app", "to": "db"}])], catalog())
        report = evaluate_plan(plan, evidence())
        self.assertEqual([item["status"] for item in report["rules"]], ["indeterminate", "satisfied"])
        self.assertEqual(report["rules"][0]["policy_class"], "architecture.direct_edge")

    def test_untrusted_policy_code_and_bad_graph_evidence_are_rejected(self) -> None:
        with self.assertRaisesRegex(BRPLCompileError, "E404"):
            parse_policy({**policy([]), "execute": ["rm", "-rf"]})
        plan = compile_policies([policy([{"id": "EDGE-001", "kind": "forbid-edge", "relation": "imports", "from": "app", "to": "db"}])], catalog())
        bad = evidence([{"relation": "imports", "edges": []}])
        with self.assertRaises(BRPLVerificationError): evaluate_plan(plan, bad)

    def test_v4_is_explicit_and_does_not_change_legacy_default(self) -> None:
        from brpl import CHECKER_VERSION
        self.assertEqual(CHECKER_VERSION, "2.0.0")
        self.assertEqual(compile_policies([policy([])], catalog())["brpl_version"], 4)

    def test_enforce_mode_requires_external_authority_and_detects_launch_tampering(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            outer = Path(temporary); root = outer / "candidate"; root.mkdir(); (root / "app.txt").write_text("candidate", encoding="utf-8")
            policy_path = outer / "policy.json"; catalog_path = outer / "catalog.json"; evidence_path = outer / "evidence.json"; adapter = outer / "adapter"; checker = outer / "checker"; baseline = outer / "baseline"; evaluator = outer / "evaluator"
            for file in (adapter, checker, baseline, evaluator): file.write_text(file.name, encoding="utf-8")
            policy_path.write_text(json.dumps(policy([])), encoding="utf-8"); catalog_path.write_text(json.dumps(catalog()), encoding="utf-8")
            tree = __import__("brpl.v4.cli", fromlist=["_tree_hash"])._tree_hash(root)
            evidence_path.write_text(json.dumps({**evidence(), "candidate_tree": {"sha256": tree}}), encoding="utf-8")
            launch_path = outer / "launch.json"
            pin = lambda label, path: {"id": label, "path": str(path), "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
            launch = {"schema": "brpl-launch-manifest/v4", "catalog": pin("catalog", catalog_path), "policies": [pin("policy", policy_path)], "capabilities": [], "adapter_bundle": pin("adapter", adapter), "checker": pin("checker", checker), "baseline": pin(HASH, baseline), "evaluator": pin("evaluator", evaluator)}
            launch_path.write_text(json.dumps(launch), encoding="utf-8")
            self.assertEqual(cli_main(["--repo-root", str(root), "--policy", str(policy_path), "--catalog", str(catalog_path), "--evidence", str(evidence_path), "--enforce", "--launch-manifest", str(launch_path)]), 0)
            launch["checker"]["sha256"] = "0" * 64; launch_path.write_text(json.dumps(launch), encoding="utf-8")
            self.assertEqual(cli_main(["--repo-root", str(root), "--policy", str(policy_path), "--catalog", str(catalog_path), "--evidence", str(evidence_path), "--enforce", "--launch-manifest", str(launch_path)]), 2)

    def test_enforce_mode_blocks_candidate_substitution_during_evaluation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            outer = Path(temporary); root = outer / "candidate"; root.mkdir(); candidate_file = root / "app.txt"; candidate_file.write_text("before", encoding="utf-8")
            policy_path = outer / "policy.json"; catalog_path = outer / "catalog.json"; evidence_path = outer / "evidence.json"; launch_path = outer / "launch.json"
            policy_path.write_text(json.dumps(policy([])), encoding="utf-8"); catalog_path.write_text(json.dumps(catalog()), encoding="utf-8")
            tree = __import__("brpl.v4.cli", fromlist=["_tree_hash"])._tree_hash(root); evidence_path.write_text(json.dumps({**evidence(), "candidate_tree": {"sha256": tree}}), encoding="utf-8")
            authorities = []
            for name in ("adapter", "checker", "baseline", "evaluator"):
                path = outer / name; path.write_text(name, encoding="utf-8"); authorities.append(path)
            pin = lambda label, path: {"id": label, "path": str(path), "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
            launch_path.write_text(json.dumps({"schema": "brpl-launch-manifest/v4", "catalog": pin("catalog", catalog_path), "policies": [pin("policy", policy_path)], "capabilities": [], "adapter_bundle": pin("adapter", authorities[0]), "checker": pin("checker", authorities[1]), "baseline": pin(HASH, authorities[2]), "evaluator": pin("evaluator", authorities[3])}), encoding="utf-8")
            from brpl.v4 import cli
            original = cli.evaluate_plan
            def mutate(plan: dict[str, object], observed: dict[str, object]) -> dict[str, object]:
                candidate_file.write_text("after", encoding="utf-8")
                return original(plan, observed)
            with patch("brpl.v4.cli.evaluate_plan", mutate):
                self.assertEqual(cli_main(["--repo-root", str(root), "--policy", str(policy_path), "--catalog", str(catalog_path), "--evidence", str(evidence_path), "--enforce", "--launch-manifest", str(launch_path)]), 2)

    def test_enforce_mode_rejects_candidate_controlled_evidence_file(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            outer = Path(temporary); root = outer / "candidate"; root.mkdir(); (root / "app.txt").write_text("candidate", encoding="utf-8")
            policy_path = outer / "policy.json"; catalog_path = outer / "catalog.json"; evidence_path = root / "evidence.json"; launch_path = outer / "launch.json"; report_path = outer / "report.json"
            policy_path.write_text(json.dumps(policy([])), encoding="utf-8"); catalog_path.write_text(json.dumps(catalog()), encoding="utf-8")
            tree = __import__("brpl.v4.cli", fromlist=["_tree_hash"])._tree_hash(root); evidence_path.write_text(json.dumps({**evidence(), "candidate_tree": {"sha256": tree}}), encoding="utf-8")
            authorities = []
            for name in ("adapter", "checker", "baseline", "evaluator"):
                path = outer / name; path.write_text(name, encoding="utf-8"); authorities.append(path)
            pin = lambda label, path: {"id": label, "path": str(path), "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
            launch_path.write_text(json.dumps({"schema": "brpl-launch-manifest/v4", "catalog": pin("catalog", catalog_path), "policies": [pin("policy", policy_path)], "capabilities": [], "adapter_bundle": pin("adapter", authorities[0]), "checker": pin("checker", authorities[1]), "baseline": pin(HASH, authorities[2]), "evaluator": pin("evaluator", authorities[3])}), encoding="utf-8")
            self.assertEqual(cli_main(["--repo-root", str(root), "--policy", str(policy_path), "--catalog", str(catalog_path), "--evidence", str(evidence_path), "--enforce", "--launch-manifest", str(launch_path), "--json-report", str(report_path)]), 2)
            self.assertEqual(json.loads(report_path.read_text(encoding="utf-8"))["outcome"], "blocked_evaluation_error")

    def test_dependency_rule_fails_closed_without_complete_manifest_evidence(self) -> None:
        plan = compile_policies([policy([{"id": "DEP-001", "kind": "dependencies", "manifest": "manifest"}])], catalog())
        absent = evaluate_plan(plan, evidence())
        self.assertEqual((absent["rules"][0]["status"], absent["errors"][0]["evidence"]["code"]), ("indeterminate", "V419"))
        incomplete = evaluate_plan(plan, {**evidence(), "manifest_deltas": [{"manifest": "manifest", "added": [], "removed": [], "completeness": "indeterminate", "candidate_tree_sha256": HASH}]})
        self.assertEqual((incomplete["rules"][0]["status"], incomplete["errors"][0]["evidence"]["code"]), ("indeterminate", "V420"))
        duplicate = evaluate_plan(plan, {**evidence(), "manifest_deltas": [{"manifest": "manifest", "added": [], "removed": [], "completeness": "complete", "candidate_tree_sha256": HASH}, {"manifest": "manifest", "added": [], "removed": [], "completeness": "complete", "candidate_tree_sha256": HASH}]})
        self.assertEqual((duplicate["rules"][0]["status"], duplicate["errors"][0]["evidence"]["code"]), ("indeterminate", "V419"))

    def test_enforce_mode_requires_capability_artifact_to_match_catalog_digest(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            outer = Path(temporary); root = outer / "candidate"; root.mkdir(); (root / "app.txt").write_text("candidate", encoding="utf-8")
            policy_value = policy([{"id": "EDGE-001", "kind": "forbid-edge", "relation": "imports", "from": "@app", "to": "@db"}]); catalog_value = catalog(); trusted = ROOT / "v4" / "adapters" / "python_static.py"
            relation = next(item for item in catalog_value["adapters"] if item["id"] == "imports"); relation["digest"] = hashlib.sha256(trusted.read_bytes()).hexdigest(); relation["binding"] = "brpl.v4.adapters.python-static.v1"
            policy_path = outer / "policy.json"; catalog_path = outer / "catalog.json"; evidence_path = outer / "evidence.json"; launch_path = outer / "launch.json"; mismatched = outer / "different-adapter"; mismatched.write_text("not the trusted artifact", encoding="utf-8")
            policy_path.write_text(json.dumps(policy_value), encoding="utf-8"); catalog_path.write_text(json.dumps(catalog_value), encoding="utf-8")
            tree = __import__("brpl.v4.cli", fromlist=["_tree_hash"])._tree_hash(root); evidence_path.write_text(json.dumps({**evidence([ {**graph([]), "adapter_binding": "brpl.v4.adapters.python-static.v1"} ]), "candidate_tree": {"sha256": tree}}), encoding="utf-8")
            authorities = []
            for name in ("adapter-bundle", "checker", "baseline", "evaluator"):
                path = outer / name; path.write_text(name, encoding="utf-8"); authorities.append(path)
            pin = lambda label, path: {"id": label, "path": str(path), "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
            launch_path.write_text(json.dumps({"schema": "brpl-launch-manifest/v4", "catalog": pin("catalog", catalog_path), "policies": [pin("policy", policy_path)], "capabilities": [pin("imports", mismatched)], "adapter_bundle": pin("adapter-bundle", authorities[0]), "checker": pin("checker", authorities[1]), "baseline": pin(HASH, authorities[2]), "evaluator": pin("evaluator", authorities[3])}), encoding="utf-8")
            self.assertEqual(cli_main(["--repo-root", str(root), "--policy", str(policy_path), "--catalog", str(catalog_path), "--evidence", str(evidence_path), "--enforce", "--launch-manifest", str(launch_path)]), 2)

    def test_python_adapter_is_a_separate_pinned_artifact(self) -> None:
        from brpl.v4.adapters import adapter_artifact_digest
        artifact = ROOT / "v4" / "adapters" / "python_static.py"
        self.assertEqual(adapter_artifact_digest("python-evidence-bundle"), hashlib.sha256(artifact.read_bytes()).hexdigest())
        core = (ROOT / "v4" / "compiler.py").read_text(encoding="utf-8") + (ROOT / "v4" / "runtime.py").read_text(encoding="utf-8")
        self.assertNotIn("brpl.v4.adapters", core)
        self.assertNotIn("from ..v2", core)
        self.assertNotIn("import ast", core)

    def test_python_evidence_bundle_normalizes_changes_graph_manifest_and_fixed_checks(self) -> None:
        from brpl.v4.adapters.python_static import collect
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); subprocess.run(["git", "init", "-q", str(root)], check=True); subprocess.run(["git", "-C", str(root), "config", "user.email", "test@example.invalid"], check=True); subprocess.run(["git", "-C", str(root), "config", "user.name", "Test"], check=True)
            (root / "pkg").mkdir(); (root / "pkg" / "__init__.py").write_text("", encoding="utf-8"); (root / "pkg" / "a.py").write_text("from . import b\nfrom .b import VALUE\n", encoding="utf-8"); (root / "pkg" / "b.py").write_text("VALUE = 1\n", encoding="utf-8"); (root / "pyproject.toml").write_text("[project]\ndependencies = ['one>=1']\n", encoding="utf-8")
            subprocess.run(["git", "-C", str(root), "add", "."], check=True); subprocess.run(["git", "-C", str(root), "commit", "-qm", "baseline"], check=True)
            (root / "pyproject.toml").write_text("[project]\ndependencies = ['one>=1', 'two>=2']\n", encoding="utf-8")
            observed = collect(root, "HEAD", [{"check": "unit", "status": "pass"}])
            self.assertEqual(observed["graphs"][0]["completeness"], "complete")
            self.assertIn({"source": "pkg/a.py", "target": "pkg/b.py"}, observed["graphs"][0]["edges"])
            self.assertEqual(observed["manifest_deltas"][0]["added"], ["two>=2"])
            self.assertEqual(observed["checks"][0]["candidate_tree_sha256"], observed["candidate_tree"]["sha256"])
            policy_value = policy([{"id": "EDGE-001", "kind": "forbid-edge", "relation": "imports", "from": "pkg/a.py", "to": "pkg/b.py"}])
            catalog_value = catalog(); relation = next(item for item in catalog_value["adapters"] if item["id"] == "imports"); relation.update({"binding": "brpl.v4.adapters.python-evidence-bundle.v1", "source_universe": "candidate-static-python-files", "target_universe": "candidate-static-python-files"})
            self.assertFalse(evaluate_plan(compile_policies([policy_value], catalog_value), observed)["ok"])

    def test_unresolved_relative_import_fails_complete_static_extraction(self) -> None:
        from brpl.v4.adapters.python_static import _imports
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); (root / "pkg").mkdir(); (root / "pkg" / "__init__.py").write_text("", encoding="utf-8"); (root / "pkg" / "a.py").write_text("from . import missing\n", encoding="utf-8")
            with self.assertRaisesRegex(RuntimeError, "cannot resolve local relative import"):
                _imports(root)

    def test_tree_hash_covers_untracked_mode_and_symlink_without_following(self) -> None:
        from brpl.v4.tree import candidate_tree_hash
        from brpl.v4.cli import _tree_hash
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); file = root / "tracked"; file.write_text("same", encoding="utf-8"); first = candidate_tree_hash(root)
            file.chmod(0o755); self.assertNotEqual(first, candidate_tree_hash(root)); (root / "untracked").write_text("new", encoding="utf-8"); second = candidate_tree_hash(root)
            (root / "link").symlink_to("/outside/does-not-need-to-exist"); self.assertNotEqual(second, candidate_tree_hash(root)); self.assertEqual(candidate_tree_hash(root), _tree_hash(root))

    def test_changes_include_untracked_rename_delete_mode_and_symlink(self) -> None:
        from brpl.v4.adapters.python_static import _changes
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); subprocess.run(["git", "init", "-q", str(root)], check=True); subprocess.run(["git", "-C", str(root), "config", "user.email", "test@example.invalid"], check=True); subprocess.run(["git", "-C", str(root), "config", "user.name", "Test"], check=True)
            (root / "old").write_text("old", encoding="utf-8"); (root / "delete").write_text("delete", encoding="utf-8"); (root / "mode").write_text("mode", encoding="utf-8"); (root / "link").symlink_to("old")
            subprocess.run(["git", "-C", str(root), "add", "."], check=True); subprocess.run(["git", "-C", str(root), "commit", "-qm", "baseline"], check=True)
            (root / "old").rename(root / "renamed"); (root / "delete").unlink(); (root / "mode").chmod(0o755); (root / "link").unlink(); (root / "link").symlink_to("renamed"); subprocess.run(["git", "-C", str(root), "add", "-A"], check=True); (root / "untracked").write_text("untracked", encoding="utf-8")
            observed = _changes(root, "HEAD")
            self.assertIn("untracked", {item["change_kind"] for item in observed}); self.assertIn("delete", {item["change_kind"] for item in observed}); self.assertIn("mode", {item["change_kind"] for item in observed}); self.assertIn("symlink", {item["change_kind"] for item in observed}); self.assertTrue(any(item.get("old_path") == "old" and item["path"] == "renamed" for item in observed))

    def test_required_manifest_and_ambiguous_candidate_modules_fail_extraction(self) -> None:
        from brpl.v4.adapters.python_static import _imports, collect
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); subprocess.run(["git", "init", "-q", str(root)], check=True); subprocess.run(["git", "-C", str(root), "config", "user.email", "test@example.invalid"], check=True); subprocess.run(["git", "-C", str(root), "config", "user.name", "Test"], check=True); (root / "x").mkdir(); (root / "y").mkdir(); (root / "a.py").write_text("import b\n", encoding="utf-8"); (root / "x" / "b.py").write_text("", encoding="utf-8"); (root / "y" / "b.py").write_text("", encoding="utf-8"); subprocess.run(["git", "-C", str(root), "add", "."], check=True); subprocess.run(["git", "-C", str(root), "commit", "-qm", "baseline"], check=True)
            with self.assertRaisesRegex(RuntimeError, "required candidate pyproject"):
                collect(root, "HEAD")
            with self.assertRaisesRegex(RuntimeError, "ambiguous candidate module"):
                _imports(root)

    def test_bundle_rejects_unflagged_invalid_candidate_and_missing_baseline_manifest(self) -> None:
        from brpl.v4.adapters.python_static import collect
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); subprocess.run(["git", "init", "-q", str(root)], check=True); subprocess.run(["git", "-C", str(root), "config", "user.email", "test@example.invalid"], check=True); subprocess.run(["git", "-C", str(root), "config", "user.name", "Test"], check=True); (root / "pyproject.toml").write_text("not = [valid", encoding="utf-8"); subprocess.run(["git", "-C", str(root), "add", "."], check=True); subprocess.run(["git", "-C", str(root), "commit", "-qm", "baseline"], check=True)
            with self.assertRaisesRegex(RuntimeError, "invalid candidate"):
                collect(root, "HEAD")
            (root / "pyproject.toml").write_text("[project]\ndependencies=[]\n", encoding="utf-8")
            subprocess.run(["git", "-C", str(root), "rm", "-q", "--cached", "pyproject.toml"], check=True); subprocess.run(["git", "-C", str(root), "commit", "-qm", "remove manifest"], check=True)
            with self.assertRaisesRegex(RuntimeError, "required baseline"):
                collect(root, "HEAD")

    def test_v4_schemas_mirror_closed_policy_and_graph_evidence_keys(self) -> None:
        policy_schema = json.loads((ROOT / "schemas" / "brpl-v4-policy.schema.json").read_text(encoding="utf-8")); evidence_schema = json.loads((ROOT / "schemas" / "brpl-v4-evidence.schema.json").read_text(encoding="utf-8"))
        self.assertFalse(policy_schema["additionalProperties"]); self.assertIn("repository", policy_schema["properties"]); self.assertIn("threshold", policy_schema["properties"]["rules"]["items"]["properties"]["kind"]["enum"])
        graph = evidence_schema["properties"]["graphs"]["items"]; self.assertFalse(graph["additionalProperties"]); self.assertEqual(set(graph["required"]), {"relation", "source_universe", "target_universe", "completeness", "adapter_binding", "candidate_tree_sha256", "edges"})


if __name__ == "__main__": unittest.main()
