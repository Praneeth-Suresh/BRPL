from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from brpl.v4 import BRPLCompileError, BRPLVerificationError, compile_policies, evaluate_plan, load_catalog, parse_policy
from brpl.v4.cli import main as cli_main


HASH = "a" * 64


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
    return {"schema": "brpl-evidence/v4", "candidate_tree": {"sha256": HASH}, "changes": [], "graphs": graphs or [], "manifest_deltas": [], "checks": [], "metrics": metrics or []}


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
            launch = {"schema": "brpl-launch-manifest/v4", "catalog": pin("catalog", catalog_path), "policies": [pin("policy", policy_path)], "adapter_bundle": pin("adapter", adapter), "checker": pin("checker", checker), "baseline": pin("baseline", baseline), "evaluator": pin("evaluator", evaluator)}
            launch_path.write_text(json.dumps(launch), encoding="utf-8")
            self.assertEqual(cli_main(["--repo-root", str(root), "--policy", str(policy_path), "--catalog", str(catalog_path), "--evidence", str(evidence_path), "--enforce", "--launch-manifest", str(launch_path)]), 0)
            launch["checker"]["sha256"] = "0" * 64; launch_path.write_text(json.dumps(launch), encoding="utf-8")
            self.assertEqual(cli_main(["--repo-root", str(root), "--policy", str(policy_path), "--catalog", str(catalog_path), "--evidence", str(evidence_path), "--enforce", "--launch-manifest", str(launch_path)]), 2)


if __name__ == "__main__": unittest.main()
