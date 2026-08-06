"""Active BRPL v2 validation, evidence evaluation, and gate API."""

from .core import BRPLV2Error, LintContext, REMEDIATION_CLASSES, evaluate_policy_set, hash_candidate_tree, lint_policy_set, load_evidence_file, load_policy_file, load_test_file, run_policy_tests, validate_evidence, validate_policy
from .runtime import BRPLConfigError, BRPLEvaluationError, CHECKER_VERSION, EvaluationConfig, evaluate_policy_set as evaluate_repository, report_to_human, report_to_json

__all__ = [
    "BRPLV2Error", "BRPLConfigError", "BRPLEvaluationError", "CHECKER_VERSION",
    "EvaluationConfig", "LintContext", "REMEDIATION_CLASSES", "evaluate_policy_set",
    "evaluate_repository", "hash_candidate_tree", "lint_policy_set", "load_evidence_file",
    "load_policy_file", "load_test_file", "run_policy_tests", "report_to_human",
    "report_to_json", "validate_evidence", "validate_policy",
]
