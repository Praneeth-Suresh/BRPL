"""Prospective BRPL v2 validation and pure evaluation API.

This package is intentionally side-by-side with the frozen BRPL v1 API.  It is
not wired into the production gate until the prospective design is amended into
the protocol.
"""

from .core import (
    BRPLV2Error,
    LintContext,
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

__all__ = [
    "BRPLV2Error",
    "LintContext",
    "evaluate_policy_set",
    "hash_candidate_tree",
    "lint_policy_set",
    "load_evidence_file",
    "load_policy_file",
    "load_test_file",
    "run_policy_tests",
    "validate_evidence",
    "validate_policy",
]
