# ADR 0009: Use a Host-Neutral BRPL v4 Verifier with Complete Graph Evidence

## Status

Accepted prospectively on 2026-08-11; v4 is not selected by the legacy CLI and is not authorized for confirmatory execution until the project protocol gates are complete.

## Context

The existing BRPL versions are valuable compatibility artifacts, but their shipped extraction path is Python-oriented and cannot express transitive architecture constraints, component adjacency, acyclicity, or typed quantitative boundaries without overloading a general required check.

## Decision

Add an explicitly selected BRPL v4 strict JSON language and a host-neutral compiler/verifier that accepts only finite normalized evidence and never imports a language AST, package-manifest parser, legacy runtime, adapter code, or policy-defined command; expose reviewed language extraction only through separate named adapter-driver modules whose artifact digests an external catalog pins.

Add finite direct-edge, reachability, component-adjacency, acyclicity, dependency-delta, required-check, path, and exact-decimal threshold predicates; graph predicates require complete candidate-bound evidence that declares relation, endpoint universes, completeness, and adapter binding.

Keep adapter identities and digests in an external catalog, and require an external launch manifest in v4 enforcement mode to pin catalog, policy, adapter bundle, checker, baseline, and evaluator artifacts before and after evaluation.

## Consequences

- BRPL v4 can express stronger repository-state and architectural constraints without becoming an executable expression language.
- Adapter coverage remains an empirical external contract, not a theorem of the language core.
- v1–v3 and the generic v2 CLI remain unchanged, preserving historical runs and default installations.
- Policy authors must use the external canonical policy-generation workflow to establish parity with natural-language guidance.
