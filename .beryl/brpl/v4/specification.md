# BRPL v4 Language Specification

BRPL v4 source is strict JSON with schema identifier `brpl-policy/v4`; duplicate keys, unknown keys, executable fields, and invalid field types are errors.

One policy has `kind` `repository` or `task`, a stable `id`, optional `areas` and `components`, and an ordered-insensitive `rules` array; a repository policy additionally has one `repository` object, while a task policy must not have one.

The compiler requires exactly one repository policy and zero or more unique task policies, combines every rule conjunctively, sorts canonical plan objects, and produces `brpl-plan/v4` with a semantic SHA-256 digest.

Each rule has a stable uppercase `id`, a `kind`, and optional enforcement severity `error` or `warning`; evaluator severity is intentionally external metadata rather than a policy mechanism for compensating violations.

`changes` accepts `mode` `only` or `deny` plus repository selectors; `protect` and `generated` reject any matching final diff evidence.

`forbid-edge` rejects a directly observed graph edge between source and target selectors, while `forbid-path` rejects any directed reachable path between them.

`component-adjacency` maps evidence endpoints to declared components and rejects cross-component edges not in its finite allowed-pair list; `acyclic` reports concrete directed cycles, optionally within selected paths.

`dependencies` compares trusted direct manifest deltas against finite allow-add and allow-remove sets, and `require` demands a candidate-bound passing result with its declared public summary.

`threshold` compares an exact integer or decimal-string metric value using only `at-most` or `at-least`; it declares the metric identifier, unit, value, and public summary, and a violation reports the value, threshold, unit, and distance.

An adapter catalog has schema `brpl-adapter-catalog/v4` and only contains declarative bindings with identifiers, digests, and public summaries; relation bindings additionally declare the relation, source universe, target universe, and `complete` or `partial` catalog coverage.

Graph evidence has schema `brpl-evidence/v4` and each graph declares its relation, source universe, target universe, completeness status, adapter binding, candidate-tree SHA-256, and finite edge list; graph rules fail closed if a matching graph is absent, partial, indeterminate, mismatched, or not bound to the candidate tree.

The report has schema `brpl-report/v4` and contains every evaluated rule in `rules`, including policy identity, policy class, enforcement severity, applicability, status, and remediation; `findings`, `violations`, and `errors` provide stable attributable evidence.

Enforcement mode requires externally located policy, catalog, and launch-manifest artifacts; the launch manifest pins the catalog, policies, adapter bundle, checker, baseline, and evaluator identities and digests, which the CLI verifies before and after candidate-bound evaluation.
