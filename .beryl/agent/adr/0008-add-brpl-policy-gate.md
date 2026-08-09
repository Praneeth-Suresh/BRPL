# ADR 0008: Add Opt-In BRPL Policy Gate

## Status

Accepted

## Context

Beryl already provides natural-language repository contracts and deterministic checks, but repository constraints such as protected paths, change scope, architecture boundaries, dependency additions, and required checks are not expressed through one machine-readable gate.

## Decision

Add Beryl Repository Policy Language v1 under `.beryl/brpl/` and expose it through `.beryl/scripts/check-brpl.sh`. The aggregate check gate invokes this wrapper, but the wrapper exits successfully when no BRPL policy is configured.

BRPL policies are strict data-only YAML validated against the bundled v1 JSON schema before evaluator metadata is attached. Policies require `version: 1`, `policy_id`, and `kind: repository|task`. Repository and task policies are evaluated conjunctively, so overlays can add constraints but cannot weaken repository constraints. Required checks reference a trusted JSON adapter registry; policy files never contain commands.

Every rule object carries a stable explicit `id`, and duplicate policy or rule ids across the combined repository/task policy set fail configuration. Path rules use segment-aware whole-path globs. Each `change_scope` rule owns its allow/deny pattern lists and reports that rule's declared id. Dependency rules name an explicit regular PEP 621 manifest, architecture rules scan the final Python source tree, and JSON reports use `brpl-report/v1` with raw and semantic policy hashes plus typed canonical evidence. JSON report files must be written outside the evaluated repository, or emitted to stdout.

External evaluators can set `BRPL_ENFORCEMENT=enforce` with explicit external `BRPL_REPOSITORY_POLICY`, `BRPL_TASK_POLICY`, and `BRPL_CHECK_REGISTRY` paths so missing, unreadable, deleted, repo-local, wrong-kind, or wrong-shape evaluator inputs fail closed. The unset/default mode remains backward compatible for installed repositories with no BRPL policy, and `BRPL_ENFORCEMENT=off` is available for BRPL's own unit-test path.

## Consequences

- Existing Beryl installs keep the same behavior until a BRPL policy is added or BRPL environment variables are set.
- Policy evaluation requires an explicit Git baseline through `BRPL_BASE_REF` or `--base`, and Python >=3.11.
- The aggregate gate runs BRPL unit tests only in Beryl source/self-test mode, so inactive installed checks do not require Python.
- External evaluators can import the same `.beryl/brpl` core library and run policies against archived patches.
