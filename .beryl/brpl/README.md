# Beryl Repository Policy Language

BRPL is an opt-in machine-readable policy gate for Beryl. It evaluates a small
versioned YAML policy against an explicit Git baseline and reports deterministic
violations before agent work is accepted.

The v1 policy shape is intentionally small:

- `version: 1`, `policy_id`, and `kind: repository|task` are required.
- Every rule object has an explicit stable `id`; duplicate policy ids and rule ids are rejected across repository and task policies.
- `change_scope` is a list of rule objects. Each rule has one stable `id` and
  optional `allow` and `deny` pattern lists. Allow alternatives are unioned
  within that rule, repository and task rules are evaluated conjunctively, and
  violations report the declared rule `id`.
- `protected_paths` blocks modification, deletion, copy, rename, or type changes of sensitive files.
- `architecture.forbid_imports` builds a final-tree Python module index, scans every matched source file, and resolves absolute and relative imports.
- `new_dependencies` compares a required explicit PEP 621 manifest, including optional dependency groups. BRPL v1 only supports `allow: false`.
- `required_checks` names trusted adapters in a registry. Policy files never contain commands.

Repository and task policies are evaluated conjunctively. A task overlay can add
rules, but it cannot weaken repository rules.

## Usage

Copy or create policies under `.beryl/policy/`, then run with an explicit
baseline:

```bash
PYTHONPATH=.beryl python3 -m brpl \
  --repo-root . \
  --base origin/main \
  --policy .beryl/policy/brpl.repository.yml \
  --policy .beryl/policy/brpl.task.yml \
  --check-registry .beryl/policy/check-registry.json
```

The CLI exits with:

- `0` when all policies pass.
- `1` when policy violations are found.
- `2` when policy schema, configuration, or evaluation fails.

For JSON output:

```bash
PYTHONPATH=.beryl python3 -m brpl --format json --json-report /tmp/brpl-report.json ...
```

The JSON report uses `schema: brpl-report/v1` and includes the checker version,
resolved baseline SHA, raw and semantic policy hashes, canonical rules
evaluated, typed evidence, stable `violation_id` values, and deterministic
ordering. Use `--format json` for stdout JSON. `--json-report` must point
outside the evaluated repository so task changes cannot overwrite evaluator
evidence.

Globs are repository-relative whole-path patterns. `*` and `?` match only
within one path segment. A complete `**` segment matches zero or more complete
segments. Absolute paths, backslashes, NUL, empty segments, `.`, `..`, character
classes, and partial `**` segments are rejected.

The trusted check registry is strict JSON:

- top-level keys are only `version` and `checks`;
- check ids must be unique stable identifiers;
- each command is an argv array run with `shell=False`;
- `timeout_seconds` is required, positive, and bounded;
- timeout results are blocking required-check violations.

`./.beryl/scripts/check.sh` remains backward-compatible. It runs BRPL unit tests
only in Beryl source/self-test mode and runs BRPL policy evaluation only when a
BRPL policy exists or when `BRPL_REPOSITORY_POLICY` / `BRPL_TASK_POLICY` is set.
When enabled, policy evaluation requires Python 3.11 or newer and
`BRPL_BASE_REF` must name the explicit baseline. Set `BRPL_ENFORCEMENT=off` to
skip policy evaluation externally.

Set `BRPL_ENFORCEMENT=enforce` for evaluator-owned fail-closed evaluation. In
that mode `BRPL_REPOSITORY_POLICY`, `BRPL_TASK_POLICY`, and
`BRPL_CHECK_REGISTRY` are all required. Each path must be a readable regular
file outside the evaluated repository, and the policy files must have the
matching `kind`.
