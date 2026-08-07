# Beryl Repository Policy Language

BRPL is Beryl's machine-readable repository-contract representation. The
enforcement pipeline evaluates compiled constraints against trusted evidence and
reports deterministic violations before agent work is accepted.

## Versions

| Version | Status | Documentation and entry point |
| :-- | :-- | :-- |
| v1 | Preserved legacy YAML implementation | `brpl.core`; schema at `schemas/brpl-v1.schema.json` |
| v2 | Active typed-YAML checker and evaluator | [`v2/README.md`](v2/README.md), `brpl.v2`, and the compatibility `brpl` CLI |
| v3 | Prospective compact language and reference compiler; not gate-integrated | [`v3/README.md`](v3/README.md) and `python3 -m brpl.v3` |

The active CLI points to v2. BRPL v3 changes the source representation and adds
an explicit compilation boundary, while retaining the existing separation
between representation and trusted deterministic enforcement. It cannot replace
v2 in confirmatory execution until the required protocol, parity, containment,
tamper, shortcut, freeze, and validity gates pass.

## Invariants across versions

- Policies are parsed as data and never executed as code.
- Repository and task constraints compose conjunctively.
- Rules and findings use stable identifiers.
- Required checks refer to trusted registry entries; policy files contain no
  commands.
- Invalid or unobservable required inputs fail closed.
- Authoritative policy, checker/compiler, registry, baseline, evaluator, and
  integrity records remain outside the agent-writable worktree in enforced use.
