# Beryl Repository Policy Language

BRPL is Beryl's machine-readable repository-contract representation. The enforcement pipeline evaluates compiled constraints against trusted evidence and reports deterministic violations before agent work is accepted.

## Versions

| Version | Status | Documentation and entry point |
| :-- | :-- | :-- |
| v1 | Preserved legacy YAML implementation | `brpl.core`; schema at `schemas/brpl-v1.schema.json` |
| v2 | Active typed-YAML checker and evaluator | [`v2/README.md`](v2/README.md), `brpl.v2`, and the compatibility `brpl` CLI |
| v3 | Prospective compact language, compiler, and native verifier | [`v3/README.md`](v3/README.md), `python3 -m brpl.v3`, and `BRPL_POLICY_VERSION=v3` |
| v4 | Prospective host-neutral graph and threshold verifier | [`v4/README.md`](v4/README.md) and explicit `python3 -m brpl.v4` selection |

The default CLI points to v2. Setting `BRPL_POLICY_VERSION=v3` selects the v3 compiler/verifier and requires an external `BRPL_CAPABILITIES` registry. It cannot replace v2 in confirmatory execution until the required protocol, parity, containment, tamper, shortcut, freeze, and validity gates pass.

BRPL v4 does not change the generic CLI or v2/v3 behavior. Its `--enforce` mode requires external policy, catalog, evidence, and launch-manifest paths, and it verifies candidate and authority integrity before and after evaluation.

## Invariants across versions

- Policies are parsed as data and never executed as code.
- Repository and task constraints compose conjunctively.
- Rules and findings use stable identifiers.
- Required checks refer to trusted registry entries; policy files contain no commands.
- Invalid or unobservable required inputs fail closed.
- Authoritative policy, checker/compiler, registry, baseline, evaluator, and integrity records remain outside the agent-writable worktree in enforced use.
