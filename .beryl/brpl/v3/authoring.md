# Writing BRPL v3

Use BRPL for a compact repository map and machine-checkable constraints. Do not
copy general documentation into it.

## Authoring sequence

1. Read repository-owned evidence: manifests, CI, contributor guidance,
   architecture documents, tool configuration, generated-file markers, and
   security configuration.
2. Write one repository header and a short `repo` statement.
3. Add only `about` and `uses` facts that could change an agent's implementation
   or verification choices. List major dependencies, not every package.
4. Name a small number of useful `area`s: architectural components, public API,
   tests, generated output, migrations, controls, or sensitive configuration.
5. Add a rule only when a trusted capability can decide it. Use:
   - `changes`, `protect`, or `generated` for path constraints;
   - `forbid-edge` for observable dependency boundaries;
   - `dependencies` for direct manifest changes; and
   - `require` for formatter, linter, type, test, build, security, compatibility,
     licence, generation, or documentation checks.
6. Compile with the repository's trusted capability registry. Missing coverage
   is a design problem, not permission to claim enforcement.

## Translation examples

| Intent | BRPL form |
| :-- | :-- |
| This repository uses Vitest. | `uses test-framework "Vitest"` |
| The trusted test suite must pass. | `require TEST-001 check "test" means "The trusted test suite must pass"` |
| Domain code lives under `src/domain`. | `area domain paths "src/domain/**"` |
| Domain must not import adapters. | `forbid-edge ARCH-001 relation "source.import" from @domain to @adapters` |
| This folder is generated. | `area generated paths "src/generated/**"` |
| Generated output must not be edited directly. | `generated GEN-001 paths @generated` |
| Write secure code. | Too ambiguous. State useful context, then add only rules with defined evidence. |

## Keep contracts small

- Prefer five meaningful areas to directory aliases for every folder.
- Use one proposition per context statement.
- Keep rationale in ordinary documentation.
- Never include commands, credentials, hidden evaluator details, task solutions,
  or policy-specific implementation advice.
- Do not use a passing security check as evidence for security properties outside
  that check's declared contract.
- Generate information-equivalent prose and BRPL from one semantic source when
  used in the experiment.
