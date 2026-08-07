# BRPL v3 Compiler

## Responsibility

The compiler is a deterministic, side-effect-free transformation from one
repository contract plus optional task overlays to canonical JSON. It does not
read repository source, execute checks, inspect manifests, or decide whether a
candidate passes.

Compilation has five stages:

1. **Parse:** tokenize JSON strings and recognize one closed statement per line.
2. **Type-check:** validate vocabulary, identifiers, cardinality, paths, and
   statement-specific clauses.
3. **Link:** compose policies, resolve areas, and resolve relation, manifest, and
   check names against a trusted capability registry.
4. **Normalize:** expand area references and sort semantically unordered values.
5. **Lower:** emit separate `context`, `areas`, `rules`, and `capabilities`
   sections in a `brpl-plan/v3` JSON document.

The compiler emits operations, not executable code:

| Source statement | Plan operation | Evidence capability |
| :-- | :-- | :-- |
| `changes ... only` | `changed_paths_within` | `changes` |
| `changes ... deny` | `changed_paths_exclude` | `changes` |
| `protect` | `protected_paths_unchanged` | `changes` |
| `generated` | `generated_paths_unchanged` | `changes` |
| `forbid-edge` | `edge_absent` | named relation |
| `dependencies` | `direct_dependency_delta` | named manifest |
| `require` | `check_pass` | named check |

## Trusted capability registry

The prototype accepts strict JSON shaped as follows:

```json
{
  "schema": "brpl-capabilities/v1",
  "relations": ["source.import"],
  "manifests": ["package.json"],
  "checks": [
    {"id": "test", "summary": "The trusted test suite must pass"}
  ]
}
```

This is a symbol table and public contract, not an executable adapter
configuration. Production enforcement additionally binds each entry to a
versioned implementation, evidence schema, coverage declaration, and hashes
outside the policy and candidate worktree.

## Output and verifier boundary

The compiler output includes a semantic SHA-256 over the canonical plan. A
verifier must separately bind the plan, baseline, candidate tree, adapters,
evidence, and results. The prototype compiler does not claim to complete that
trusted runtime integration.

The reference implementation in [compiler.py](compiler.py) intentionally uses
only the Python standard library. It is a prototype for inspecting the language
boundary; confirmatory adoption requires independent test vectors, capability
coverage tests, overlay monotonicity tests, and integration with the externally
held verifier.
