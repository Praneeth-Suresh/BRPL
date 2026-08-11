# BRPL v4

BRPL v4 is an explicitly selected, prospective repository-policy language for deterministic verification over trusted normalized evidence; it is not selected by `python -m brpl`, which continues to use v2.

Use `PYTHONPATH=.beryl python3 -m brpl.v4 --repo-root <candidate> --policy <external-policy.json> --catalog <external-catalog.json> --evidence <external-evidence.json>` for development validation, and add `--enforce --launch-manifest <external-launch.json>` when an evaluator controls all authority artifacts; enforced evidence/run records must be outside the candidate worktree.

The v4 verifier does not inspect Python syntax, parse a package manifest, invoke a command, or execute policy source. Trusted adapters produce data conforming to the evidence contract, and the closed verifier only compares that data to a canonical plan.

The development adapter is explicitly selected with `python3 -m brpl.v4.adapter_driver --adapter python-static`; it is outside the compiler/verifier boundary, emits partial static-import coverage, and prints the artifact SHA-256 that an external catalog must pin. Regenerate a catalog digest whenever the reviewed adapter artifact changes.

Read [specification.md](specification.md) for the normative language, [authoring.md](authoring.md) for policy authors, [coverage-matrix.md](coverage-matrix.md) for operational coverage, and [properties.md](properties.md) for claims and limits.
