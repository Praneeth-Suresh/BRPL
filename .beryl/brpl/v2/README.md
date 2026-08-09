# BRPL v2

BRPL v2 is the active implementation of the closed typed design in the research repository's `BRPLDesign.md`. Confirmatory use remains subject to the dated protocol amendment and validity gates.

The public Python API is `brpl.v2`. It provides:

- strict, data-only YAML policy, evidence, and policy-test loaders;
- closed validation for five rule kinds;
- semantic lint for duplicate, conflicting, unresolved, and empty selectors;
- a pure evaluator with typed, deterministic findings;
- trusted-side candidate-tree hashing and candidate-bound check results;
- control-hash, gate-bypass, and control-tampering evidence support; and
- data-only policy test vectors with rule-coverage reporting.

Policy evaluation never executes commands, follows policy-supplied filesystem paths, or loads extensions. Evidence extraction, check execution, registry resolution, immutable control storage, and runtime telemetry remain trusted harness responsibilities.

Schemas are descriptive review artifacts under `../schemas/`. Runtime validation is implemented directly so v2 has no third-party parser or JSON Schema dependency. Examples under `../examples/v2/` form a minimal policy/evidence/test-vector set.

Run the focused tests from the Beryl repository root:

```bash
PYTHONPATH=.beryl python3 -m unittest discover -s .beryl/brpl/tests -p 'brpl_v2_test.py'
```
