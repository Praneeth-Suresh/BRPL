# BRPL v3

BRPL v3 is a prospective compact repository-contract language. It separates
agent-facing repository context from statements that compile into deterministic
verifier operations.

The components are intentionally separate:

- [specification.md](specification.md) is the normative language definition;
- [authoring.md](authoring.md) is the short guide for an LLM or human author;
- [compiler-design.md](compiler-design.md) defines the compiler boundary and
  canonical output; and
- [compiler.py](compiler.py) is the dependency-free reference compiler.

The [examples](../examples/v3) and focused tests in
[`brpl_v3_test.py`](../tests/brpl_v3_test.py) are executable illustrations.

BRPL v3 is not yet wired into Beryl's gate and is not authorized for
confirmatory use. The existing verifier architecture is retained; v3 changes the
source representation and compilation boundary.
