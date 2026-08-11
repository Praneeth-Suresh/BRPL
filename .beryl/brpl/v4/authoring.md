# Writing BRPL v4 Policies

Author only strict data in a canonical policy bundle and generate repository and task policies from it; do not hand-maintain natural-language guidance and BRPL as independent descriptions.

Areas name reusable path selectors, while components name non-overlapping architectural responsibility areas; use `@area` when a graph source, graph target, or path rule refers to an area.

Choose `forbid-edge` for direct dependency rules and `forbid-path` when an indirect dependency is prohibited; use component adjacency for a declared architecture and `acyclic` only when the trusted relation evidence is complete for the named universe.

Use threshold rules only for trusted metrics with a stable unit and reproducible measurement protocol; use exact decimal strings for non-integer boundaries and state the operational meaning in `summary`.

Policies cannot contain adapter paths, commands, environment variables, shell expressions, network locations, executable code, exemption logic, or unbounded expressions; register a trusted adapter externally instead.

Treat a partial static analysis as insufficient evidence for graph compliance, and document its coverage boundary in the external catalog rather than claiming universal language analysis.
