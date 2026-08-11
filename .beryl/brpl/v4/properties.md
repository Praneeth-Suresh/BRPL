# BRPL v4 Properties and Proof Sketches

BRPL v4 is declarative because policy source is a finite strict JSON data object whose grammar has no commands, expressions, functions, imports, adapter paths, or user-defined computation.

Parsing and compilation terminate for bounded input because the accepted JSON tree, rule kinds, selector lists, and adapter catalog are finite; verifier graph traversal is finite over the supplied finite edge list.

Canonical compilation is deterministic because policies, areas, components, rules, capabilities, and allowed edges are sorted through canonical JSON before the semantic SHA-256 is calculated.

Verification is deterministic conditional on identical validated plan and normalized evidence because every predicate is a finite path, graph, set, exact-decimal, or status comparison with no clock, random source, command execution, or network access.

Task overlays are monotonic because composition only unions rules and rejects duplicate identities or redefinitions; no source construct can delete, override, exempt, or weaken a repository rule.

Source order is semantically irrelevant because compilation sorts policies and lower-level collections, and all policy rules are conjunctive.

Mandatory graph, check, manifest, and metric evidence fails closed when absent, malformed, candidate-mismatched, incomplete, or indeterminate; an evaluation error is not compliance.

Diagnostics are attributable because each emitted finding has a stable rule identifier, policy identity, policy class, remediation, canonical evidence digest, and stable finding identifier.

Host-language neutrality is a core property, not a claim that every adapter is language-neutral: the compiler and verifier consume paths, graph edges, manifest deltas, check results, and metric observations without importing a language AST or manifest parser.

These are proof sketches over the abstract v4 core; adapter completeness, external-check termination, accurate metric measurement, correct baseline selection, and recovery of unstated human intent are explicitly not language theorems and require adapter conformance and empirical validation.
