# BRPL v4 Constraint Coverage Matrix

| Constraint class | Rule or control | Evidence and decision | Limitation |
| --- | --- | --- | --- |
| Change scope | `changes` | Candidate-bound path changes match finite selectors. | Does not observe reverted transient edits. |
| Protected and generated paths | `protect`, `generated` | Candidate-bound path changes do not match protected selectors. | Generated status is declared policy, not inferred provenance. |
| Direct architecture dependency | `forbid-edge` | Complete normalized graph has no selected direct edge. | Depends on relation adapter completeness. |
| Layering and transitive architecture | `forbid-path`, `component-adjacency` | Complete graph has no forbidden reachability or undeclared component edge. | Dynamic loading can be outside a static adapter universe. |
| Dependency cycles | `acyclic` | Complete graph has no reported directed cycle. | Applies only to the declared relation and selected universe. |
| Direct dependency delta | `dependencies` | Candidate-bound trusted manifest delta is within finite allowlists. | Does not prove transitive resolution behavior. |
| Build or test requirement | `require` | Candidate-bound trusted check has status `pass`. | Check coverage is defined by its external adapter. |
| Quantitative quality budget | `threshold` | Exact candidate-bound metric value satisfies typed comparison. | Reproducibility and construct validity belong to metric adapter protocol. |
| Control integrity | Launch manifest and external controls | Pinned authority artifacts and candidate hash are checked before and after evaluation. | Does not protect an attacker controlling the trust root. |
