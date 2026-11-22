# BRPL: Beryl Repository Policy Language

**Research prototype for checking repository rules against a proposed code change.**

Coding agents can read rules in prose, but their output does not show which rules they followed. BRPL represents selected rules as data and checks them against evidence about a candidate change. The research question is whether machine-readable rules and deterministic enforcement improve coding-agent outcomes over equivalent instructions written in prose.

This repository is the policy-language research fork. For the general-purpose tooling and setup guide, see [upstream Beryl](https://github.com/Praneeth-Suresh/Beryl).

## One policy, one verdict

The [v2 example policy](.beryl/brpl/examples/v2/brpl.repository.yml) includes this rule:

```yaml
- id: ARCH-001
  kind: dependency.forbid
  relation: python_import
  source: src/api/**
  target: src/persistence/internal/**
  severity: error
  remediation: change_dependency
```

The [checked-in test case](.beryl/brpl/examples/v2/policy-tests.yml) describes a proposed change to `src/api/service.py` that imports `src/persistence/internal/store.py`. Its unit and lint checks both pass, but the evaluator reports an `ARCH-001` violation. The [passing fixture](.beryl/brpl/examples/v2/evidence.pass.yml) uses a permitted import rather than crossing that boundary.

A passing verdict means the supplied evidence satisfies the configured rules. It does not prove the code is correct, cover behavior outside those rules, or replace review. The verifier compares data; a separate trusted harness is responsible for collecting evidence and binding check results to the candidate.

## Inspect the prototype

- [BRPL v2](.beryl/brpl/v2/README.md): current typed evaluator, evidence format, and fixtures.
- [BRPL v3](.beryl/brpl/v3/README.md) and [BRPL v4](.beryl/brpl/v4/README.md): prospective language and verifier designs.

From a local checkout, use Python 3.11 or newer to run the focused v2 test suite, which includes the example above:

```sh
PYTHONPATH=.beryl python3 -m unittest discover -s .beryl/brpl/tests -p 'brpl_v2_test.py'
```

## Evidence status

The repository provides implementations, fixtures, and tests of verifier behavior. Those tests do not establish that policy enforcement improves coding-agent outcomes. In particular, prospective prototypes and development checks are not confirmatory evidence. This README makes no comparative benchmark claim.
