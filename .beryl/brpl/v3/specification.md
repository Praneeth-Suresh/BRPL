# BRPL v3 Language Specification

**Version:** 3

**Status:** prospective normative draft

**Encoding:** UTF-8, one statement per physical line

## 1. Program model

A BRPL source is a repository contract or task overlay. It contains three kinds
of information:

- context statements (`about`, `uses`) communicate facts to an agent;
- `area` declarations name reusable repository path sets; and
- rule statements compile to fixed deterministic operations.

Context and area declarations do not create gate obligations by themselves.
All rules in a repository contract and its task overlays combine by logical AND.
Source order has no effect on semantics.

## 2. Lexical rules

- The first non-comment line is `brpl 3 KIND "ID"`, where `KIND` is
  `repository` or `task`.
- Blank lines and comments beginning with `#` outside strings are ignored.
- Strings use JSON double-quoted syntax.
- Keywords and identifiers are ASCII and case-sensitive.
- Names match `[a-z][a-z0-9-]*`; rule identifiers match
  `[A-Z][A-Z0-9-]{2,63}`.
- `@name` refers to an `area` in the composed contract.
- `none` represents an empty dependency allow-list.
- Tabs outside strings are invalid.
- A contract is limited to 64 KiB of UTF-8, 1,000 physical lines, 500
  statements, 4,096 characters per line, 128 tokens per statement, and 2,048
  decoded characters per string. Exceeding a limit is a compilation error.
- Paths use normalized repository-relative POSIX syntax. `.` is permitted only
  as the repository root. Absolute paths, backslashes, NUL, empty segments,
  `.` or `..` segments, character classes, brace expansion, negation, and a
  partial `**` segment are invalid. `*` and `?` match within one segment; a
  complete `**` segment matches zero or more segments.

## 3. Grammar

```text
program      = header newline { statement newline }
header       = "brpl" "3" ("repository" | "task") json-string

statement    = repo | about | uses | area
             | changes | protect | generated
             | forbid-edge | dependencies | require

repo         = "repo" json-string "root" json-string
about        = "about" about-key json-string
uses         = "uses" technology-kind json-string
               ["major" json-string] ["from" json-string]
               ["role" json-string]
area         = "area" name "paths" selector {selector}

changes      = "changes" rule-id ("only" | "deny") selector {selector}
protect      = "protect" rule-id "paths" selector {selector}
generated    = "generated" rule-id "paths" selector {selector}
forbid-edge  = "forbid-edge" rule-id "relation" json-string
               "from" area-ref "to" area-ref
dependencies = "dependencies" rule-id "manifest" json-string
               "allow-add" string-list "allow-remove" string-list
require      = "require" rule-id "check" json-string
               "means" json-string

selector     = json-string | area-ref
area-ref     = "@" name
string-list  = "none" | json-string {json-string}
```

The closed `about-key` vocabulary is:

```text
purpose, architecture, entrypoint, owner, release, data-classification,
compatibility, documentation
```

The closed `technology-kind` vocabulary is:

```text
language, runtime, framework, dependency, package-manager, formatter, linter,
type-checker, test-framework, build-system, database, message-broker,
deployment, code-generator, security-tool, observability
```

## 4. Declarations

### 4.1 Header and repository identity

The header supplies the policy class and a stable policy ID. IDs must be unique
in a composed policy set. A repository contract contains exactly one `repo`
statement. A task overlay contains no `repo` statement.

`repo NAME root "."` gives the agent a display name and fixes all selectors to
the repository root. Version 3 supports only `root "."`.
The repository name is non-empty.

### 4.2 Context

`about KEY VALUE` communicates one stable repository fact. `uses KIND NAME`
communicates one relevant technology and may add a major version, configuration
path, or concise role. These statements are validated and included in the
canonical agent context, but the compiler does not assert their truth.

Context values are non-empty. This includes the repository display name, every
`about` value, a technology name, and supplied `major`, `from`, or `role`
values. Check capability IDs and their public `means` summaries are also
non-empty.

Repeated context statements are permitted. Exact semantic duplicates are
rejected. Context is canonically sorted.

### 4.3 Areas

`area NAME paths SELECTOR...` defines the union of its selectors. It has no gate
effect until a rule refers to it. Area references may be forward references.
Repository areas may be used by task overlays. An overlay may add a new area but
may not redefine an existing name.

Areas cannot refer to other areas; this avoids cycles and keeps expansion a
single lookup.

## 5. Rule semantics

Every rule has a globally unique stable ID. A false predicate is blocking.
Severity and remediation are fixed by rule kind rather than configurable in
source.

### 5.1 `changes`

`changes R only S...` passes when every changed path is contained in the union
of `S`. `changes R deny S...` passes when no changed path is contained in that
union. Both source and destination paths of copies and renames are evaluated.

The change evidence must account for additions, modifications, deletions,
copies, renames, mode or type changes, symlink-target changes, submodule pointer
changes, and relevant untracked files. Unresolved normalization is an evaluation
error.

### 5.2 `protect` and `generated`

`protect R paths S...` passes when no selected path changed. `generated` has the
same predicate but a distinct policy class: it communicates that files must be
updated through a trusted source or generator. BRPL does not execute that
generator.

### 5.3 `forbid-edge`

`forbid-edge R relation K from @A to @B` passes when the trusted adapter for
relation `K` reports no directed edge from a path in area A to a path in area B.
BRPL does not define how language-specific edges are extracted.

### 5.4 `dependencies`

`dependencies R manifest P allow-add A allow-remove D` passes when every direct
dependency addition reported for manifest `P` is in A and every removal is in D.
Package identifiers are canonicalized by the trusted manifest capability.
Transitive, vendored, runtime-installed, and alternate-manifest dependencies are
outside this predicate unless the capability explicitly includes them.

### 5.5 `require`

`require R check K means M` passes when trusted check `K` returns `pass` for the
exact candidate-tree hash. `M` must equal the registry's public summary for K.
This keeps the agent-visible meaning and verifier operation synchronized.

Missing results, failures, timeouts, crashes, malformed output, and
candidate-hash mismatches do not pass. Commands, environments, timeouts, and
result interpretation exist only in the trusted registry.

## 6. Composition

Exactly one repository contract and zero or more task overlays compile together.
Policy IDs, area names, and rule IDs are unique across the set. Context and new
areas are unioned; rules are conjoined. No statement can override, disable, or
weaken another statement. Deny, protect, generated, edge, dependency, and check
requirements cannot be rescued by an allow statement.

Task `changes ... only` rules narrow the accepted changed-path set by
conjunction. Other task rules add prohibitions or obligations. The compiler
rejects redefinitions; it does not implement `last rule wins` behavior.

## 7. Host-language neutrality

The compiler emits four evidence requirements: changed paths, graph edges,
direct dependency deltas, and candidate-bound check results. A trusted
`brpl-capabilities/v2` registry maps the change source and every relation,
manifest, and check ID to an adapter identifier plus the adapter artifact's
SHA-256. The compiler copies only bindings that a plan uses. Before evaluating,
the verifier validates the closed `brpl-plan/v3` structure and recomputes its
semantic SHA-256. Policy files never supply adapter code, commands, filesystem
paths to executables, environment variables, or network locations.

Language neutrality means BRPL syntax and predicate meanings do not change when
the repository language changes. It does not mean one adapter observes every
language or dynamic behavior. Missing, ambiguous, failed, or incomplete required
coverage is fail-closed and must be reported.

## 8. Canonical form and diagnostics

Compilation emits canonical JSON with sorted keys and compact separators.
Context, areas, rules, and capability references are sorted by stable semantic
keys. Selector and allow-list order is insignificant and canonicalized.

Compilation errors include a stable code, source name, line number, and bounded
message. Unknown statements or fields, duplicate identifiers, malformed values,
unsafe paths, unresolved references, unavailable capabilities, and public-summary
mismatches are errors. The compiler never executes source content.
