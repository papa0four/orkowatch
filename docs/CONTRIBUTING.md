# Contributing to orkowatch

orkowatch is a cross-platform host security auditing CLI. These conventions
keep `dev` known-good and make intent explicit for anyone picking up the work.

## Getting started

Before running any `make` target, install the required pipeline tools:

```sh
make install-tools
```

On Windows, run the equivalent PowerShell script:

```powershell
.\scripts\install-tools.ps1
```

Tools already present are skipped. See `scripts/install-tools.sh` for the
full list and manual fallback instructions for tools that cannot be
auto-installed.

## Developer guides

Subsystem-specific design and implementation detail lives under
`docs/dev_guide/`, one file per subsystem. Check the relevant guide before
extending a subsystem, so decisions already made aren't duplicated or
contradicted. Add a row here whenever a new guide is created — this table is
a live index, not a one-time snapshot.

| Guide | Covers |
|---|---|
| `docs/dev_guide/scan_registry.md` | `CheckMask` registry, filename derivation, `all`/`audit` composition model, package boundaries |

## Priorities

Every decision is weighed in this order, and none is compromised for
short-term ease:

1. Scalable
2. Optimal
3. Thorough
4. Safe
5. Modular

## Issue templates

Open a GitHub issue before cutting any branch. Use the correct template:

- `Bug` -- a confirmed defect with observed behavior
- `Enhancement` -- new capability or improvement to existing behavior
- `Chore` -- housekeeping, tooling, or maintenance with no user-facing behavior change
- `Docs` -- documentation additions or corrections
- `Infrastructure` -- CI, pipelines, build, release, or environment work
- `Test` -- New tests, test infrastructure, or corrections to existing tests

Blank issues are disabled. If none of the templates fit, reconsider the scope.

## Branch naming

`<type>/<issue#>-<short-description>`

- Types: `bug`, `enhancement`, `chore`, `docs`, `infrastructure`, `test`
- Issue number is the GitHub issue this branch resolves
- Description is lowercase, hyphen-separated, short enough to read at a glance

Example: `chore/77-add-issue-pr-and-branch-templates`

## Workflow

- One problem at a time. Cut sub-branches one at a time to avoid rebase debt.
- Sub-branches merge into their parent before the parent merges up.
- Planning issues establish design before any sub-issue branch is cut. No
  sub-branch starts before the design document or interface definition is
  committed to the planning branch.
- `dev` is always known-good. `main` holds tagged releases only.
- Direct commits to a parent branch are acceptable for small self-contained
  changes. Anything substantial enough to warrant isolation gets its own
  sub-branch and pipeline run.
- Sub-branches that are substantial enough to warrant their own isolation
  require a full issue with title and description before the branch is cut.
- Planning branches establish a design or interface before sub-issue branches
  are cut. Sub-issue branches merge back into the planning branch. The
  planning branch merges to `dev` when all sub-issues are complete.

## Pipeline gate

The full local pipeline must pass before any merge:

```sh
gofmt -w .
go build ./...
go vet ./...
gosec ./...
govulncheck ./...
golangci-lint run --timeout=5m
GOOS=windows go build ./...  # required for any change touching a platform-tagged file or platform-aware package
```

On Windows, additionally run:

```powershell
Invoke-ScriptAnalyzer -Path . -Recurse  # PSScriptAnalyzer for any .ps1 changes
```

Shell scripts require `shellcheck` to pass before merge.

`golangci-lint` must be installed via `go install` to match the local Go
toolchain version:

```sh
go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@latest
```

Do not install `golangci-lint` via a system package manager.

## Pull requests

- Follow the PR template. Fill the `Closes #` line with the issue number so
  the linked issue auto-closes on merge.
- Keep the `## Summary` / `## Changes` / `## Verified` structure.
- PR summary describes what was done. Issue description reads like a user
  story or design brief. These are different documents with different audiences.

## Registry citations

YAML registry entries require verified citable sources (CIS Benchmarks, NIST
SP 800-53 Rev 5, or equivalent). Fabricated or stretched citations are not
accepted. A check idea taken from a reference manual still needs a primary
citation behind the registry entry. No entry ships without a citation.

## Code conventions

- Doc comments are documentation, not narration. Every exported symbol gets a
  doc comment beginning with the symbol name, written as one or more complete
  sentences that describe purpose and behavior precisely enough to stand alone
  without the code beneath them. Godoc renders these directly -- write them
  for a reader who cannot see the implementation.
- Package-level `// Package X ...` comments are required in every package.
  They appear at the top of the godoc page and must describe what the package
  does and where it fits in the architecture.
- Unexported symbols that are non-obvious get a doc comment following the same
  standard. Unexported symbols that are self-evident do not need one.
- Body comments (inside function bodies) explain why a non-obvious decision
  was made, briefly. They do not narrate what the code already shows.
- Completeness and precision are the standard. Padding, filler phrases, and
  AI-sounding prose are not. A correct doc comment reads like a manual entry,
  not a summary of what you just did.
- No dead code. Every unexported symbol must have a live caller. Every
  unexported function must justify its existence with active use.
- No copy-paste between files or packages. Extract a helper.
- Named constants for domain values. Structural indices may stay literal.
- No hardcoded severity strings. Severity is derived from CVSS score ranges
  via `SeverityFromCVSS`.
- No stubs that silently succeed. Return a typed sentinel error instead so the
  caller knows the subsystem is not yet configured.
- Comments explain why, not what. Naming carries meaning. Verbose explanation
  lives in docs, not in function bodies.
- Use merge/merged/merging, not promote/promoted/promoting.

## Code quality: no dead or duplicate code

Dead code is not merged, under any circumstance -- exported or unexported,
finished feature or abandoned attempt. If a package, type, or function has
no demonstrable live caller, it is removed, not left in place "in case it's
useful." The same standard applies to duplicate implementations: if two
pieces of code solve the same problem, one is removed or they are
consolidated with a stated reason for keeping both.

This is enforced, not assumed. Before extending or documenting any existing
code, confirm it is actually called from somewhere real -- a passing build
and clean lint output are not evidence of that. The goal is to keep the
codebase's actual surface area matched to what's genuinely in use, which
keeps throughput high and both attack surface and maintenance burden as
small as the feature set actually requires.

## Tests

Follow the issue template when opening a test issue. Go testing categories
in use in this project:

- **Unit** -- isolated logic, one function or type at a time
- **Integration** -- component communication across package boundaries
- **Table-driven** -- scaling coverage cleanly across input variants
- **Fuzz** -- edge-case and boundary discovery
- **Benchmark** -- performance validation for hot paths
- **Example** -- doubles as documentation; rendered by godoc

All tests use the standard `testing` package unless a design discussion
recorded in `docs/dev_guide/testing.md` justifies an addition.

Test file placement follows Go convention:

- Unit, integration, table-driven, fuzz, benchmark, and example tests live
  alongside the package they test in a `_test.go` file. Use `package X` for
  white-box tests that need access to unexported symbols, and `package X_test`
  for black-box tests that exercise only the exported surface.
- Functional and end-to-end tests that invoke the compiled `owatch` binary
  directly live in a top-level `tests/` directory.
- Test fixture files live in a `testdata/` subdirectory alongside the package
  that uses them.

`_test.go` files are excluded from the compiled binary by the Go toolchain
unconditionally. No separation is needed to keep tests out of the binary.

Platform-specific test files follow the same build tag conventions as
production code.