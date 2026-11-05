# Agent guidance for C-Tor

This repository contains the C implementation of Tor. It is primarily in
security maintenance mode. Favor small fixes that are easy to review, validate,
and backport. New features, protocol changes, and broad architectural rewrites
need an explicit task scope; they are not incidental improvements to a fix.

Read linked guides only when relevant, and read only the applicable sections;
do not recursively follow references.

## Engineering preferences

### Investigation and scope

- Before editing, read the affected implementation, consumers, and subsystem
  guidance. Establish the failure, affected versions, and required behavior.
  Verify historical commands and configuration examples against this checkout.
- For protocol work, consult the
  [Tor specifications and proposals](https://gitlab.torproject.org/tpo/core/torspec).
  Use `reference_repos/torspec` for spec compliance and `reference_repos/arti`
  for Arti compatibility. Verify that the reference revision and configuration
  apply to the C-Tor behavior and version under review. If an optional checkout
  is absent, ask the user to add it if they want that comparison. Report which
  checks were possible.
- Make the smallest complete fix, including affected consumers and cleanup
  paths. Report incidental defects and leave unrelated fixes, refactoring,
  formatting, and speculative hardening to separate work unless requested.
- Fix necessary prerequisites in clearly scoped commits with regression
  coverage. Avoid workarounds that preserve known incorrect behavior.
- Obtain explicit user approval before adding any new external dependency to
  C-Tor, whether vendored or supplied externally. Explain why it is needed,
  what alternatives exist, and what maintenance it would require.

### C conventions and portability

- Prefer straightforward C, existing data structures, and Tor helpers. Avoid
  new frameworks, dependencies, configuration knobs, and parallel state
  tracking when a local correction will suffice.
- Respect directory `.may_include` rules and upstream provenance. Change
  generated code through its inputs and regeneration tools. For parsers, see
  the [Trunnel README](src/trunnel/README).
- Use Tor's allocation, string, character, and socket helpers in place of libc
  equivalents. See `src/lib/{malloc,string,net}/` and `src/lib/container/`.
  Examples include `tor_malloc`, `tor_free`, `tor_strdup`, `tor_snprintf`,
  `strlcpy`, `TOR_IS*`, and `tor_socket_t`. Resize arrays with
  `tor_reallocarray(ptr, count, size)` to avoid multiplying sizes at the caller.
- For owned types, follow the `abc_free_()` / `abc_free()` convention using
  `FREE_AND_NULL`. Destructors accept NULL and the public macro clears the pointer.
- Use `lowercase_with_underscores` names, module/object prefixes for functions,
  `_t` type names, and `ALL_CAPS` macros/constants. Document ownership, return
  values, and other contracts with Doxygen comments.
- For manual binary access, use `uint8_t` buffers and `get_uint*`/`set_uint*`
  from `src/lib/arch/bytes.h`. Avoid unaligned integer-pointer casts and
  handle wire byte order explicitly.
- Preserve supported Unix-like, Windows, 32-bit, and module-disabled builds.
  Use existing portability wrappers and feature checks, and isolate necessary
  platform-specific code.
- Use LF line endings, no trailing whitespace, 79-column C lines, two-space C
  indentation, and the required tabs in make recipes. Verify whitespace with
  the checks in [Build and validation](#build-and-validation).

### Security and lifecycle

- Preserve anonymity, isolation, security boundaries, and protocol compatibility.
  Trace shared global state across affected clients, bridges, relays, onion
  services, and directory authorities, including combined roles. Check for
  unintended changes to another component's behavior or a peer's wire contract.
- Follow shared ownership, aliases, list/index membership, and back-pointers
  through attachment, callbacks, failure, recovery, close, free, and shutdown.
  Circuit and stream lists, channel associations, and Conflux sets can couple
  distant code. Keep shared ownership and per-leg state consistent, including
  per-leg isolation. Distinguish marked-for-close from freed objects, and
  local cancellation from failure of a shared resource.
- Account for Tor's OOM killer in affected call chains. Reclamation can close
  other circuits or streams, mutate lists and queues, invoke callbacks,
  allocate memory, and request further cleanup. Recheck pointers, iterators,
  and accounting afterward. Keep accounting consistent through teardown,
  preserve pending reclamation work, and prefer existing lifecycle mechanisms.
- Treat hostile input and resource exhaustion as expected conditions. Check
  arithmetic, allocation sizes, parsing, ownership, and worst-case work. Avoid
  remotely reachable crashes and unintended or attacker-amplified CPU and
  memory costs. Bound diagnostic work and avoid logging sensitive or untrusted
  payloads.
- Justify new limits and timeouts against a concrete attack or invariant, existing
  guards, and legitimate traffic. Avoid copying arbitrary caps from other projects.
- Use assertions only for programming bugs. Reserve `tor_assert()` for cases
  where continuing would lead to memory corruption or a crash. Otherwise,
  prefer `tor_assert_nonfatal()` or `BUG()` and handle the failure.
- Use Tor's cryptography, randomness, constant-time comparison, and memory-wiping
  helpers where appropriate. Compare secrets with `tor_memeq`/`tor_memneq` from
  `src/lib/ctime/di_ops.h`. Reserve `fast_*` comparisons for non-secret data.

### Regression tests and documentation

- Where feasible, cover the original failure, relevant boundaries, failure paths,
  and forbidden side effects with small deterministic fixtures. Where practical,
  show that the test fails before the fix and passes afterward. A focused run
  suffices to demonstrate test sensitivity.
- Tests of a security property must exercise the production mechanism enforcing
  it. Use mocks only for surrounding dependencies.
- Keep new test frameworks and broad benchmark suites out of local fixes.
  Claims of measured speedups require measurements.
- Keep comments and permanent documentation aligned with current behavior.
  Explain security invariants, non-obvious ownership, and enduring rationale.
  Keep investigation history and validation results in the working review record
  or, for work without a plan, in the conversation or PR description.
- In operator guides, explain what the operator needs to decide or do and link
  to the reference that defines the detailed behavior.

## Independent subagent workflows

Use independent subagents for design, audits, and implementation review without
waiting for a separate delegation request. Scale review to the change.

- Use a committed plan when the user requests one, when continuing an existing
  plan, or when the work would benefit from distinct implementation and review
  phases. Examples include changes spanning subsystems with different validation
  needs and changes where later work depends on an earlier design or integration
  decision. Routine multi-step fixes can use the lightweight review workflow
  from this section without a plan file. Small documentation edits need no plan.
- Before starting planned work, creating or revising its plan, or preparing its
  delivery branch, follow [the planning workflow](doc/HACKING/AgentPlanningWorkflow.md).
  Keep the committed plan, review record, and unsquashed fixups on the working
  branch through user review rounds. Announce the process and handoff state.
- Prepare a separate plan-free delivery branch only on explicit user request.
  Preserve the working branch and independently review every new delivery SHA
  and the combined delivery branch before calling it merge-ready.

### Coordinator responsibilities

- Choose non-authors for each review or audit and start them in fresh
  conversations where possible. Keep reviewers read-only by default and give
  delegated editors explicit file ownership. Avoid fixed reviewer counts and
  duplicate checks.
- Give each reviewer a self-contained brief with intent, baseline, scope,
  invariants, security constraints, and validation evidence, including known
  failures and gaps. Provide access to the relevant checkout and Git history.
  Include applicable changes fragments and documentation in scope.
- Own resolution and completion. If a reviewer inherited the author's context,
  disclose it and the checks performed. If independent tooling was unavailable,
  report the checks performed and the missing independent review.

### Review method

- Before editing, have a design reviewer challenge the approach and the need
  for checks, and identify removable responsibilities. Resolve findings that
  materially affect a decision before building on it.
- Before recommending a check be added or removed, identify the component that
  owns the invariant. Verify its guarantees for the affected versions and
  configurations against the implementation and regression coverage.
- Assign distinct audit questions. Before investigating, each auditor
  checks whether their scope and method can answer their question and flags
  gaps between assignments. The coordinator ensures those gaps are examined.
- Trace surrounding consumers, failure paths, and test coverage. Use relevant
  bug history to select scenarios, including affected cross-component and OOM
  interactions, callbacks, and deferred work. Report findings with evidence,
  areas examined where no issue was found, and limits of the review.

### Implementation review

- Verify claims and question unnecessary checks. Record an initial assessment
  before consulting the author's rationale or prior findings, then reconcile
  it with all prior findings and fixups before completing the review.
- Where duplicated checks, parallel state, or fragile ownership emerge,
  evaluate concrete simplifications against the contracts they must preserve.
- Review each exact commit and its relevant consumers. For uncommitted work,
  identify the base SHA, exact diff, and contents of new files in scope.
  Correct findings introduced by the uncommitted patch in that patch, then
  review the resulting exact SHA.
- Use `git commit --fixup=<introducing-SHA>` only for defects introduced by
  commits in the working branch's own series. For an in-scope defect inherited
  from the base (including the base commit itself), make a standalone commit
  with a message explaining the defect and its correction. Independently
  review each standalone commit and fixup.
  Keep history unsquashed through final implementation review. Later changes
  reopen affected reviews.
- At meaningful intermediate boundaries and before completion, review the
  combined implementation and complete affected call chains or documentation
  references. For a small single-commit change, one review may cover both the
  exact SHA and combined state if it examines both scopes.
- During combined review, trace **all prior findings and fixups** through the
  surrounding code for recurring causes, cross-component hazards, and coverage
  gaps elsewhere in the branch. Resolve findings, add appropriate regressions,
  and decide whether a wider audit, simplification, or design change is needed.

## Changes files

Every bug fix against a stable release requires a changes file:

- Add a distinct file under `changes/` for user-visible behavior and noticeable
  internal, documentation, or build changes. Include it with the implementation
  commit where possible. Use `bugNNNNN` or `ticketNNNNN` for an existing ticket,
  or a descriptive unique name when there is no ticket.
- Exceptions include fixes to unreleased code, changes to files
  not distributed in the tarball, non-functional movement, renames, and comment
  or spelling edits. Assess the actual distribution rules for developer tooling;
  do not assume every tooling or documentation change is exempt.
- Write a terse user-facing entry in the present imperative. Start with a
  two-space-indented `o` category header and a colon, then a four-space-indented
  `-` entry with continuation lines indented six spaces. Bugfix and feature
  categories need an area in parentheses. Use existing entries for examples.
  Name changed configuration options and briefly explain obscure ones. Use
  "relays" rather than "servers" or "nodes" when referring to relays.
- Ticket references are optional on this branch. Never invent an issue number or
  an affected version. When referencing a bug, use `Fixes bug NNNNN; bugfix on
  X.Y.Z.` with the verified introducing version; omit `#` and the `tor-` prefix.
  If necessary, investigate with `git log -S`, `git blame`, and
  `git describe --contains`. An "all supported versions" fallback does not
  satisfy this branch's linter when a numeric bug is cited;
  report unresolved version attribution rather than inventing a version or
  weakening the check.
- Edit the fragment, not the release `ChangeLog`. Leave version bumps, release
  aggregation, generated directory lists, and GeoIP updates to their own tasks.

## Build and validation

Run `configure` with `--enable-fatal-warnings`, preserving needed local
configuration. Run make in the configured build directory; edit
`Makefile.am`/`include.am` inputs rather than generated Makefiles. Serialize
validation sharing a build directory and keep sources fixed while it runs.

Build the affected test binary before focused runs, e.g.
`make src/test/test` then `./src/test/test 'cellfmt/..'` from the build directory;
other tests use `test-slow` or standalone binaries. When writing
tests, consult the applicable [WritingTests.md](doc/HACKING/WritingTests.md)
sections on registration, fixtures, exposing static functions, or mocking.

Run `git diff --check` for every change. For code changes, run focused tests
while iterating and `make check` before handoff; checks that executed
successfully need no separate rerun. Select additional validation by the
affected behavior below; combined targets do not replace checks they omit.
For changes-fragment-only edits, run `make check-changes`. Target coverage comes
from this branch's `Makefile.am` and `src/test/include.am`.

| Command | When to run | Coverage and limits |
| --- | --- | --- |
| `make check` | Before handing off code changes | Main/slow unit suites, standalone binaries, and script tests; includes `check-spaces` (owned C/headers), `check-changes` (whole `changes/` directory), `check-includes` (dependency rules/cycles), and `shellcheck`. |
| `make check-best-practices` | For substantive C changes | Practracker; requires configured Python. Not included in `make check`. |
| `make check-docs` | For option or manual changes | Reports discrepancies among Tor's options, sample torrc, and manual; inspect output even on success. Not included in `make check`. Also build affected documentation. |
| `make distcheck` | For changes to the build system, packaging, or which files are shipped | Builds and checks a source distribution, including install/uninstall checks. Use relevant `DISTCHECK_CONFIGURE_FLAGS`; separate build may differ from local configuration. |
| `make test-stem` | For controller/process integration changes | Selected Stem controller and process integration tests; set `STEM_SOURCE_DIR`. Not included in `make check`. |
| `make test-network` | For circuit/network integration changes | Quick local Chutney IPv4/IPv6 scenarios; set `CHUTNEY_PATH` to a CI-compatible checkout. Not included in `make check`. |
| `make test-network-all` | For changes needing broader network scenarios | Broader Chutney flavors; mixed-version cases require `tor-stable`. Not included in either `test-full` target. |
| `make test-fuzz-corpora` | For affected parsers/fuzz harnesses | Builds fuzzers and replays corpus inputs; set `TOR_FUZZ_CORPORA`. Does not perform new fuzzing. Corpus replay in `make check` skips without this checkout. |

To claim corpus coverage, verify that the affected harness ran successfully
on at least one corpus input. Check the replay output (the script's test log
under `make check`) and its matching corpus directory. A missing harness
directory can produce `No tests found` and a successful exit. Report the
missing coverage.

For combined coverage, `make test-full` runs `check`, quick `test-network`, and
selected `test-stem` tests; it needs both external checkouts.
`make test-full-online` expands Stem to its full suite including online tests,
requiring internet access. Neither combined target runs `test-network-all`.

Use a build with unit tests enabled. Ensure Perl/Python checks actually executed:
configure can omit `check-spaces` without Perl, and `check-changes`,
`check-includes`, and `check-best-practices` without Python. The shellcheck
wrapper also succeeds without running if its tool is absent. Inspect skips as
well as failures; missing tools or corpora are missing coverage, not passes.
For `check-docs`, read affected
[manual options](doc/man/tor.1.txt) and, for syntax/parser changes,
[torrc format](doc/torrc_format.txt). Documentation builds require the relevant
AsciiDoc/manpage/HTML configuration to be enabled.

For documentation-only edits outside those categories, check the diff, links,
command claims, and whitespace; no C build is needed. If no configured Makefile
is available, report that limitation; direct script checks are partial evidence.

Inspect diagnostics and `test-suite.log`, not just exit status.
After localized fixes, rerun affected checks and finish required checks; reuse valid
results with their scope/configuration recorded. Report commands, results, and
omissions precisely. Do not weaken checks.

Practracker checks size, include counts, and advisory dependencies, not
cyclomatic or cognitive complexity. Do not regenerate its exceptions merely to
pass. When available, run clang-tidy's
`readability-function-cognitive-complexity` check on affected code using the
configured build's compilation database:

```sh
clang-tidy -p /path/to/build \
  --checks='-*,readability-function-cognitive-complexity' \
  src/path/to/file.c
```

Compare diagnostics and high-risk hotspots with the baseline. Scores support
review, not lifecycle correctness; do not extract helpers solely to lower them.
Report unavailable optional tools or build information without making them
mandatory dependencies.

## Git and workspace care

- Check status and the intended base before editing. Base bug fixes on the
  appropriate supported maintenance branch for the affected versions.
- Preserve unrelated tracked, untracked, and ignored user files. Stage specific
  intended paths; avoid `git add .` and `git add -A`.
- Keep commits focused and explain the defect, resulting behavior, and relevant
  evidence. Do not invent sign-offs, ticket references, or review claims.
- Do not push, merge, publish, or change remote state without user instructions.
- Use temporary state and isolated local fixtures for tests. Do not use real Tor
  identity keys or private state, or run test traffic through the public Tor
  network as a substitute for local integration tests.
