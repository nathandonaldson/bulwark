# ADR-024: Contracts for core defense modules

**Status:** Accepted
**Date:** 2026-04-20

## Context

The v1.3.1 SDD audit revealed a two-tier test culture:

- **Spec-driven (tier 1):** HTTP endpoints, presets, red-team tiers, dashboard UI — every test references a `G-*-NNN` guarantee ID, and `test_spec_compliance.py::test_every_guarantee_has_test` enforces coverage both ways.
- **Implementation-driven (tier 2):** the four core defense modules — `sanitizer`, `isolator`, `executor`, `validator` — have ~2,700 lines of tests across ~246 test methods, and **zero** guarantee IDs. They are exhaustively tested at the unit level, but the behaviours they enforce are nowhere documented as a contract.

This matters because:

- These modules are the *substance* of Bulwark's defense. The HTTP API is a thin wrapper; the defense itself is `sanitize → wrap → analyze → guard → execute → canary-check` — mostly inside these four modules.
- Without contracts, a well-intentioned refactor can quietly drop a behaviour that attackers (or integrators) rely on. No test would name what was lost.
- New contributors reading `test_sanitizer.py` learn the implementation, not the promise.
- Downstream integrators (Wintermute et al.) consume these modules via `from bulwark import sanitize`. They have no spec to read.

ADR-021 made the case for contracts being "product documentation, not library data" for attack presets. The same argument applies here with more force: the defense guarantees *are* the product.

## Decision

Write contracts for all four core defense modules, with guarantee IDs following the pattern `G-<MODULE>-NNN`:

- `spec/contracts/sanitizer.yaml` — 16 guarantees, 4 non-guarantees
- `spec/contracts/isolator.yaml` — 12 guarantees, 3 non-guarantees
- `spec/contracts/executor.yaml` — 13 guarantees, 3 non-guarantees
- `spec/contracts/validator.yaml` — 12 guarantees, 3 non-guarantees

Total: **53 new guarantees, 13 new non-guarantees**.

Tag each existing test with its guarantee ID via docstring (for test methods that map to one specific guarantee) or class-level docstring (where a `TestClass` exists specifically to test one guarantee). No test logic is rewritten — tests are being *linked* to guarantees that already describe what they enforce.

`test_every_guarantee_has_test` then enforces coverage the same way it does for HTTP contracts: every `G-*` ID must appear in at least one `test_*.py` file.

### What this is NOT
- Not a per-function contract. A guarantee describes a behaviour, not an API surface. Multiple private helpers may share one guarantee; one public function may split across several.
- Not a rewrite. Existing tests stay; they gain a reference.
- Not a policy that every Python module needs a contract. Modules that are pure glue or that expose only internal helpers (e.g., `_data/`, `shortcuts`) stay contract-less.

## Consequences

### Positive
- Every behaviour the defense promises is written down in one place and enforced by at least one test.
- Refactors that silently break a guarantee now fail CI — the guarantee ID's test-presence check ensures somebody has to either remove the guarantee from the contract (public statement) or fix the refactor.
- Contributors can read a contract and know what the module promises without trawling 800 lines of tests.
- Integrators get a versioned, machine-readable description of the defense surface.

### Negative
- Four new contract files, 66 new IDs. Contract drift is now possible in more places — the `test_every_guarantee_has_test` check is the mitigation.
- Some guarantees are coarser than the test suite (e.g., `G-SANITIZER-002` covers 7 tests). If someone adds a new test that doesn't fit any existing guarantee, they'll need to decide: add it to an existing guarantee's scope, or propose a new one. This is the point.

### Neutral
- Prune candidates surfaced during the audit (~2 pairs of near-duplicate tests per module) are left alone in this change. Pruning is a separate decision; tagging first lets us see the redundancy against a labelled baseline.
- Gap candidates (e.g., multi-timeout in `isolator`, no-canary path in `executor`) are documented in the audit report but not filled in this change — that's new test work, not contract work.
