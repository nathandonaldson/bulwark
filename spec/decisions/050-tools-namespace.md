## ADR-050: Collapse sister packages into `bulwark.tools.{bench, falsepos}`

**Status:** Accepted
**Date:** 2026-05-01

## Context

`bulwark_bench` (ADR-034) and `bulwark_falsepos` (ADR-036) shipped as
top-level sibling packages under `src/`. The framing was "three
independent packages"; the reality, on inspection, was different:

- `bulwark_falsepos` hard-imported from `bulwark_bench` at 5 sites
  (`__main__.py`, `runner.py`, plus 3 test files). It cannot be
  installed without `bulwark_bench`.
- `bulwark.dashboard.app` hard-imported from `bulwark_falsepos.corpus`
  at 3 sites — the False-Positives tier card on the Test page is wired
  to that module's `load_corpus` / `categories`. The dashboard
  package was therefore not independent of the falsepos package.
- Both packages shipped in the **same wheel** (`pyproject.toml`
  `[tool.hatch.build.targets.wheel] packages` listed all three roots),
  versioned through one `VERSION`, tested in one `tests/` tree, and
  documented in one `CHANGELOG`.
- Concrete duplication in the runners: `_safe_id`, `_persist`,
  `_snapshot`, `_restore`, the `_run_one_*` orchestration shell,
  `stderr_progress`, the argparse plumbing, and the `render_json`
  scaffolding plus `_fmt_pct` were duplicated across two places. The
  CHANGELOG already shows the cost: ADR-038's error classification
  fix (v2.3.2) had to land in two files.

In addition, `pricing.py` (95 LOC) was already deleted in v2.5.11
(Batch 1) per ADR-034 §"Cost reporting drops out".

The "independent sister packages" model added structural drag without
delivering the independence it advertised. No external user imports
either package as a library — both are CLI/HTTP tools — so there is
no constituency for separate distributions.

## Decision

Collapse the two sister packages into the main package's `tools`
sub-namespace:

```
src/bulwark_bench/         → src/bulwark/tools/bench/
src/bulwark_falsepos/      → src/bulwark/tools/falsepos/
src/bulwark/tools/__init__.py    (new, brief docstring)
```

Move via `git mv` to preserve history. Internal imports updated to
the new dotted paths; `bulwark_falsepos.runner` now imports
`DetectorConfig` from `bulwark.tools.bench.configs`, and so on.

`bulwark.dashboard.app` updates its 3 import sites to the new path,
and its `importlib.resources.files(...)` lookup for the bundled
corpus moves from `bulwark_falsepos / _data / falsepos_corpus.jsonl`
to `bulwark.tools.falsepos / _data / falsepos_corpus.jsonl` — matching
the `[tool.hatch.build.targets.wheel.force-include]` change.

Console scripts are unchanged on `$PATH`:

- `bulwark-bench` → `bulwark.tools.bench.__main__:main`
- `bulwark-falsepos` → `bulwark.tools.falsepos.__main__:main`

### Back-compat shims (one release)

`src/bulwark_bench/` and `src/bulwark_falsepos/` are kept as ~15 LOC
shim packages whose `__init__.py` re-exports the moved submodules and
whose `__main__.py` delegates to the new entry point. This keeps:

- `python -m bulwark_bench` / `python -m bulwark_falsepos`
- `from bulwark_bench import …` / `from bulwark_bench.configs import …`
- `from bulwark_falsepos.corpus import …`

working for v2.5.x without code changes on the caller side. The
shims are registered in `pyproject.toml`'s wheel `packages` list so
they ship in the same wheel.

The shims will be removed in v3 (next major). Migration: switch
imports to `bulwark.tools.bench` / `bulwark.tools.falsepos`. The
console scripts (`bulwark-bench`, `bulwark-falsepos`) are stable
across both major versions.

## Consequences

### Positive

- ~250 LOC saved net across `src/`: 95 LOC of dead `pricing.py`
  already gone in Batch 1, plus the structural collapse opens a path
  to dedupe `_safe_id` / `_persist` / `_snapshot` / `_restore` /
  `stderr_progress` / `render_json` scaffolding when they next need
  edits, minus ~30 LOC of back-compat shims.
- Single source of truth for the shared `BulwarkClient`,
  `DetectorConfig` preset list, and the snapshot/restore pattern.
  Bug fixes in the runner pipeline land in one place, not two.
- Dashboard ↔ tools coupling is now expressed in the import path
  (`from bulwark.tools.falsepos.corpus import …`) rather than papered
  over with a top-level cross-package import that pretended the
  packages were independent.
- 3 → 1 top-level `src/` package after the shims expire in v3.

### Negative

- One release of back-compat shims (ADR-050 explicitly time-boxes
  these to v2.5.x). The shims register synthetic `sys.modules`
  entries so `from bulwark_bench.configs import X` continues to
  resolve to the real module — small but non-zero complexity.
- Spec contract files (`spec/contracts/bulwark_bench.yaml`,
  `spec/contracts/bulwark_falsepos.yaml`) keep their feature names
  (the user-facing CLI prog names did not change). Guarantee IDs
  (`G-BENCH-*`, `G-FP-*`) are unchanged, so contract regression
  tests stay green.

### Neutral

- The `[tool.hatch.build.targets.wheel.force-include]` entry for
  `falsepos_corpus.jsonl` now writes to
  `bulwark/tools/falsepos/_data/falsepos_corpus.jsonl` — the new
  package-resource layout. The dashboard's resource lookup matches.
- Console-script entry points changed in `pyproject.toml`, but the
  script names on `$PATH` are stable. End-user behaviour is identical.
