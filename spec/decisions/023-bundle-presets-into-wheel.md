# ADR-023: Bundle `spec/presets.yaml` into the distribution wheel

**Status:** Accepted
**Date:** 2026-04-19

## Context

ADR-021 placed attack presets in `spec/presets.yaml` at the repo root, with `bulwark.presets._default_spec_path()` walking up from the installed module location to find it. That walk-up works in editable installs (`pip install -e .`) where the source tree remains intact, but fails in any installed-wheel environment — including the official Docker image, which installs the package into `/usr/local/lib/python3.11/site-packages/bulwark/` while `spec/` lives at `/app/spec/` (unreachable via parent walk).

The v1.3.0 Docker image shipped to the `v1.3.0` tag crashed on startup:

```
FileNotFoundError: spec/presets.yaml not found — checked from
/usr/local/lib/python3.11/site-packages/bulwark/presets.py
```

The smoke test correctly detected this, but the CI workflow published no image (the failure blocked the push step). `nathandonaldson/bulwark:1.3.0` was never created; `:latest` still points at `1.2.2`.

Any `pip install bulwark-shield` user hitting `load_presets()` — directly or via `bulwark.dashboard` — has the same crash.

ADR-021's stance that "presets are product documentation, not library data" remains correct as an authoring and versioning choice: the source of truth stays in `spec/`. But the *distribution* question — how does the file reach an installed runtime — was left unaddressed.

## Decision

Bundle `spec/presets.yaml` into the wheel at build time, at the path `bulwark/_data/presets.yaml`. Do not add a second source copy to `src/bulwark/_data/` — the file is not tracked there; it is copied only during `hatch build` via `[tool.hatch.build.targets.wheel.force-include]`.

The loader resolves the spec path in this order:

1. **`importlib.resources`** on the `bulwark` package — finds the wheel-bundled copy in installed environments.
2. **Walk-up from `__file__`** — finds `spec/presets.yaml` in editable installs and source checkouts.

If neither succeeds, `FileNotFoundError` is raised with both paths reported.

Contract: `G-PRESETS-007` — `load_presets()` succeeds in both editable and wheel-installed environments.

## Consequences

### Positive

- `nathandonaldson/bulwark:*` images start cleanly. `pip install bulwark-shield` works from any CWD.
- Single source of truth preserved: the file is authored in `spec/presets.yaml`; the wheel copy is a build artifact, not a tracked duplicate.
- Strategy chain is explicit and testable — each resolver is a pure function returning `Path | None`.

### Negative

- Hatch's `force-include` is the mechanism that makes this work; the wheel layout now has a `_data/` subdirectory inside the `bulwark` package that doesn't exist in the source tree. Readers of the built wheel will see a file that isn't in git.
- `importlib.resources` with `MultiplexedPath` has historically had quirks across Python versions; we pin to `>=3.11` (already required) where the API is stable.

### Neutral

- ADR-021's "spec is product documentation, not library data" framing is unchanged. Authoring, review, and versioning all happen in `spec/`. The wheel inclusion is purely a distribution concern.
