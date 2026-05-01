# ADR-051: Drop PyPI as a distribution channel; Docker is canonical

**Status:** Accepted
**Date:** 2026-05-01

## Context

`bulwark-shield` was set up for PyPI publication early in the project (ADR-009 covered the package-name conflict with the unrelated `bulwark` package). A `.github/workflows/publish.yml` workflow existed for the publish flow.

As of 2026-05-01, the package has never been successfully published to PyPI:

- `https://pypi.org/pypi/bulwark-shield/json` returns 404.
- `https://pypi.org/simple/bulwark-shield/` returns 404.
- `publish.yml` ran 4 times in April 2026 (auto-fired on push at that time); every run failed. The workflow was then changed to `workflow_dispatch` only and has never been triggered manually.

Meanwhile, the operational reality:

- Docker (`nathandonaldson/bulwark:latest`) IS published, with a working multi-arch native build pipeline (ADR-049).
- Multiple docs and example files instruct users to `pip install bulwark-shield[...]`. Those instructions fail.

The choice is: re-attempt PyPI publication, or accept that Docker is the only distribution channel and stop pretending otherwise.

## Decision

Drop the PyPI surface entirely:

- Delete `.github/workflows/publish.yml`.
- Trim PyPI-display metadata from `pyproject.toml` (classifiers, PyPI URLs). Keep the `[project]` block for local source installs.
- Replace all "pip install bulwark-shield[...]" instructions in README, docs, and example docstrings with either Docker or "from source" (`git clone` + `pip install -e .`) variants.

The package can still be installed locally from a checkout via `pip install -e ".[extras]"`. The `bulwark`, `bulwark-bench`, and `bulwark-falsepos` console scripts continue to work after a source install. ADR-009's package-name decision is preserved historically; if PyPI publication is ever revisited, the name resolution work it captured is still applicable.

## Consequences

### Positive
- Docs stop lying. Every install instruction in the repo now resolves to something that works.
- One distribution channel = one source of truth. Versioning, deprecation, and migration messaging all aim at the Docker tag stream.
- Simpler `v3` story for the `bulwark.tools.*` migration (ADR-050) — no PyPI compat shim required.
- ~30 lines of CI YAML retired; no more failed `publish.yml` runs accruing.

### Negative
- Users who would have preferred `pip install` for embedding the library lose the easy path. They retain the `git clone` + `pip install -e .` route.
- The `protect()` SDK proxy and `Pipeline.from_config()` library entry points are now harder to consume from a Python project that doesn't already have Bulwark cloned.

### Neutral
- The `bulwark-shield` name remains reserved on PyPI (per the standard "no published version" convention — anyone could still register it, but they'd be impersonating). If future-you decides to publish, the workflow can be reconstituted from this ADR's git history.
