# ADR-049: Native arm64 runner for docker-publish

**Status:** Accepted
**Date:** 2026-04-30

## Context

`docker-publish.yml` produced multi-arch images by building both `linux/amd64` and `linux/arm64` inside a single job on `ubuntu-latest` (amd64). The arm64 leg ran under QEMU emulation via `docker/setup-qemu-action`. With torch + transformers wheels in the image, every layer was expensive in emulated mode.

Past tag-push wall times (each preceded a Docker Hub publish):

| Tag    | Wall time |
|--------|-----------|
| v2.3.0 | 82 min    |
| v2.3.1 | 88 min    |
| v2.3.2 | 61 min    |
| v2.5.8 | ~85 min   |

Almost all of that time was the emulated arm64 leg. The amd64 leg alone (which is what PR/branch pushes run) historically takes ~13 min.

In January 2025 GitHub made `ubuntu-24.04-arm` available for free in public repositories. The runner remains in public preview — there is no GA announcement, no deprecation notice — and queue times are reportedly longer at peak hours, but for an occasional tag-push that's acceptable.

## Decision

Split `docker-publish.yml` into three jobs:

1. **`build-amd64`** (`ubuntu-latest`, native).
   On every trigger (PR, tag, dispatch): builds amd64, runs the smoke test against the loaded image.
   On tag-push or `workflow_dispatch` only: pushes amd64 by digest.

2. **`build-arm64`** (`ubuntu-24.04-arm`, native, gated by job-level `if`).
   Skipped on PR runs to keep PR cost ~13 min and conserve arm64 runner-minutes.
   On tag-push or `workflow_dispatch`: builds arm64 and pushes by digest.

3. **`manifest`** (`ubuntu-latest`, gated by job-level `if`).
   Skipped on PR runs.
   On tag-push: stitches the two digests under `IMAGE:VERSION` + `IMAGE:latest` via `docker buildx imagetools create`.
   On `workflow_dispatch`: stitches under `IMAGE:latest` only.

GHA cache is scoped per-arch (`scope=amd64`, `scope=arm64`) so PR amd64 cache hits don't compete with tag-push arm64 cache, and a flake on one arch doesn't poison the other.

## Consequences

### Positive
- Tag-push wall time drops from ~85 min to ~15 min (estimate; both arch legs build native in parallel, and the manifest stitch is seconds).
- Arm64 image is a faithful native build, not a QEMU emulation. Bit-for-bit reproducibility on real Graviton-class hardware is now expected.
- PR builds unchanged (~13 min, amd64 only), and arm64 runner-minutes are not consumed for unmerged work.
- Per-arch cache scopes isolate failure modes and avoid the pathological case where a partial arm64 layer evicts amd64 cache.

### Negative
- Three jobs instead of one: more YAML, three sets of `actions/checkout` + `setup-buildx`. Net wall time still wins by ~70 min per release.
- `ubuntu-24.04-arm` remains in public preview as of January 2025 with no GA ETA. If GitHub ever moves it behind a paid tier, this workflow needs to revert to QEMU emulation or accept the cost — but historical precedent (the existing free amd64 runners) suggests free public-repo access is sticky.
- First post-migration run is a full cache miss on both legs.

### Neutral
- Smoke test still runs on amd64 only. arm64 builds without smoke. If an arm64-specific regression ever matters (FFI, native deps), duplicate the smoke test step in `build-arm64`.
- Image tags on Docker Hub remain bare semver (`2.5.9`, `latest`). The manifest job still strips the `v` prefix from `refs/tags/vX.Y.Z`.
- The smoke-test step's invariants (G-PRESETS-007, ADR-038, ADR-040) are preserved verbatim — only the surrounding workflow shape changed.

## Validation

The next tag push (v2.5.9 carrying this change) is the regression test. Expected outcome:
- `build-amd64` ≤ ~15 min, smoke test green.
- `build-arm64` ≤ ~15 min on native Graviton-class.
- `manifest` < 1 min, both `:VERSION` and `:latest` updated on Docker Hub.

If `ubuntu-24.04-arm` queue depth at the time of v2.5.9's tag is unusually high, the arm64 leg may still be slow — that's a runner-availability problem, not a workflow-design problem, and revisit only if it recurs.
