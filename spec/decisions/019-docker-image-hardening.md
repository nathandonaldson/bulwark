# ADR-019: Docker image hardening strategy

**Status:** Accepted (A+B; C deferred)
**Date:** 2026-04-17
**Branch:** `docker-hardening`

## Context

A CVE scan of `nathandonaldson/bulwark:latest` (v1.2.1) returns **1
critical + 7 high** vulnerabilities:

| Severity | CVE | Package | Fix version | Source |
|----------|-----|---------|-------------|--------|
| Critical (9.4) | CVE-2026-35030 | `litellm 1.82.6` | 1.83.0 | transitive via garak |
| High (8.7) | CVE-2026-35029 | `litellm 1.82.6` | 1.83.0 | transitive via garak |
| High (8.6) | GHSA-69x8-hrgq-fjj8 | `litellm 1.82.6` | 1.83.0 | transitive via garak |
| High (8.6) | CVE-2026-23949 | `jaraco.context 5.3.0` | 6.1.0 | transitive (setuptools family) |
| High (7.5) × 3 | CVE-2026-28388/28389/28390 | `openssl 3.5.5-1~deb13u1` | 3.5.5-1~deb13u2 | base (python:3.11-slim) |
| High (7.1) | CVE-2026-24049 | `wheel 0.45.1` | 0.46.2 | build tool |

**Observation:** 4 of 8 CVEs originate in the garak dependency tree,
which exists in the image purely to power optional red-team endpoints
(`/api/redteam/*`). Garak's direct dependencies include `litellm,
langchain, openai, boto3, cohere, mistralai, transformers, torch,
datasets, google-cloud-translate, nvidia-riva-client, ollama,
replicate, deepl, huggingface_hub, sentencepiece, accelerate` — forty
plus LLM-provider SDKs, most of which Bulwark's production pipeline
(`/v1/clean`, `/v1/guard`) never calls. Every one is a supply-chain
surface the production image didn't need to carry.

The OS-layer openssl CVEs stem from the pinned-point-release Debian
base; they resolve with a fresh `python:3.11-slim` pull.

Reference: Docker Hardened Images blog (shared by user) —
<https://www.docker.com/blog/why-we-chose-the-harder-path-docker-hardened-images-one-year-later/>

## Options

### (A) Two-image strategy — drop garak from the default image

Publish two images from the same codebase:

- `bulwark:latest` / `:vX.Y.Z` — **production image**. Installs
  `.[dashboard]` only. No garak, no transformers/torch, no LLM SDKs.
  All core endpoints (`/v1/clean`, `/v1/guard`, `/api/config`, etc.)
  work. `/api/redteam/tiers` already returns `{garak_installed:
  false, tiers: []}` when garak is missing — no code change needed
  there.
- `bulwark:bench` / `bulwark:bench-vX.Y.Z` — **full image**. Installs
  `.[dashboard,testing]`. Adds garak and the dep tree needed to run
  red teams from the dashboard UI or `bulwark_bench`.

**Pros**
- Removes ~4 of 8 current CVEs from `:latest` immediately (all the
  litellm ones, and most of the jaraco/wheel dep-tree noise gets
  smaller when garak is not installed).
- Production users (the majority — Wintermute integration, etc.)
  don't pay the CVE tax for a feature they don't use.
- Image size drops dramatically (torch alone is ~800 MB).
- Cleaner deployment story: `bulwark:latest` is narrow, `:bench` is
  opt-in.

**Cons**
- CI matrix complexity: two builds, two pushes.
- Dashboard UI needs to detect garak-missing and show an upgrade hint
  (currently just hides the red-team section silently).
- Docs need a "which image do I want?" section.
- Some users running in-dashboard red teams will be surprised on
  upgrade; needs a loud release note.

### (B) Just patch and rebuild

Stay on a single image. In `pyproject.toml`, override the transitive
pins:

```toml
[project.optional-dependencies]
dashboard = [..., "litellm>=1.83.0", "wheel>=0.46.2", "jaraco.context>=6.1.0"]
testing = ["garak>=0.9,<1.0", "litellm>=1.83.0"]
```

Rebuild with a freshly-pulled `python:3.11-slim` (new openssl).

**Pros**
- Small, fast, low-risk change. Addresses every CVE on the current
  list.
- No behavior change for users.

**Cons**
- Treadmill. Garak's forty-plus dep tree means a new CVE is likely
  monthly. This buys a few weeks.
- Pinning `litellm>=1.83.0` may conflict with garak's own pin if
  garak hasn't updated; we'd need to verify resolvability.

### (C) Docker Hardened Image / Chainguard base

Swap `python:3.11-slim` for a minimally-scoped base (Chainguard's
`cgr.dev/chainguard/python:latest-dev` for build, `:latest` for
runtime; or Docker Scout's DHI tier).

**Pros**
- Near-zero OS-layer CVEs going forward; images get automatic
  rebuilds when CVEs land upstream.
- Tiny image size, no apt, no shell in the runtime layer.
- Compounds with (A) for a minimal attack surface end-to-end.

**Cons**
- `apt-get install -y gcc rustc cargo libffi-dev` in the current
  builder doesn't translate to Chainguard's apk/minimal-glibc model.
  Need to rework the builder stage.
- Subscription cost for Docker DHI (unless Chainguard's free dev
  images are acceptable; those are copyleft-licensed and should be
  fine for MIT Bulwark).
- First-time conversion is a day's work. Ongoing maintenance is
  cheaper but the switch is painful.

## Recommendation (draft — not yet decided)

**Ship (A) + (B) near-term, defer (C).**

1. Split images so `:latest` loses the garak dep tree. Biggest win.
2. Patch remaining CVEs in `:latest` via version pins + base rebuild.
3. Add CI step: CVE scan `:latest` on every PR, fail the build on
   new critical/high. Stops this from silently regressing.
4. Revisit (C) once (A) lands — the DHI rework is much smaller once
   the image has dropped torch/litellm/friends.

## Open questions

- How many users actually use the in-dashboard red team vs
  `bulwark_bench` from source? If most do, `:bench` becomes the
  "normal" image and the split is less compelling. Check download
  stats / issues.
- Is garak's own `litellm` pin floor below 1.83.0? If so, (B) may
  require opening a PR on garak or vendoring a pin override.
- Wintermute and other downstream consumers: confirm none depend on
  garak being in the production image.

## Non-goals for this ADR

- **Image size optimization for its own sake.** The goal here is CVE
  surface, not binary size. Size shrinks as a side effect of (A).
- **Switching from Python to Rust/Go.** The core-lib is zero-dep
  Python by design; no rewrite is on the table.
- **Removing the dashboard.** Dashboard stays in `:latest`; only the
  optional red-team/garak deps leave.
