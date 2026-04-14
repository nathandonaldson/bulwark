# ADR-009: Package Rename to bulwark-shield

**Status:** Accepted
**Date:** 2026-04-14

## Context

The original PyPI package name "bulwark-ai" worked but was generic. We wanted to shorten to "bulwark" for branding, but "bulwark" is taken on PyPI (v0.6.1, a defensive data analysis package).

## Decision

Rename the PyPI package to "bulwark-shield". The Docker image name remains "bulwark" (no conflict in container registries). Branding in docs and UI uses "Bulwark" (capital B, no suffix).

Checked and confirmed available on PyPI: bulwark-defense, bulwark-sec, bulwark-guard, bulwark-shield. Chose "bulwark-shield" because it matches the dashboard's shield visualization.

## Consequences

- `pip install bulwark-shield` replaces `pip install bulwark-ai`
- All import paths remain `import bulwark` (unchanged)
- Docker image is `ghcr.io/nathandonaldson/bulwark` (no conflict)
- Existing users of bulwark-ai need to change their pip install command
