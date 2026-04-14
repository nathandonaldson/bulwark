# ADR-008: Docker Distribution

**Status:** Accepted
**Date:** 2026-04-14

## Context

Bulwark was only available via pip install, requiring a Python environment. Non-Python developers (Go, Node, Ruby) couldn't use the HTTP API without setting up Python, a venv, and installing dependencies. Docker would let anyone run Bulwark as a service with one command.

## Decision

Ship a single Docker image containing the dashboard and all v1 API endpoints. Single-stage build from python:3.11-slim. No detection models pre-loaded (keeps image under 150MB compressed). Config and event data are ephemeral (no volume mounts in v1).

The image name is "bulwark" (not "bulwark-shield") because Docker image names don't conflict with PyPI package names.

GHCR (GitHub Container Registry) for publishing, triggered by version tags in CI.

## Alternatives Considered

- **Multi-stage build:** Unnecessary for pure Python. No compiled assets to discard.
- **API-only image (no dashboard):** Dashboard is the product differentiation. The visual demo sells Bulwark.
- **Pre-loaded detection models:** Would make the image 400MB+. Users opt in via the dashboard.
- **Transparent proxy mode:** Deferred to future. Ship the container first, validate demand.

## Consequences

- Non-Python developers can use Bulwark via `docker run -p 3000:3000 bulwark`
- Config changes via the dashboard are lost on container restart (by design in v1)
- Detection models and red teaming work but require additional setup inside the container
- The adoption funnel gains a new entry point parallel to pip install
