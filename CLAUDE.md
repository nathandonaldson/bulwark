# Bulwark Shield

Prompt injection defense through architecture, not detection.

## Spec-driven development (MANDATORY — DO NOT SKIP)

This rule has been violated 4 times. It is not optional.

BEFORE writing ANY implementation code in this repo:

1. **Spec first.** Update `spec/openapi.yaml` for any new or changed HTTP endpoints.
2. **Contracts first.** Write or update `spec/contracts/*.yaml` with guarantee IDs and non-guarantees.
3. **ADRs for decisions.** Record design decisions in `spec/decisions/NNN-title.md`.
4. **Tests first.** Write tests referencing guarantee IDs (e.g., `G-HTTP-HEALTHZ-001`).
5. **Then implement.** Make the tests pass.

If you find yourself writing implementation before specs, STOP. Delete what you wrote and start over with the spec. "I'll backfill later" is not acceptable. It has failed every time.

See `CONTRIBUTING.md` for the full process. `tests/test_spec_compliance.py` enforces spec/implementation agreement in CI.

## Running tests

```bash
PYTHONPATH=src python3 -m pytest tests/ -v
```

## Running the dashboard

```bash
# From source
PYTHONPATH=src python -m bulwark.dashboard --port 3000

# Docker
docker run -p 3000:3000 ghcr.io/nathandonaldson/bulwark
```

## Project structure

- `src/bulwark/` — Core library (zero dependencies)
- `src/bulwark/dashboard/` — FastAPI dashboard and HTTP API
- `spec/openapi.yaml` — HTTP API contract (source of truth)
- `spec/contracts/` — Function guarantees and non-guarantees
- `spec/decisions/` — Architecture Decision Records
- `tests/` — 718 tests including spec compliance enforcement

## Package name

PyPI: `bulwark-shield` (the name `bulwark` is taken on PyPI by a data analysis package)
Docker: `ghcr.io/nathandonaldson/bulwark`
Import: `import bulwark`
