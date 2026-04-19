# Bulwark Shield

Prompt injection defense through architecture, not detection.

## Spec-driven development (MANDATORY)

Every new feature follows this sequence. Complete each step before moving to the next.

1. **Start with the spec.** Update `spec/openapi.yaml` for any new or changed HTTP endpoints.
2. **Write the contract.** Create or update `spec/contracts/*.yaml` with guarantee IDs and non-guarantees.
3. **Record the decision.** Add an ADR in `spec/decisions/NNN-title.md` when making architectural choices.
4. **Write the tests.** Reference guarantee IDs (e.g., `G-HTTP-HEALTHZ-001`). Watch them fail.
5. **Implement.** Make the tests pass.

This is the workflow. Spec first, then contract, then tests, then code. Every time.

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
docker run -p 3000:3000 nathandonaldson/bulwark
```

## Project structure

- `src/bulwark/` — Core library (zero dependencies)
- `src/bulwark/dashboard/` — FastAPI dashboard and HTTP API
- `spec/openapi.yaml` — HTTP API contract (source of truth)
- `spec/contracts/` — Function guarantees and non-guarantees
- `spec/decisions/` — Architecture Decision Records
- `tests/` — 1020 tests including spec compliance enforcement

## Package name

PyPI: `bulwark-shield` (the name `bulwark` is taken on PyPI by a data analysis package)
Docker: `nathandonaldson/bulwark`
Import: `import bulwark`
