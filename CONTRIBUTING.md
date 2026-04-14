# Contributing to Bulwark

## Spec-First Development

Bulwark follows spec-driven development. The spec is the source of truth. If the implementation diverges from the spec, the implementation is wrong.

### For new API endpoints

1. **Write the OpenAPI spec first** — add the endpoint to `spec/openapi.yaml` with request/response schemas before writing any Python code
2. **Write contract specs** — add guarantee and non-guarantee entries to `spec/contracts/` for the new endpoint
3. **Write tests referencing guarantee IDs** — each test docstring must include the guarantee ID (e.g., `"""G-HTTP-CLEAN-001: Returns sanitized content."""`)
4. **Implement to make the tests pass**
5. **Verify spec compliance** — `test_spec_compliance.py` enforces that every spec path exists in the app and every guarantee has a test

### For new Python functions

1. **Write the contract spec first** — add a YAML file to `spec/contracts/` with guarantees, non-guarantees, and error conditions
2. **Write tests referencing guarantee IDs**
3. **Implement to make the tests pass**

### For design decisions

Record significant decisions in `spec/decisions/` using the ADR template. Key decisions that should be recorded:
- New API design choices (response codes, field names, error formats)
- Architectural changes (new layers, changed pipeline order)
- Things we chose NOT to do and why

### Contract spec format

```yaml
function: bulwark.example
version: "0.5.0"

guarantees:
  - id: G-EXAMPLE-001
    summary: What this function promises to do

non_guarantees:
  - id: NG-EXAMPLE-001
    summary: What this function explicitly does NOT promise
    reason: Why this is intentionally not guaranteed
```

Non-guarantees matter as much as guarantees for a security library. They prevent users from relying on behavior that may change.

### CI enforcement

The meta-tests in `tests/test_spec_compliance.py` run automatically and enforce:
- Every path in `spec/openapi.yaml` exists in the running FastAPI app
- Every request field in the spec matches the Pydantic model
- Every guarantee ID in `spec/contracts/*.yaml` has at least one test
- No duplicate guarantee IDs across contracts

### What doesn't need a spec

- Internal implementation details (private functions, helper modules)
- Dashboard UI changes (HTML/CSS/JS)
- Configuration changes (config.py fields)
- Bug fixes that don't change the public API

## Testing

Run the full test suite:

```bash
PYTHONPATH=src python3 -m pytest tests/ -v
```

Run just the spec compliance tests:

```bash
PYTHONPATH=src python3 -m pytest tests/test_spec_compliance.py -v
```

## Architecture

See `spec/decisions/` for ADRs explaining key design choices. The main ones:

- **ADR-001**: Spec-driven development (this process)
- **ADR-002**: Two-phase execution architecture
- **ADR-003**: Convenience API tiers (clean/guard -> protect -> Pipeline)
- **ADR-007**: HTTP API response codes (always 200 for completed analysis)
- **ADR-008**: Docker distribution
- **ADR-009**: Package rename to bulwark-shield
