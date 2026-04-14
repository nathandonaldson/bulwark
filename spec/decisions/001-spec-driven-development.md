# ADR-001: Spec-Driven Development

**Status:** Accepted
**Date:** 2026-04-14

## Context

Bulwark's first convenience APIs (clean, guard, protect) were built code-first. The plan was written, reviewed, and implemented in a single session. This worked for shipping fast but left no formal record of what the APIs guarantee, what they don't, or why they were designed that way.

For a security library, "what it doesn't guarantee" matters as much as what it does. A developer using `clean()` might assume it provides full prompt injection defense when it only provides 2 of 5 layers. Without formal specs, there's no machine-verifiable way to catch over-promises.

Three options for the OpenAPI spec:
- **A:** Generate Pydantic models from spec using `datamodel-code-generator` (adds a dep, build step)
- **B:** Hand-write spec and models separately, validate agreement in CI
- **C:** Pydantic models are the spec (Python-only, defeats language-agnostic goal)

Three options for contract test tracing:
- **A:** Generate test files from YAML (stale files when spec changes)
- **B:** Runtime pytest parametrize from YAML (opaque failures)
- **C:** Hand-written tests with guarantee IDs in docstrings, meta-test for coverage (traceable, debuggable)

## Decision

Spec-first development with Option B for OpenAPI and Option C for contracts.

The spec lives in `spec/openapi.yaml` (hand-written, language-agnostic). Pydantic models are hand-written to match. A CI test validates structural agreement — paths, field names, types — without requiring exact deep equality (FastAPI adds extra fields).

Contract YAMLs define guarantees (with IDs) and non-guarantees. Tests reference IDs in docstrings. A meta-test greps the test directory and asserts every guarantee ID has at least one test.

## Consequences

### Positive
- Language-agnostic spec enables Go/Node/Ruby clients
- Non-guarantees are formally documented, reducing false security assumptions
- CI catches spec/implementation drift automatically

### Negative
- Two sources to maintain (spec YAML + Pydantic models) — but only 2 endpoints worth
- Hand-written tests are more work than generated ones — but they're debuggable

### Neutral
- Existing 655 tests are not retroactively tagged — only public API tests get guarantee IDs
