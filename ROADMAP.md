# Bulwark Roadmap

## Current State (v0.5.0)

5 defense layers, 709 tests, Docker distribution, HTTP API, interactive dashboard with LLM backend config.

### Shipped
- 5 defense layers: Sanitizer, TrustBoundary, TwoPhaseExecutor, CanarySystem, MapReduceIsolator
- Pipeline orchestrator with async support
- 77 attack patterns across 10 categories
- Convenience API: `bulwark.clean()`, `bulwark.guard()`, `bulwark.protect()`
- HTTP API: `/v1/clean`, `/v1/guard`, `/v1/pipeline` (language-agnostic)
- Docker distribution: `docker run -p 3000:3000 bulwark`
- LLM backend config: Anthropic API, OpenAI-compatible (local inference), or sanitize-only
- Detection models: ProtectAI DeBERTa (ungated, ~30ms), PromptGuard-86M (gated)
- Production red team runner (Garak probes through real pipeline)
- Interactive dashboard with shield visualization, event stream, config management
- OpenAPI spec, contract specs with guarantee IDs, 7 ADRs
- Anthropic SDK integration via `protect()`
- `bulwark test` CLI with color output
- GitHub Actions CI (Python 3.11, 3.12, 3.13) + Docker build + GHCR publish
- Security audited, benchmarked (<1ms deterministic layers)

### Next
- **Dashboard auth** — bearer token for non-localhost deployments
- **Persistent config in Docker** — env var config, named volumes for data
- **LLM Guard integration** — broader scanner coverage (PII, toxicity)

### Future
- **Transparent proxy mode** — Bulwark as a reverse proxy between your app and the LLM provider. Zero-code integration.
- **Promptfoo CI eval pipeline** — assertion-based regression testing
- **CaMeL-style capability tracking** — fine-grained information flow control
- **More attack patterns** — expand from 77+ with community contributions

## Running Tests

```bash
PYTHONPATH=src python3 -m pytest tests/ -v
```

## Running the Dashboard

```bash
# From source
PYTHONPATH=src python -m bulwark.dashboard --port 3000

# Docker
docker run -p 3000:3000 nathandonaldson/bulwark
```
