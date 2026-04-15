# Bulwark Roadmap

## Current State (v0.7.0)

5 defense layers, 811 tests, Docker distribution, HTTP API, interactive dashboard, OpenClaw integration, three-tier red teaming.

### Shipped
- 5 defense layers: Sanitizer, TrustBoundary, TwoPhaseExecutor, CanarySystem, MapReduceIsolator
- Pipeline orchestrator with async support
- 77 attack patterns across 10 categories
- Convenience API: `bulwark.clean()`, `bulwark.guard()`, `bulwark.protect()`
- HTTP API: `/v1/clean`, `/v1/guard`, `/v1/pipeline` (language-agnostic)
- Docker distribution: `docker run -p 3000:3000 nathandonaldson/bulwark`
- LLM backend config: Anthropic API, OpenAI-compatible (local inference), or sanitize-only
- Model dropdowns with short aliases that auto-resolve to latest version
- Detection models: ProtectAI DeBERTa (ungated, ~30ms), PromptGuard-86M (gated)
- Three-tier red teaming: Smoke Test (10), Standard Scan (~4k), Full Sweep (~33k) with dynamic counts from garak
- Two-tier verdict scoring: structural analysis check eliminates false positives (100% defense rate on full sweep)
- Retest failures from previous reports
- Report persistence with download
- Smart rate limiting (only delays probes that hit the LLM)
- Event emission from /v1/clean and /v1/guard to dashboard
- Smart status pill showing actual pipeline state + version
- OpenClaw integration: Docker sidecar + npm plugin with infrastructure-level hooks
- Security: SSRF validation on execution paths, API key masking, defense-disable protection, XSS escaping
- OpenAPI spec, contract specs with guarantee IDs, 12 ADRs
- Anthropic SDK integration via `protect()`
- `bulwark test` CLI with color output
- GitHub Actions CI + Docker Hub publish
- Security audited, benchmarked (<1ms deterministic layers)

### Next
- **Dashboard auth** — bearer token for non-localhost deployments
- **LLM Guard integration** — broader scanner coverage (PII, toxicity)
- **Transparent proxy mode** — Bulwark as a reverse proxy between your app and the LLM provider. Zero-code integration.
- **Docker hardening** — multi-stage build, non-root user
- **LLM-as-judge for edge cases** — cheap model call to classify ambiguous verdicts in red teaming

### Future
- **Promptfoo CI eval pipeline** — assertion-based regression testing
- **CaMeL-style capability tracking** — fine-grained information flow control
- **More attack patterns** — expand from 77+ with community contributions
- **OpenClaw TypeScript plugin** — deeper integration via `before_agent_reply` hooks (version-dependent)
