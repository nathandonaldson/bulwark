# Bulwark Roadmap

## Current State (v1.0.1)

5 defense layers, 843 tests, Docker distribution, unified HTTP API, dashboard with auth, OpenClaw integration, three-tier red teaming.

### Shipped
- 5 defense layers: Sanitizer, TrustBoundary, TwoPhaseExecutor, CanarySystem, MapReduceIsolator
- Pipeline orchestrator with async support
- 77 attack patterns across 10 categories
- Convenience API: `bulwark.clean()`, `bulwark.guard()`, `bulwark.protect()`
- Unified HTTP API: `/v1/clean` runs full defense stack, `/v1/guard` checks output (language-agnostic)
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
- Dashboard bearer token auth via BULWARK_API_TOKEN
- Docker hardening: multi-stage build, non-root user, no build tools in final image
- Env vars override config file (Docker .env always wins)
- Security: SSRF validation on execution paths, API key masking, defense-disable protection, XSS escaping
- OpenAPI spec, contract specs with guarantee IDs, 12 ADRs
- Anthropic SDK integration via `protect()`
- `bulwark test` CLI with color output
- GitHub Actions CI + Docker Hub publish
- Security audited, benchmarked (<1ms deterministic layers)

### Next
- **LLM Guard integration** — broader scanner coverage (PII, toxicity)
- **Transparent proxy mode** — Bulwark as a reverse proxy between your app and the LLM provider. Zero-code integration.
- **LLM-as-judge for edge cases** — cheap model call to classify ambiguous verdicts in red teaming

### Future
- **Promptfoo CI eval pipeline** — assertion-based regression testing
- **CaMeL-style capability tracking** — fine-grained information flow control
- **More attack patterns** — expand from 77+ with community contributions
- **OpenClaw TypeScript plugin** — deeper integration via `before_agent_reply` hooks (version-dependent)
