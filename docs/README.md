# Bulwark Documentation

## Quick start

```bash
docker run -p 3000:3000 nathandonaldson/bulwark
```

Dashboard at http://localhost:3000. See [Configuration](config.md) for env var setup.

## Guides

- [Configuration](config.md) — Docker env vars, YAML config, dashboard toggles
- [Dashboard](dashboard.md) — five tabs: Shield, Events, Configure, Leak Detection, Test
- [Detectors](detection.md) — DeBERTa (mandatory), PromptGuard, LLM Judge, custom classifiers
- [Per-layer usage](layers.md) — use individual layers without the full pipeline
- [Batch processing](batch.md) — recommended client-side concurrency pattern (no batch endpoint by design)
- [Async support](async.md) — calling `/v1/clean` from an async client
- [CLI reference](cli.md) — all commands and flags (`bulwark`, `bulwark_bench`, `bulwark_falsepos`)
- [HTTP API reference](api-reference.md) — `/v1/clean`, `/v1/guard`, `/healthz`, error codes, env vars
- [Red teaming](red-teaming.md) — built-in attacks, production red-team runner, false-positive harness
- [OpenClaw integration](openclaw.md) — Docker sidecar + plugin hooks
- [Wintermute integration](integrations/wintermute.md) — personal-agent integration via the Docker HTTP API, with request/response shape, canary handling, failure modes
- [Roadmap](../ROADMAP.md) — what's shipped, what's next
