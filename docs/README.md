# Bulwark Documentation

## Quick start

```bash
docker run -p 3000:3000 ghcr.io/nathandonaldson/bulwark
```

Dashboard at http://localhost:3000. See [Configuration](config.md) for env var setup.

## Guides

- [Configuration](config.md) — Docker env vars, YAML config, dashboard toggles
- [Dashboard](dashboard.md) — setup, event streaming, webhook integration
- [Detection plugins](detection.md) — ProtectAI DeBERTa, PromptGuard-86M, LLM Guard, custom classifiers
- [Per-layer usage](layers.md) — use individual layers without the full pipeline
- [Two-phase execution](two-phase.md) — direct executor setup, bridge configuration
- [Batch isolation](batch.md) — MapReduceIsolator for processing multiple items
- [Async support](async.md) — async pipelines, mixed sync/async callables
- [CLI reference](cli.md) — all commands and flags
- [Red teaming](red-teaming.md) — built-in attacks, production red team runner, Garak integration
- [Roadmap](../ROADMAP.md) — what's shipped, what's next
