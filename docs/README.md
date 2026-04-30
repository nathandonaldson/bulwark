# Bulwark Documentation

## Quick start

```bash
docker run -p 3000:3000 nathandonaldson/bulwark
```

Dashboard at <http://localhost:3000>. See [Configuration](config.md) for env var setup.

## Which port am I on?

Three ports show up across this project. The right one depends on how
you're running Bulwark:

| Surface                                    | Port | Where used                                          |
|--------------------------------------------|------|-----------------------------------------------------|
| Docker image (`nathandonaldson/bulwark`)   | 3000 | Default `docker run -p 3000:3000` and every example here. |
| Source-tree dev (`python -m bulwark.dashboard`) | 3001 | Local hacking only; reserved in `CLAUDE.md`.   |
| OpenClaw sidecar                           | 8100 | Per [`integrations/openclaw/docker-compose.bulwark.yml`](../integrations/openclaw/docker-compose.bulwark.yml). |

If a doc shows `localhost:3000`, you're reading the Docker contract.
Source-tree devs swap in `:3001`; OpenClaw operators swap in `:8100`.
Wintermute and other HTTP integrations pin to `:3000` — see
[`integrations/wintermute.md`](integrations/wintermute.md).

## Guides

- [Configuration](config.md) — Docker env vars, YAML config, dashboard toggles
- [Dashboard](dashboard.md) — five tabs: Shield, Events, Configure, Leak Detection, Test
- [Detectors](detection.md) — DeBERTa (mandatory), PromptGuard, LLM Judge, custom classifiers
- [Python library](python-library.md) — `bulwark.clean()`, `Pipeline.from_config()`, entry-point comparison
- [Per-layer usage](layers.md) — use individual layers without the full pipeline
- [Batch processing](batch.md) — recommended client-side concurrency pattern (no batch endpoint by design)
- [Async support](async.md) — calling `/v1/clean` from an async client
- [CLI reference](cli.md) — all commands and flags (`bulwark`, `bulwark_bench`, `bulwark_falsepos`)
- [HTTP API reference](api-reference.md) — `/v1/clean`, `/v1/guard`, `/healthz`, error codes, env vars
- [Red teaming](red-teaming.md) — built-in attacks, production red-team runner, false-positive harness
- [OpenClaw integration](openclaw.md) — Docker sidecar + plugin hooks
- [Wintermute integration](integrations/wintermute.md) — personal-agent integration via the Docker HTTP API, with request/response shape, canary handling, failure modes
- [Roadmap](../ROADMAP.md) — what's shipped, what's next
