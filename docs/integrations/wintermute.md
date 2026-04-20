# Wintermute ↔ Bulwark integration

Wintermute is a personal agent that handles real untrusted content — inbound email, shared documents, arbitrary web pages — before handing it to an LLM. Bulwark runs as a local Docker sidecar on `localhost:3000` and every bit of external content flows through `POST /v1/clean` before the agent trusts it.

This guide documents what Wintermute expects from Bulwark and how the two programs stay correct as Bulwark evolves.

## Why Bulwark runs as a sidecar

The trust boundary is the Docker image. Bulwark's internals (sanitizer, trust boundary tags, two-phase executor, canary system) change on their own schedule; Wintermute only sees the HTTP contract in [`spec/openapi.yaml`](../../spec/openapi.yaml). This means:

- Wintermute pins `nathandonaldson/bulwark:1.3.2` (or newer) and knows exactly what endpoints it gets.
- Bulwark can rewrite its defense layers without breaking Wintermute as long as the HTTP contract holds.
- Wintermute never sees raw LLM credentials — they live in the sidecar's `.env`.
- If something in Bulwark crashes, Wintermute sees an HTTP error and can fail safe, not partially-executed.

## Architecture

```
 ┌──────────────┐   POST /v1/clean    ┌─────────────────────┐   analyze/execute    ┌─────────┐
 │  Wintermute  │ ─────────────────▶  │   Bulwark sidecar   │ ───────────────────▶ │   LLM   │
 │    agent     │ ◀─────────────────  │  localhost:3000     │ ◀─────────────────── │         │
 └──────────────┘  { result, blocked, └─────────────────────┘                      └─────────┘
                    analysis, … }
```

Every piece of untrusted content — an email body, a document a user pasted in, a web page the agent was asked to summarise — becomes one `POST /v1/clean` call. The response tells Wintermute whether to proceed and with what content.

## Deploying the sidecar

Wintermute ships a `docker-compose.yml` (adapted from [the one in this repo](../../docker-compose.yml)) that:

1. Pins an exact Bulwark version (`nathandonaldson/bulwark:1.3.2`, bumped deliberately — never `:latest`).
2. Binds `~/.config/wintermute/bulwark-config.yaml` into the container so canaries + guard patterns survive `docker rm`.
3. Reads Bulwark's LLM credentials from a sidecar-local `.env` that Wintermute's own code never touches.
4. Sets a healthcheck against `/healthz`; Wintermute's startup sequence waits for `healthy` before issuing the first `/v1/clean`.

Minimum viable sidecar compose:

```yaml
services:
  bulwark:
    image: nathandonaldson/bulwark:1.3.2
    container_name: bulwark
    restart: unless-stopped
    ports:
      - "3000:3000"
    volumes:
      - ${HOME}/.config/wintermute/bulwark-config.yaml:/app/bulwark-config.yaml
    env_file:
      - bulwark.env
    healthcheck:
      test: ["CMD", "python", "-c", "import urllib.request; urllib.request.urlopen('http://localhost:3000/healthz')"]
      interval: 30s
      timeout: 5s
      start_period: 10s
      retries: 3
```

The `bulwark.env` file provides `BULWARK_LLM_MODE`, `BULWARK_API_KEY`, `BULWARK_BASE_URL`, `BULWARK_ANALYZE_MODEL`, `BULWARK_EXECUTE_MODEL`, and — if the LLM lives on a LAN IP — `BULWARK_ALLOWED_HOSTS` to satisfy the SSRF guard.

## The one call that matters: POST /v1/clean

This is the entire hot path. Wintermute issues it once per piece of external content.

### Request

```json
{
  "content": "Hello Nathan\u200b\u200cI\u200dg\u200en...",
  "source": "email",
  "label": "inbound_from_external_contact",
  "max_length": 10000,
  "canary_tokens": null
}
```

- `content` *(required)* — the untrusted text. Anything that didn't come from the agent's own prompts is untrusted.
- `source` *(default `"external"`)* — a short name for the origin. Ends up in the trust-boundary tag name, so pick something meaningful (`"email"`, `"web"`, `"document"`).
- `label` *(optional)* — extra context for the trust-boundary tag. Wintermute uses this to distinguish inbound email from user-pasted content inside the same `source="external"` bucket.
- `max_length` *(optional)* — override the sanitizer's default 3000-char cap. Wintermute sets this per source type; documents get more, chat messages get less.
- `canary_tokens` *(optional)* — per-request canary override. Normally null; Wintermute relies on the sidecar's `canary_tokens` config set via `bulwark canary add`.

### Response (200 — safe)

```json
{
  "result": "<untrusted_external source=\"email\" treat_as=\"data_only\">\nHello Nathan\n...\n</untrusted_external>",
  "blocked": false,
  "modified": true,
  "source": "external",
  "format": "xml",
  "content_length": 246,
  "result_length": 312,
  "analysis": "...",
  "execution": "...",
  "block_reason": null
}
```

### Response (422 — blocked)

```json
{
  "result": null,
  "blocked": true,
  "block_reason": "Canary token leaked from: prod_db_url, prod_aws_key",
  "analysis": "...the LLM's phase 1 output which echoed the canary...",
  "execution": null
}
```

### What Wintermute does with each field

- `blocked: true` — **stop**. Do not feed this content to any downstream tool or LLM. Log `block_reason` and the source identifier; surface it to the user with a "could not safely process" message. Never retry with less careful settings.
- `blocked: false, modified: true` — proceed with `result`, not the original `content`. The sanitizer removed something (zero-width chars, HTML, bidi controls, etc.). The removal *is* the defense; the original content must not be retrieved.
- `blocked: false, modified: false` — content was already clean. `result` equals the wrapped-but-unmodified input.
- `analysis` / `execution` — present only when Bulwark's two-phase LLM is configured. Wintermute uses these directly as the LLM output rather than making its own LLM call, because the sidecar's LLM has already processed the content with the full defense stack applied.

### Status codes Wintermute checks

| HTTP | Meaning | Wintermute action |
|------|---------|-------------------|
| 200  | Safe (possibly sanitized) | Use `result` / `analysis` / `execution` |
| 422  | Injection / canary / guard block | Log `block_reason`, surface "could not process" to the user |
| 401  | Auth required (if `BULWARK_API_TOKEN` set) | Ops problem — alert and retry with the header |
| 5xx  | Bulwark crashed | Fail safe: treat the content as unprocessable, do not retry with a bypass |

## Canary tokens — what Wintermute seeds

Canaries are per-deployment. Wintermute's install script seeds the sidecar with canaries that match *real* Wintermute-accessible resources (a fake admin URL, a fake AWS key pattern, a fake database URI). The values are **never** real credentials — they're sentinel strings that exist nowhere else. If a canary ever appears in LLM output, it's proof the model followed an instruction embedded in untrusted content.

Seeding happens via `bulwark canary add`:

```bash
bulwark canary add wintermute_admin_url --shape url
bulwark canary add wintermute_db_conn   --shape mongo
bulwark canary add wintermute_api_key   --shape bearer
```

Rotation is just re-adding under the same label. Wintermute rotates on the same schedule as its own secrets rotation — quarterly is fine; after any suspected compromise is mandatory.

When Bulwark returns `blocked: true` with `block_reason` mentioning a canary source, Wintermute:

1. Logs the event at the highest severity.
2. Stops processing the triggering content.
3. Does **not** automatically rotate the canary. Rotation is a human decision — the canary did its job; changing its value doesn't change what it tells you.

### Wiring the sidecar to Wintermute's alert channel

Set `BULWARK_WEBHOOK_URL` in the sidecar's env to Wintermute's existing alert endpoint (or directly at a Slack incoming webhook). Bulwark fires a fire-and-forget POST on every BLOCKED event — canary leak, guard-pattern hit, detection-model block — so Wintermute's on-call path hears about leaks without polling `/api/events`. See [ADR-026](../../spec/decisions/026-external-webhook-on-blocked-events.md) for the payload shape and failure semantics.

## Auth

In Wintermute's default local deployment, `BULWARK_API_TOKEN` is not set and the endpoints are open to `localhost:3000`. This is acceptable because the sidecar is on `localhost` only (not bound to `0.0.0.0` on an untrusted network).

For multi-tenant or shared-host deployments, set `BULWARK_API_TOKEN` in the sidecar env and pass `Authorization: Bearer <token>` from Wintermute. The `/v1/clean`, `/v1/guard`, `/healthz`, and `/api/presets` endpoints are public regardless; everything else (including `/api/canaries`) requires the header.

## Health checks and startup

Wintermute's boot sequence:

1. `docker compose up -d` brings the sidecar up.
2. Poll `GET /healthz` with a 30-second deadline. Expected response: `{"status":"ok","version":"1.3.x","docker":true}`. If the deadline is missed, surface a hard error — do not start processing inbound content.
3. Optional sanity check: `GET /api/canaries` confirms the seeded canaries survived bind-mount restoration.
4. Begin processing. Every inbound email / document / web page goes through `POST /v1/clean`.

Wintermute caches the Bulwark version string from `/healthz` and includes it in every one of its own audit-log entries, so if a defense change lands later you can tell which traffic pre-dates it.

## Failure modes and what Wintermute does

| Symptom | Cause | Action |
|---------|-------|--------|
| Connection refused | Sidecar down | Stop accepting new untrusted content. Alert. Do not bypass. |
| 5xx from `/v1/clean` | Bulwark internal error | Treat as unprocessable, log the error, surface to user. |
| `blocked: true` (canary) | Injection succeeded against Phase 1 | Highest-severity log. Human review. |
| `blocked: true` (guard pattern) | AnalysisGuard matched a known-bad pattern | Log, inform user "could not process". |
| Response latency > 10s | Usually the LLM call inside Bulwark is slow | Wintermute's per-call timeout is 30s. Beyond that, fail the request and retry on the next inbound. |

**The one hard rule**: Wintermute never falls back to processing unsanitized content when Bulwark is unavailable. If the sidecar is down, untrusted content queues up until it comes back. Falling back would defeat the whole point of the sidecar.

## Version pinning and upgrades

Wintermute pins an exact Bulwark image tag. To upgrade:

1. Read Bulwark's [CHANGELOG](../../CHANGELOG.md) for the range between the current pin and the target version.
2. Pay attention to anything under `### Changed` or `### Removed` — those can break Wintermute. Things under `### Added` are safe to ignore.
3. Cross-reference any HTTP contract changes against [`spec/contracts/http_clean.yaml`](../../spec/contracts/http_clean.yaml) and the other `http_*.yaml` contracts. Non-guarantees (`NG-*`) aren't promises; don't rely on them.
4. Bump the pin, `docker compose pull && docker compose up -d`, rerun the health check.

Versions that require explicit Wintermute changes will be marked as such in the changelog. As of v1.3.2 there are none — every upgrade from v1.0.0 onward has been backwards-compatible for the `/v1/clean` caller.

## What Wintermute does NOT do

- **Does not mirror Bulwark state.** Wintermute doesn't keep a local copy of canary tokens or guard patterns. The sidecar is the source of truth.
- **Does not call any `/api/*` endpoint from the hot path.** `/api/*` is dashboard-internal and unversioned. Only `/v1/*`, `/healthz`, and occasionally `/api/canaries` (for management operations, not per-request) are called.
- **Does not expose the sidecar.** The sidecar binds to `127.0.0.1:3000` only. Exposing it on `0.0.0.0` would require auth + network controls that Wintermute's threat model doesn't assume.

## References

- [`spec/openapi.yaml`](../../spec/openapi.yaml) — machine-readable contract for every HTTP endpoint.
- [`spec/contracts/http_clean.yaml`](../../spec/contracts/http_clean.yaml) — `/v1/clean` guarantees.
- [`spec/contracts/canaries.yaml`](../../spec/contracts/canaries.yaml) — canary management contract.
- [ADR-025](../../spec/decisions/025-canary-management-api.md) — why canary management is a product feature.
- [`CHANGELOG.md`](../../CHANGELOG.md) — upgrade-path reference.
