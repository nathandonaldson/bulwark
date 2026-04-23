# ADR-030: Medium-severity Codex findings — webhook SSRF, /v1/clean cost abuse, detect-endpoint DoS, canary_tokens DoS

**Status:** Accepted
**Date:** 2026-04-23

## Context

A Codex Cloud security audit (2026-04-16 → 2026-04-20) reported six medium-severity findings. Audit against the state of main after ADR-027 (LLM key scope), ADR-028 (bridge HTML strip), and ADR-029 (loopback-only mutations):

- **M1 — Webhook URL blind SSRF** (`f190f05`). `webhook_url` has no host validation; an operator with a mutation path (compromised token, or pre-ADR-029 local loopback) could point the webhook at `169.254.169.254` and exfiltrate cloud metadata via the first BLOCKED event.
- **M2 — `/v1/clean` runs LLM unauthenticated** (`3e503db`). The endpoint is in `_UNAUTH_ALL_ORIGINS` for its original sanitize-only purpose. It now also dispatches the full two-phase pipeline under the operator's API key, which is cost-abuse if exposed.
- **M3 — `/v1/pipeline` honors unauth toggles** (`bf4a42d`). **Already closed.** The `/v1/pipeline` endpoint no longer exists; `/v1/clean` absorbs its role. The toggle-mutation precondition is closed by ADR-029 (loopback-only mutations).
- **M4 — detect endpoint spawns pip** (`04cbab3`). `GET /api/integrations/detect` runs `pip install ... --dry-run` with a 15s timeout on every request when a newer Garak version is available. GETs are outside ADR-029's loopback gate, so remote clients can hammer this.
- **M5 — Unbounded `canary_tokens` in `/v1/guard`** (`4d61275`). `dict[str, str]` with no bounds; Codex PoC showed 5k tokens × 1M text = 21 s CPU per request.
- **M6 — `/api/garak/run` DoS** (`5b3ab6f`). **Already closed** by existing design + ADR-029. The endpoint is outside `_UNAUTH_ALL_ORIGINS`, so token-enabled deployments require auth; token-unset deployments allow only loopback clients via ADR-029's mutation gate.

This ADR covers the four findings that were actually open (M1, M2, M4, M5) and notes the two that were already mitigated (M3, M6).

## Decision

### M1 — webhook URL host validation

Reuse `llm_factory._validate_base_url()` for webhook URLs. Validation fires at two points:

1. **`BulwarkConfig.update_from_dict`** — a PUT `/api/config` with `{"webhook_url": "http://169.254.169.254/..."}` returns an error string and no state changes.
2. **`api_v1._fire_webhook`** — defensive re-check at emit time. If a stale `bulwark-config.yaml` on disk predated validation, the emitter silently skips rather than POSTing.

String comparison is conservative by design: `127.0.0.1`, `::1`, `localhost`, and `host.docker.internal` remain allowed (local Slack-webhook proxies and Docker-internal alert routers are legitimate use cases). `BULWARK_ALLOWED_HOSTS` opens specific LAN hostnames the same way it does for the LLM backend.

### M2 — `/v1/clean` conditional auth

When `BULWARK_API_TOKEN` is set AND an LLM backend is configured (`mode` is `anthropic` or `openai_compatible`), `/v1/clean` leaves `_UNAUTH_ALL_ORIGINS` and requires Bearer or cookie auth like any other protected endpoint. Three states:

| `BULWARK_API_TOKEN` | LLM `mode` | `/v1/clean` |
|---|---|---|
| unset | any | open (matches ADR-029 — local dev default) |
| set | `none` | open (sanitize-only; no LLM spend, safe to expose) |
| set | `anthropic` / `openai_compatible` | **auth required** |

Rationale: operators who set a token have opted into auth. Allowing `/v1/clean` to bypass it *and* burn their LLM quota is not what they asked for. Sanitize-only callers (integrators testing the sanitizer) get the permissive default because there is no spend or key-leak surface. `_is_llm_configured()` reads `config.llm_backend.mode` at request time so flipping `mode` via the config UI takes effect immediately — no restart, no stale cache.

### M4 — detect endpoint caches the pip dry-run

`_check_garak_python_upgrade_needed(installed, latest)` caches its subprocess result with the same 1-hour TTL as `_check_garak_latest()`. Cache key is the `(installed, latest)` tuple — if either version changes, recompute; otherwise return the cached boolean. This converts a "subprocess per request" DoS vector into "subprocess once per hour per unique version pair", matching the paired version-check cache that already exists.

### M5 — bounded `canary_tokens`

`GuardRequest.canary_tokens` is now `dict[Annotated[str, max_length=64], Annotated[str, max_length=256]]` with `max_length=64` on the dict itself. Worst-case work is 64 × 256 × 1 M = 16 GB-scan-seconds, practically bounded to seconds of CPU. FastAPI returns 422 on violations so callers get a clear error shape.

### What this ADR is NOT

- **Not a rate limiter.** In-process rate limiting is explicitly out of scope; operators needing rate limits should front Bulwark with a reverse proxy.
- **Not a removal of `/v1/clean` or `/api/garak/run`.** Both stay; M2 narrows *when* auth is required on `/v1/clean`, and M6 is already gated by ADR-029.
- **Not universal URL validation for outbound requests.** `_validate_base_url` is the LLM+webhook policy; other outbound paths (PyPI version check in M4, upstream alerting in custom emitters) are separate.

## Consequences

### Positive
- **M1**: webhook SSRF path closed at both config-write and emit time.
- **M2**: cost-abuse path closed. Operators who set a token now get the auth posture they assumed; sanitize-only integrations keep the open surface.
- **M4**: repeated unauth requests to `/api/integrations/detect` cost O(1) work after the first cache miss.
- **M5**: canary-based DoS is bounded by request-body limits that FastAPI enforces for free.

### Negative
- **M2** is a behaviour change for operators who rely on unauthenticated LLM-backed `/v1/clean`. The upgrade note is: "set `BULWARK_API_TOKEN` and authenticate, OR switch `mode` to `none` for sanitize-only, OR leave the token unset and rely on ADR-029's loopback-only mutation gate." A `403`-with-explanation on first hit covers the discoverability gap.
- **M5** rejects legitimate requests that submit >64 canary tokens inline. Operators managing more canaries should use the management API (`POST /api/canaries`, ADR-025) rather than inline per-request.

### Neutral
- **M3** and **M6** were already closed before this sweep. They are documented here so the ADR record is complete and future audits don't re-flag them.
- The `_garak_dry_run_cache` is module-global; it's fine for the dashboard's single-process model. A future multi-worker deployment would need per-worker caches or an out-of-process cache, but that's not the situation today.
