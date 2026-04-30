# Bulwark HTTP API Reference

The HTTP API is the primary integration surface. Source of truth: `spec/openapi.yaml`.

Bulwark is **detection only** (ADR-031). It returns safe content or an error.
Your application calls `/v1/clean` on untrusted input, feeds the result into
your own LLM, and calls `/v1/guard` on the LLM's output.

## Base URL

```
http://localhost:3000
```

The Docker image binds to port 3000 by default. Source-tree dev uses
3001 (`python -m bulwark.dashboard --port 3001`); see
[`docs/README.md` "Which port am I on?"](README.md#which-port-am-i-on).

## Endpoints

| Method | Path                          | Purpose                                                |
|--------|-------------------------------|--------------------------------------------------------|
| GET    | `/healthz`                    | Liveness + version probe.                              |
| POST   | `/v1/clean`                   | Sanitize, detect, wrap. Returns safe content or 422.   |
| POST   | `/v1/guard`                   | Output check on caller's LLM output (regex + canary).  |
| GET    | `/api/canaries`               | List canary tokens.                                    |
| POST   | `/api/canaries`               | Create or rotate a canary.                             |
| DELETE | `/api/canaries/{label}`       | Delete a canary.                                       |
| GET    | `/api/presets`                | Built-in attack-preset library (read-only).            |
| GET    | `/api/redteam/tiers`          | Available scan tiers including `falsepos`.             |
| POST   | `/api/redteam/run`            | Start a red-team or false-positive scan.               |
| GET    | `/api/redteam/reports`        | List saved red-team reports.                           |
| GET    | `/api/redteam/reports/{filename}` | Download a saved report.                          |
| POST   | `/api/redteam/retest`         | Retest the failures from an earlier report.            |

`/api/redteam/run` siblings `/api/redteam/status` (poll) and
`/api/redteam/stop` (cancel) exist but are dashboard-internal — use
them from the UI but don't depend on them as a public contract.

Other dashboard-internal endpoints (events, metrics, integrations) are
documented in `tests/test_spec_compliance.py::INTERNAL_PATHS`. They are
not a stable contract — use `spec/openapi.yaml` for anything external.

## POST /v1/clean

Pipeline: **Sanitizer → DeBERTa (mandatory) → PromptGuard (optional) → LLM Judge (optional) → Trust Boundary**.

Per ADR-047, `/v1/clean` decodes ROT13 substrings (always on) and base64
substrings (opt-in via `BULWARK_DECODE_BASE64=1`) into detection
variants. Each detector runs once per variant; the trust boundary still
wraps the original cleaned text. See `decoded_variants` and
`blocked_at_variant` in the response shape.

### Request

```json
{
  "content": "untrusted text here",
  "source": "email",
  "format": "xml"
}
```

| Field         | Type   | Default       | Notes                                          |
|---------------|--------|---------------|------------------------------------------------|
| `content`     | string | (required)    | Up to 262144 bytes (256 KiB) of UTF-8. Tunable via `BULWARK_MAX_CONTENT_SIZE`. Over-cap → 413. |
| `source`      | string | `"external"`  | Tag name fragment in the trust-boundary wrap.  |
| `label`       | string | null          | Optional override for the tag name.            |
| `max_length`  | int    | null          | Truncate after sanitizing.                     |
| `format`      | enum   | `"xml"`       | `xml` / `markdown` / `delimiter`.              |

### Response (200)

```json
{
  "result": "<untrusted_email source=\"email\" treat_as=\"data_only\">...sanitized content...</untrusted_email>",
  "blocked": false,
  "source": "email",
  "format": "xml",
  "content_length": 42,
  "result_length": 287,
  "modified": false,
  "trace": [
    {"step": 1, "layer": "sanitizer", "verdict": "passed", "detail": "..."},
    {"step": 2, "layer": "detection:protectai", "verdict": "passed", "detail": "...", "detection_model": "protectai", "duration_ms": 28.5, "max_score": 0.0021},
    {"step": 3, "layer": "trust_boundary", "verdict": "passed", "detail": "..."}
  ],
  "detector": {"label": "SAFE", "score": null},
  "mode": "normal",
  "decoded_variants": [],
  "blocked_at_variant": null
}
```

| Field                | Notes                                                                                               |
|----------------------|-----------------------------------------------------------------------------------------------------|
| `decoded_variants`   | List of variants the chain ran over (e.g. `[{"kind": "rot13", "text": "..."}]`). Empty when no decoding fired. ADR-047. |
| `blocked_at_variant` | Index into `decoded_variants` if a variant blocked, else `null`.                                    |
| `mode`               | `"normal"` on a default deploy. `"degraded-explicit"` when running with zero detectors loaded **and** `BULWARK_ALLOW_NO_DETECTORS=1` is set; every request in that mode is logged at WARNING (ADR-040). |

Per-detector trace entries also carry `detection_model`, `duration_ms`, `max_score`, and `n_windows` — useful for operator drill-downs.

### Response (422)

The detector blocked the request. Body has the same shape with `blocked: true`
and a `block_reason`. Feed `result` to nothing — return an error to your user.

### Response (401)

When `BULWARK_API_TOKEN` is set, non-loopback callers must provide a Bearer
token. Loopback callers (127.0.0.0/8, ::1) bypass per ADR-029. The auth
predicate keys on token presence + non-loopback origin alone — judge state
is no longer load-bearing (ADR-041).

### Response (413)

```json
{"error": {"code": "content_too_large", "message": "..."}}
```

`content` is capped at 262,144 bytes when UTF-8 encoded (256 KiB). The cap
is byte-counted, not char-counted, so multi-byte payloads can't sneak past.
Tunable via `BULWARK_MAX_CONTENT_SIZE` (ADR-042).

### Response (503)

```json
{"error": {"code": "no_detectors_loaded", "message": "..."}}
```

Returned when zero ML detectors are loaded **and** the LLM judge is
disabled — Bulwark refuses to silently serve a sanitizer-only response.
Operators who want sanitizer-only must set `BULWARK_ALLOW_NO_DETECTORS=1`
(see ADR-040; the response then carries `mode: "degraded-explicit"`).

## POST /v1/guard

Output-side check. Run this on your LLM's output before showing it to a user
or passing it to a tool.

### Request

```json
{
  "text": "the LLM's response text",
  "canary_tokens": null
}
```

When `canary_tokens` is null, server-configured canaries from
`bulwark-config.yaml` are used.

### Response (200, always)

```json
{
  "safe": true,
  "text": "...",
  "reason": null,
  "check": null
}
```

`safe: false` returns alongside `reason` and `check` (`"injection"` or `"canary"`).

## Configuration

See [docs/config.md](config.md) for the full env-var table, YAML file
shape, and detector configuration block. The canonical env-var contract
lives in [`spec/contracts/env_config.yaml`](../spec/contracts/env_config.yaml).

## Auth

When `BULWARK_API_TOKEN` is set, every `/api/*` call (reads + mutations)
and every `/v1/clean` call from non-loopback callers requires a Bearer
header or session cookie:

```
Authorization: Bearer <token>
```

When the token is unset, `/api/*` reads stay open to any caller; only
mutating methods (POST/PUT/DELETE/PATCH) require a loopback client (ADR-029).
`/v1/clean` from non-loopback is gated by token presence alone (ADR-041).

## Errors

- **400** — Invalid request body for canary management.
- **401** — Missing/invalid Bearer token (incl. `/v1/clean` from non-loopback when token is set, ADR-041).
- **403** — Token unset, remote client tried to mutate. Body shape is `{"error": "Mutating endpoints require BULWARK_API_TOKEN..."}` (string error, not the structured envelope).
- **404** — No matching resource (canary label, redteam report).
- **413** — `content_too_large`: `/v1/clean.content` or `/v1/guard.text` exceeded the byte cap (ADR-042).
- **422** — Validation error OR detector blocked the request.
- **503** — `no_detectors_loaded`: `/v1/clean` invoked with zero detectors and judge disabled (ADR-040).

## Versioning

The HTTP API version lives in `spec/openapi.yaml`. Breaking changes get a
major-version bump (v1 → v2 was ADR-031).
