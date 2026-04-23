# Bulwark HTTP API Reference

The HTTP API is the primary integration surface. Source of truth: `spec/openapi.yaml`.

Bulwark is **detection only** (ADR-031). It returns safe content or an error.
Your application calls `/v1/clean` on untrusted input, feeds the result into
your own LLM, and calls `/v1/guard` on the LLM's output.

## Base URL

```
http://localhost:3001
```

## Endpoints

| Method | Path                  | Purpose                                                |
|--------|-----------------------|--------------------------------------------------------|
| GET    | `/healthz`            | Liveness + version probe.                              |
| POST   | `/v1/clean`           | Sanitize, detect, wrap. Returns safe content or 422.   |
| POST   | `/v1/guard`           | Output check on caller's LLM output (regex + canary).  |
| GET    | `/api/canaries`       | List canary tokens.                                    |
| POST   | `/api/canaries`       | Create or rotate a canary.                             |
| DELETE | `/api/canaries/{label}` | Delete a canary.                                     |
| GET    | `/api/presets`        | Built-in attack-preset library (read-only).            |
| GET    | `/api/redteam/tiers`  | Available scan tiers including `falsepos`.             |
| POST   | `/api/redteam/run`    | Start a red-team or false-positive scan.               |

Dashboard-internal endpoints (events, metrics, integrations) are documented
in `tests/test_spec_compliance.py::INTERNAL_PATHS`. They are not a stable
contract — use `spec/openapi.yaml` for anything external.

## POST /v1/clean

Pipeline: **Sanitizer → DeBERTa (mandatory) → PromptGuard (optional) → LLM Judge (optional) → Trust Boundary**.

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
| `content`     | string | (required)    | Up to 1 MB. The untrusted payload.             |
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
    {"step": 2, "layer": "detection:protectai", "verdict": "passed", "detail": "..."},
    {"step": 3, "layer": "trust_boundary", "verdict": "passed", "detail": "..."}
  ],
  "detector": {"label": "SAFE", "score": null}
}
```

### Response (422)

The detector blocked the request. Body has the same shape with `blocked: true`
and a `block_reason`. Feed `result` to nothing — return an error to your user.

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

Bulwark reads config from `bulwark-config.yaml` at startup; environment
variables override file values.

### Environment variables

| Variable                | Effect                                                    |
|-------------------------|-----------------------------------------------------------|
| `BULWARK_API_TOKEN`     | Bearer auth on mutating + protected endpoints.            |
| `BULWARK_WEBHOOK_URL`   | External webhook for BLOCKED events.                      |
| `BULWARK_ALLOWED_HOSTS` | Comma-separated hostname allowlist for SSRF guard.        |

### Detector configuration

Detectors live under the dashboard's integrations + `judge_backend` blocks.
There is no `llm_backend` config in v2 — Bulwark never invokes a generative LLM.

```yaml
# bulwark-config.yaml
sanitizer_enabled: true
trust_boundary_enabled: true
canary_enabled: true
strip_emoji_smuggling: true
strip_bidi: true
normalize_unicode: false

webhook_url: ""

# DeBERTa is mandatory; PromptGuard is opt-in via /api/integrations.
integrations:
  protectai:
    enabled: true
  promptguard:
    enabled: false

# LLM judge — opt-in third detector. Off by default. See ADR-033.
judge_backend:
  enabled: false
  mode: openai_compatible      # or "anthropic"
  base_url: ""
  model: ""
  threshold: 0.85
  fail_open: true
  timeout_s: 30
```

## Auth

When `BULWARK_API_TOKEN` is set, all non-public endpoints require a Bearer
header or session cookie:

```
Authorization: Bearer <token>
```

When the token is unset, mutating methods (POST/PUT/DELETE/PATCH) require the
client to be on the loopback interface — see ADR-029.

## Errors

- **400** — Invalid request body for canary management.
- **401** — Missing/invalid Bearer token.
- **403** — Token unset, remote client tried to mutate.
- **404** — No matching resource (canary label, redteam report).
- **422** — Validation error OR detector blocked the request.

## Versioning

The HTTP API version lives in `spec/openapi.yaml`. Breaking changes get a
major-version bump (v1 → v2 was ADR-031).
