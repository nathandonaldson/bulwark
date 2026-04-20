# ADR-026: External webhook POST on BLOCKED events

**Status:** Accepted
**Date:** 2026-04-20

## Context

Bulwark detects prompt-injection and canary-leak events, writes them to the dashboard's `EventDB`, and streams them over SSE to any connected `/api/stream` subscriber. For a human sitting in front of the dashboard that is fine. It is not fine at 3 a.m.

Today, a canary firing — the highest-severity event Bulwark produces, evidence that a real injection succeeded against Phase 1 — is silent unless someone happens to look at the dashboard. ADR-025 explicitly deferred alerting with the note "hooking Slack/webhooks is a separate decision". This is that decision.

The existing `bulwark.events.WebhookEmitter` already does synchronous or threaded POSTs to a URL. It is used inside the dashboard to feed `/api/events` from in-process callers. What is missing is a single config-driven surface that lets an operator point an *external* URL (Slack incoming webhook, PagerDuty, an internal alert router, a function-as-a-service endpoint) at the same event stream and have it fire on the events that actually page someone.

## Decision

Add a single configuration field, `webhook_url`, that — when set — causes every `BLOCKED` event produced by `/v1/clean`, `/v1/guard`, or the red-team runner to fire a fire-and-forget POST to that URL. One URL per deployment; one verdict (`BLOCKED`) in scope for v1.

Wiring lives inside `src/bulwark/dashboard/api_v1.py::_emit_event`, the single choke point where every dashboard-tracked event is already written to `EventDB` + pushed to SSE. The fan-out is: DB → SSE → external webhook. The external POST is the last step so a slow or unreachable webhook cannot delay the primary response.

### What the webhook receives

```json
{
  "events": [
    {
      "timestamp": 1744905823.412,
      "layer": "canary",
      "verdict": "blocked",
      "source_id": "api:clean:email",
      "detail": "Blocked: Canary token leaked from: prod_db_url",
      "duration_ms": 1420.3,
      "metadata": {}
    }
  ]
}
```

Same wire format the internal ingestion endpoint already accepts. The shape is documented in `spec/contracts/webhooks.yaml` (G-WEBHOOK-003).

### What is explicitly out of scope

- **Retries**. Webhook is fire-and-forget. If the receiver is down, the event is lost from the external stream (still recorded in `EventDB`). Retry logic has sharp edges — duplicate alerts, ordering, backpressure — that belong in a downstream alert router, not here.
- **Multiple webhooks**. One URL only for v1. Teams that need fan-out should point this at a router.
- **Per-layer filters**. Verdict is the only filter; `verdict == "blocked"` is the whole scope. Callers that want `passed` or `neutralized` events can subscribe to the SSE stream.
- **Authentication headers**. The target URL is the auth. Slack, Datadog, and most SaaS webhook endpoints put the secret in the URL. If that is insufficient, put a reverse proxy in front that adds headers.
- **Dashboard UI to configure the URL**. Env var + `PUT /api/config` are sufficient for v1. UI affordance is a later PR.

### Config surface

- `BULWARK_WEBHOOK_URL` env var — default source. Follows the same env-shadowing semantics as the LLM backend fields (ADR-022): UI can still set/override for the session; on save, env-shadowed values are blanked so the env remains authoritative.
- `webhook_url` field in `bulwark-config.yaml` — for operators who prefer file-based config.
- Unset / empty string → no external POST happens.

## Consequences

### Positive
- Operators can wire Bulwark alerts into whatever they already use for alerts without running a sidecar or writing code.
- Canary events stop being silent. A leak at 3 a.m. reaches the on-call path the operator already has.
- Existing `WebhookEmitter` infrastructure reused — no net-new POST code.

### Negative
- One more URL the operator must keep correct. A stale Slack webhook will silently swallow events. Rotation / validation is the operator's problem (same as for any SaaS webhook URL).
- Events fire for every BLOCKED. For a busy deployment that means a lot of pages. The caller should put a router / dedupe layer in front if noise is a concern.

### Neutral
- `WebhookEmitter`'s existing `async_send=True` path runs the POST in a daemon thread. The primary request is not delayed by the webhook. If the webhook hangs, the thread simply dies when the interpreter shuts down.
- No new HTTP endpoints. Everything flows through existing `_emit_event`.
