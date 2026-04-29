# ADR-038: Detector load visibility and degraded /healthz

**Status:** Accepted
**Date:** 2026-04-29
**Related:** ADR-031 (detection-only), ADR-033 (LLM judge), ADR-037 (P1 security fixes)

## Context

A `/codex challenge` adversarial review surfaced two paired findings (P1 #1 and P1 #5) that share the same root cause: Bulwark silently boots into a state where `/v1/clean` has no defense beyond the sanitizer, with no signal to operators.

### P1 #1 — `/v1/clean` runs zero detectors by default

A fresh `BulwarkConfig()` initializes `integrations: dict = field(default_factory=dict)` (`config.py:114`).
The startup loader at `app.py:443-462` only loads detectors whose integration has `enabled=True`. The `/v1/clean` handler at `api_v1.py:130` skips the entire detection block when `_detection_checks` is empty.

Net effect: a default-configured deployment returns `200 SAFE` for an injection input. The dashboard's published Docker image fits this profile until an operator activates an integration through the UI.

### P1 #5 — Detector load failures silently degrade to "allow all after sanitizer"

`app.py:461` catches every exception during model load, prints to stdout, and continues. A first-run HuggingFace outage, gated-model approval still pending, corrupt cache, or out-of-memory condition all become silent fallback to sanitize-only. The operator only finds out by reading startup logs (which are often discarded in container deployments).

## Decision

### `/healthz` reports degraded state

`/healthz` gains two new fields that surface the state of the detection chain:

```json
{
  "status": "ok" | "degraded",
  "reason": "no_detectors_loaded",            // present only when degraded
  "detectors": {
    "loaded": ["protectai"],
    "failed": {"promptguard": "OSError: gated model ..."}
  },
  "version": "...",
  "docker": false,
  "auth_required": true
}
```

`status` is `degraded` when `len(detectors.loaded) == 0` AND `judge_backend.enabled == false`. Sanitize-only deployments that explicitly never enabled a detector ARE degraded — the operator made a choice that leaves `/v1/clean` with no detection. They can suppress the warning by setting `BULWARK_ALLOW_SANITIZE_ONLY=1` (see below).

A deployment with the LLM judge enabled (and only the LLM judge) is healthy — the judge is a detector. This avoids false-degraded alarms for judge-only deployments.

### `/v1/clean` keeps serving

We deliberately do NOT 503 the endpoint or add a `degraded:true` field to every response. The signal lives at `/healthz` for operators and monitoring tools. Existing sanitize-only deployments and integration tests that don't load a real model continue to work without code changes. Operators who want hard-fail can put a Liveness probe on `/healthz` that pages on `degraded`.

### `BULWARK_ALLOW_SANITIZE_ONLY` env opt-out

If an operator deliberately runs sanitize-only (e.g. an integration test rig, a corpus-sanitization batch job), they can set `BULWARK_ALLOW_SANITIZE_ONLY=1` and `/healthz` will report `status=ok` even with zero detectors. The `detectors.loaded`/`detectors.failed` fields still appear so the state remains observable.

### Detector load failures are tracked

A module-level `_detector_failures: dict[str, str]` is populated by the startup loop. Its contents appear under `detectors.failed` in `/healthz` and as a per-integration `load_error` field on `/api/integrations`. Operators see WHICH model failed and WHY (first 200 chars of the exception).

## Consequences

- New guarantees: `G-HEALTHZ-002` (degraded reporting), `G-HEALTHZ-003` (load-failure tracking), `G-HEALTHZ-004` (sanitize-only opt-out).
- New env var documented in `docs/dashboard.md` and `docs/config.md`.
- Operators who relied on the old `/healthz` shape (only `status`, `version`, `docker`, `auth_required`) will see new keys. The existing keys remain unchanged — additive only.
- No behavior change for `/v1/clean` itself. This is purely an observability fix.
- The integration tests that use a default `BulwarkConfig()` will start seeing `degraded` on `/healthz` unless they enable `BULWARK_ALLOW_SANITIZE_ONLY` or load a real detector. Test fixtures will need to set the env var; we update `tests/test_auth.py` and `tests/test_v1_clean.py` accordingly.
