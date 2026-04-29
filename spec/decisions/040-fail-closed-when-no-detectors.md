# ADR-040: Fail closed on `/v1/clean` when no detectors are loaded

**Status:** Accepted
**Date:** 2026-04-29
**Related:** ADR-031 (detection-only), ADR-033 (LLM judge), ADR-038 (mandatory detector visibility), ADR-039 (codex PR-B hardening)

## Context

ADR-038 made detector load state visible at `/healthz` but explicitly punted on the request-time enforcement question — "we deliberately do NOT 503 the endpoint." The follow-up review found that this leaves a hole large enough to drive a truck through:

- A fresh `BulwarkConfig()` boots with `integrations: dict = field(default_factory=dict)` and `judge_backend.enabled=false`. Default-configured deployments (including the published Docker image until an integration is activated) run zero detectors.
- The `/v1/clean` handler at `api_v1.py:137` reads `if _detection_checks and cleaned:` — when the dict is empty, the entire detection block is skipped and the sanitizer-only output is returned with a `200 OK`.
- `/healthz` reports `status: "degraded"`, but operators rarely wire a probe to fail-on-degraded by default. The visible signal is "all healthy" on the only endpoint clients actually hit.

ADR-031 declared DeBERTa "mandatory" but the only enforcement happens at startup-config validation, not at request time. A deployment whose model failed to load (HuggingFace outage, gated approval still pending, OOM, corrupt cache) silently demotes itself to "sanitize-only" — exactly the failure mode ADR-038 was supposed to surface.

## Decision

### Fail closed by default

`/v1/clean` MUST return `HTTP 503 Service Unavailable` when:

```
len(_detection_checks) == 0  AND  config.judge_backend.enabled == false
```

The check runs BEFORE the detector iteration in `api_v1.api_clean`. The response body is:

```json
{
  "error": {
    "code": "no_detectors_loaded",
    "message": "Bulwark has zero detectors loaded and the LLM judge is disabled. /v1/clean refuses to serve sanitize-only output by default. Set BULWARK_ALLOW_NO_DETECTORS=1 to opt in (see ADR-040)."
  }
}
```

The predicate matches the one `/healthz` already uses to flip to `degraded` (ADR-038), so `/healthz` and `/v1/clean` agree on the definition of "detection chain present."

### Explicit opt-in: `BULWARK_ALLOW_NO_DETECTORS=1`

Operators who deliberately run sanitize-only (a corpus-sanitization batch job, an integration test rig, a dev workstation) can set:

```
BULWARK_ALLOW_NO_DETECTORS=1
```

Truthy values: anything that lower-cases to `1`, `true`, `yes`. Falsy values: `0`, `false`, the empty string. This mirrors the convention in `BULWARK_ALLOW_SANITIZE_ONLY` (ADR-038) and the existing env helpers in `bulwark.dashboard.config`.

When opted in:

- `/v1/clean` serves the sanitize-only path that v2.4.1 served for everyone.
- The response body adds `"mode": "degraded-explicit"` so callers can detect they are in a defense-reduced mode.
- A WARNING log is emitted on every degraded-mode request via the standard `logging` module (`bulwark.dashboard.api_v1`). The log line carries the source field so operators can audit which integrations are tolerating the hole.
- `/healthz` continues to report whatever `BULWARK_ALLOW_SANITIZE_ONLY` causes it to report. Suppression of the healthz signal is still gated by the older flag — it remains observable.

The two env vars are kept separate on purpose. `BULWARK_ALLOW_SANITIZE_ONLY` is observability-only ("don't page me"); `BULWARK_ALLOW_NO_DETECTORS` is policy ("yes, actually serve traffic without ML detection"). An operator can set both, neither, or one of each.

### Why 503 and not 422?

`422 Unprocessable Entity` is what `/v1/clean` returns when a classifier *blocks* the input — the request reached every layer and was rejected on the merits. A no-detectors deployment can't even run those layers; the failure is on the server, not the input. `503 Service Unavailable` is the correct semantic and lets operators distinguish "your prompt was rejected" from "Bulwark isn't fully booted" in their dashboards.

## Consequences

### Positive

- The "silent demotion to sanitize-only" failure mode is now loud at the wire. A deployment whose model failed to load returns 503 to every `/v1/clean` call until either (a) the detector loads or (b) the operator explicitly opts in.
- The published Docker image is fail-closed by default. New users who run `docker run ...nathandonaldson/bulwark` and hit `/v1/clean` immediately learn that they must activate at least one integration. The message includes the env-var escape hatch so the experience isn't a brick wall.
- Tests that need sanitize-only behavior (the existing `test_http_api.py::TestCleanEndpoint` rig) opt in explicitly via the env var, which makes the security-relevant configuration choice visible in the test setup.

### Negative

- Existing 0-detector deployments break on upgrade. Operators who relied on sanitize-only behavior must add `BULWARK_ALLOW_NO_DETECTORS=1` to their environment. We accept this break — the previous behavior was a CVE-shaped misconfiguration trap.
- Test fixtures across `test_http_api.py`, `test_auth.py`, `test_llm_judge.py`, and `test_v2_coverage.py` that boot a default `BulwarkConfig()` will need the env var. We update those rigs in the same PR.
- WARNING log spam on opt-in deployments. By design — if you accept the reduced-defense mode, you accept the log volume.

### Migration notes

For operators upgrading to v2.4.2:

1. If you have a real detector loaded (`/healthz` reports `status: "ok"`), no action required.
2. If `/healthz` reports `"status": "degraded", "reason": "no_detectors_loaded"` AND you want to keep the existing behavior, set `BULWARK_ALLOW_NO_DETECTORS=1` in your deployment environment.
3. If `/healthz` is degraded and you DIDN'T realize you had no detectors loaded — congratulations, this ADR did its job. Activate an integration via the dashboard or `/api/integrations/{name}/activate`.

### Telemetry / observability

- The 503 is logged at WARNING level with the source field so operators can correlate refused requests with caller integrations.
- Each degraded-mode (opt-in) request also logs at WARNING. Operators who want to alert on "sanitize-only mode is being used in prod" can grep for the structured marker `bulwark.degraded_explicit=1`.
- No event is written to the EventDB on the 503 — the request never reached a detection layer, so there is no per-layer verdict to record. Operators counting "blocked-by-Bulwark" events should treat 503 as a deployment-state metric, not a defense metric.

## Forward links

- This ADR closes the gap between the ADR-031 ("DeBERTa is mandatory") promise and the actual request-time enforcement.
- A future Phase E ("Pipeline.from_config() loads full detector chain") will reduce the surface where deployments end up with zero detectors in the first place; this ADR is the belt to that suspenders.
