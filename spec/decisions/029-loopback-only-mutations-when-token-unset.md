# ADR-029: Loopback-only mutations when `BULWARK_API_TOKEN` is unset

**Status:** Accepted
**Date:** 2026-04-23

## Context

A Codex Cloud security audit (finding "Unauthenticated runtime config API lets clients disable defenses", 2026-04-16) reported that when `BULWARK_API_TOKEN` is not set, any network-reachable client can `PUT /api/config` and disable core defenses (sanitizer, trust boundary, canary checks, guard patterns). The combination of the Docker default bind (`0.0.0.0:3000`) and the token-unset default (`auth disabled`) made this exploitable on every deployment that hadn't explicitly set a token.

The finding's severity was rated *high*, with high impact (attackers can persistently disable prompt-injection defenses) and high likelihood (simple PUT, no auth, default network exposure).

At the time of the audit we didn't yet have the `BearerAuthMiddleware`; we do now. With the token set, the middleware correctly rejects unauthenticated mutations. But the default — no token — still passed everything through. Any operator who spun up `docker run nathandonaldson/bulwark` without setting `BULWARK_API_TOKEN` (the common case in local and hobby deployments) had the original vulnerability.

"Make token mandatory" solves the security problem but breaks the zero-friction local-development story that Bulwark ships with. `docker run -p 3000:3000 nathandonaldson/bulwark` has to keep working on a laptop.

## Decision

When `BULWARK_API_TOKEN` is **not set**, the `BearerAuthMiddleware` enforces one additional rule:

**Mutating methods (`POST`, `PUT`, `DELETE`, `PATCH`) on non-public endpoints require the client to be on the loopback interface.** All other requests — reads, public endpoints (`/healthz`, `/v1/clean`, `/v1/guard`, `/api/presets`, `/api/auth/login`, `/`), static assets — pass through as before.

Loopback = `127.0.0.0/8` or `::1`, decided from `request.client.host`. The FastAPI `TestClient` sentinel `"testclient"` also counts as loopback so the existing test suite runs unchanged.

We do **not** honour `X-Forwarded-For`. An operator running behind a reverse proxy who still wants remote mutations must set `BULWARK_API_TOKEN`. Trusting `X-Forwarded-For` by default would let any upstream client claim loopback and defeat the entire fix.

### What this is NOT

- **Not a token-required regime.** With the token set, behaviour is unchanged.
- **Not applied to reads.** `GET /api/config`, `GET /api/events`, `GET /api/metrics` still succeed from remote clients without a token. Configuration values and event streams are already subject to CORS for browsers; any operator concerned about read exposure should set the token.
- **Not an allowlist of trusted networks.** Loopback is the one exception; there is no way to declare "also trust 10.0.0.0/24". Operators with that requirement set the token and authenticate.
- **Not a change to public endpoints.** `/v1/clean`, `/v1/guard`, `/healthz`, `/api/auth/login`, `/api/presets` stay open regardless of token state. These are the language-agnostic defense surface and the liveness probe; requiring auth to call them would break every integrator.

## Consequences

### Positive
- The Codex finding's exploit path (remote `PUT /api/config` with no token) returns 403.
- The default `docker run` experience is unchanged on localhost — `curl -X PUT http://localhost:3000/api/config ...` from the same machine still works.
- Operators who intentionally expose mutation endpoints (e.g. a CI bot that toggles config on deploy) get a loud 403 that tells them exactly what to do: set `BULWARK_API_TOKEN`. No silent exploit path.
- `G-AUTH-007` is machine-checkable; the test suite pins the invariant and a future refactor that collapses the loopback check gets caught by CI.

### Negative
- Operators running Bulwark behind a reverse proxy without setting `BULWARK_API_TOKEN` will find that proxied `PUT` requests now fail. This is intentional (trusting `X-Forwarded-For` would reintroduce the vuln) but will surprise anyone who didn't read this ADR. The error message names the env var explicitly.
- A remote read (`GET /api/config`) still reveals config shape and (masked) credentials. Closing that would require the same loopback-only rule for reads, which is a bigger UX hit — deferred.

### Neutral
- Method-based gating (only mutating methods are gated) means we don't need to maintain a list of "mutating endpoints"; HTTP verbs are the signal.
- `_UNAUTH_ALL_ORIGINS` replaces the old `_PUBLIC_PATHS` constant. Same paths, clearer name — "unauthenticated for all origins, including remote" vs. "public" which was ambiguous about the loopback case.
