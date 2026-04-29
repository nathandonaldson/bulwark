# ADR-041: `/v1/clean` auth gated on token, not on judge state

**Status:** Accepted
**Date:** 2026-04-29
**Supersedes:** Tightens G-AUTH-008 (ADR-030 / ADR-037). Preserves ADR-029.

## Context

A `/codex` adversarial review of the v2.4.x codebase flagged the `/v1/clean`
auth predicate as too narrow. Until v2.4.1 the middleware only flipped
`/v1/clean` off the always-public allowlist when **both** of:

1. `BULWARK_API_TOKEN` is set, AND
2. `config.judge_backend.enabled` is true.

That means in any deployment where the operator has set a token but the LLM
judge is disabled (sanitize-only mode, or judge mid-rollout, or
`judge_backend.enabled=False` for whatever reason), `/v1/clean` accepts
unauthenticated requests from non-loopback callers. The exposure:

- **Quota / detector burn.** Even with the judge disabled, every request
  invokes the DeBERTa / PromptGuard ML detectors. An attacker can drive a
  detection container to OOM or burn the operator's compute budget.
- **Unauthenticated content submission.** Anything posted to `/v1/clean` is
  pipeline-traced and (depending on logging config) appears in the operator's
  event log. An attacker can spam noise into the operator's telemetry.
- **Inconsistent threat surface.** Operators who set a token reasonably
  expect `/v1/clean` to be authenticated. The judge-state coupling was
  surprising and undocumented except in a code comment.

The original judge-coupled predicate from ADR-030/-037 was added to address
*judge-quota burn specifically*. That framing is too narrow — the right
trigger is "operator has signalled they want auth on this deployment", which
is `BULWARK_API_TOKEN` being set.

## Decision

The `BearerAuthMiddleware` no longer consults `_is_llm_configured()` when
deciding whether `/v1/clean` requires auth.

**New predicate:**

> When `BULWARK_API_TOKEN` is set and the request is **not** from a loopback
> client, `/v1/clean` requires Bearer or cookie auth. Loopback clients
> bypass the token check (ADR-029 unchanged). When no token is set,
> `/v1/clean` remains open to any caller (also unchanged from ADR-029 —
> the token is the operator's opt-in for auth).

The previous judge-coupling clause (ADR-030 / ADR-037) is removed. The
helper `_is_llm_configured()` was deleted in v2.4.3 once it had zero
production callers (the auth predicate no longer references it; the
healthz handler and `/v1/clean` pipeline path read
`config.judge_backend.enabled` directly).

### Interaction with ADR-029 (loopback exception)

`_is_loopback_client()` is still consulted, and a loopback caller
(TestClient sentinel, `127.0.0.0/8`, `::1`) bypasses the token check on
`/v1/clean` the same way it bypasses on every other non-public endpoint.
This keeps the localhost dev experience intact:
`docker run -p 3000:3000 -e BULWARK_API_TOKEN=foo nathandonaldson/bulwark`
followed by `curl localhost:3000/v1/clean ...` from the same machine still
works without an Authorization header.

#### Loopback asymmetry vs other token-gated routes

The earlier draft of this ADR claimed ADR-029 was "preserved exactly."
That phrasing was misleading and the spec/code reviewers correctly
flagged it. The accurate framing:

- **ADR-029 (original):** when **no** token is set, loopback callers may
  invoke mutating endpoints; remote mutations get 403. Loopback bypass
  is conditioned on the absence of a token.
- **ADR-041 (this change):** when a token **is** set, loopback callers
  bypass the token check on `/v1/clean` specifically. Other token-gated
  routes — notably `PUT /api/config` and the rest of the
  `_MUTATING_METHODS` surface — still require the Bearer header from
  loopback when a token is set, exactly as they did before this ADR.

So `/v1/clean` is uniquely permissive among token-gated routes: it is
the only path where a loopback caller bypasses the token after the
operator has opted into auth. `PUT /api/config` from loopback with a
token set still demands `Authorization: Bearer <token>`.

**Why `/v1/clean` is treated specially.** The motivating shape is
sanitize-as-a-library local use: an operator runs
`docker run -p 3000:3000 -e BULWARK_API_TOKEN=foo nathandonaldson/bulwark`
and calls `curl localhost:3000/v1/clean -d '...'` from the same machine
— typically from a script, agent, or sister service that doesn't want
to thread the token through. Forcing token-on-loopback for `/v1/clean`
would break that ergonomic without buying meaningful security on a host
where any local process could read `/proc/.../environ` to recover the
token anyway. `PUT /api/config` is the inverse: a configuration mutation
that should remain explicit even from localhost, because it changes
defensive posture (presets, judge enablement, allowlists). Different
risk profile, different rule.

**Deferred design knob.** A `require_token_for_clean: bool` config flag
was considered but **not added in v2.4.2 / v2.4.3**. Operators who want
the strict "token always required, even on loopback" posture currently
have no opt-in for `/v1/clean`. If that need surfaces (e.g. a multi-tenant
host where local processes are not trusted, or a compliance regime that
forbids any auth bypass) the predicate at `app.py:128-136` is the single
point to tighten — add `and not config.require_token_for_clean` to the
loopback bypass clause and gate the new flag in `BulwarkConfig`. This is
called out explicitly so the next contributor reaches for the flag
instead of re-deriving the asymmetry from scratch.

### Interaction with judge state

Orthogonal. Whether the judge is enabled affects:

- Pipeline behaviour (whether the LLM judge stage runs).
- Cost (judge invocations cost real money).
- Latency (judge adds ~1–3 s).

It does **not** affect routing or auth. An operator running sanitize-only
who sets a token gets the same auth wall as an operator running with the
judge enabled. The unified rule is easier to reason about and to test.

### Interaction with Phase A fail-closed (ADR-040 / 503)

When PR #35 (Phase A: 503 on no-detectors-loaded) lands, `/v1/clean` may
also short-circuit with 503 before reaching the auth check. The middleware
order is **auth first, then handler**:

1. CORS preflight pass-through.
2. Public-allowlist check (`/v1/clean` is on the allowlist by default but
   conditionally elevated to auth-required by this ADR).
3. Token check (this ADR's contribution): if token set & non-loopback →
   401 unless valid Bearer / cookie. **This runs before the route handler.**
4. Route handler runs — Phase A may emit 503 here if zero detectors
   loaded.

So an unauthenticated remote caller hitting a degraded deployment gets
**401, not 503.** That is the correct ordering: we don't leak the
detector-load status to unauthenticated callers, and authenticated callers
get the 503 they need to debug. If the operator wants to expose `/healthz`
for liveness probes (which is the right channel for that signal), that
endpoint stays on `_UNAUTH_ALL_ORIGINS` and is unaffected.

## Consequences

### Positive

- Closes the Codex finding. Sanitize-only deployments with a token now
  enforce that token on `/v1/clean`.
- Simpler mental model: "token set ⇒ auth required (except loopback)" is
  one rule across every protected endpoint. Operators no longer need to
  cross-reference `judge_backend.enabled` to predict auth behaviour.
- Spec-checkable. `G-AUTH-CLEAN-001` pins the new invariant in
  `spec/contracts/http_auth.yaml`; `tests/test_auth.py` exercises it
  directly.
- Drift-resistant. Future contributors who add a new public-by-default
  endpoint can't accidentally re-introduce the gap by adding a similar
  judge-coupling clause — the simpler predicate is harder to mis-extend.

### Negative

- **Breaking change for one specific deployment shape:** an operator who
  was running sanitize-only (`judge_backend.enabled=False`), had a token
  set, and was relying on `/v1/clean` being callable without auth from a
  remote network. We do not believe this configuration is sensible — the
  whole point of setting the token is to gate access — but it is a behaviour
  change. The CHANGELOG entry calls it out; the only fix on the operator
  side is to send the Bearer header (or unset the token).

### Neutral

- `_is_llm_configured()` was deleted in the v2.4.3 follow-up commit. The
  v2.4.2 draft of this ADR kept the helper "in case future telemetry
  wants it"; on review that was rationalisation — the helper had zero
  production callers after the predicate change, and the only remaining
  test (`test_is_llm_configured_reflects_judge_state`) was tautological.
  Both were removed. The two real readers of `judge_backend.enabled`
  (`healthz()` in `app.py` and the pipeline path in `api_v1.py`) read
  the config attribute directly with their own try/except.

## References

- ADR-029: Loopback-only mutations when token unset.
- ADR-030 / ADR-037: Original judge-coupled predicate (this ADR
  supersedes the coupling).
- `spec/contracts/http_auth.yaml` — `G-AUTH-CLEAN-001`, updated G-AUTH-008.
- `tests/test_auth.py::TestV1CleanAuthRegardlessOfJudge`.
- Codex review note: "/v1/clean exposed for unauth content submission and
  detector burn whenever judge is disabled."
