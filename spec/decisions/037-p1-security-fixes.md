# ADR-037: P1 Security Fixes (Codex Adversarial Review)

**Status:** Accepted
**Date:** 2026-04-29
**Supersedes:** Updates G-AUTH-008, G-HTTP-CLEAN-005, NG-JUDGE-004, G-JUDGE-005

## Context

A `/codex challenge` adversarial review of the v2 architecture surfaced three
P1 findings that defeat security-relevant invariants. All three were verified
in code.

### Finding 1 — Auth bypass when judge is enabled

`_is_llm_configured()` in `dashboard/app.py` is a stub that always returns
`False`. Its docstring claims "Bulwark never calls an LLM", but ADR-033
reintroduced the LLM judge as an opt-in third detector. The auth flip at
`app.py:116` is therefore dead code: `/v1/clean` stays on the always-public
allowlist even when `judge_backend.enabled=true` AND `BULWARK_API_TOKEN` is
set. Any unauthenticated remote caller can burn the operator's judge quota.

This violates the original intent of G-AUTH-008.

### Finding 2 — Judge `reason` leaks via trace

`JudgeVerdict.reason` is parsed from the judge's JSON output (`llm_judge.py:83`)
and embedded in the public trace at `api_v1.py:184`:

```python
"detail": f"LLM judge: INJECTION ({v.confidence:.2f}) — {v.reason} ...",
```

`v.reason` is generative LLM output. Returning it to `/v1/clean` callers is a
direct violation of NG-JUDGE-004 ("Does NOT expose the judge's raw response to
/v1/clean callers") and creates an exfiltration side-channel: an attacker who
can steer the judge's reasoning text gets that text echoed in the response body.

### Finding 3 — UNPARSEABLE bypasses fail-closed mode

`api_v1.py:239-246` treats `SAFE` and `UNPARSEABLE` identically as pass-through.
`fail_open=false` only catches `ERROR`. An attacker who induces the judge to
emit prose, refuse, or return malformed JSON ends up with `UNPARSEABLE` and
slips past strict mode. Strict mode is therefore not strict.

## Decision

### Auth flip (Finding 1)

`_is_llm_configured()` is replaced by a function that returns
`bool(config.judge_backend.enabled)`. When `BULWARK_API_TOKEN` is set AND the
judge is enabled, `/v1/clean` requires Bearer or cookie auth.

Sanitize-only and judge-disabled deployments keep the open default — operators
who don't pay LLM costs don't get auth gates they don't need.

### Trace sanitization (Finding 2)

The trace `detail` for the judge layer drops `v.reason`. The trace records the
verdict label, confidence, and latency only. `v.reason` continues to live on
the `JudgeVerdict` dataclass for server-side logs, but never reaches the HTTP
response.

### UNPARSEABLE = ERROR for fail-closed (Finding 3)

`UNPARSEABLE` is treated as an error path. With `fail_open=false`, an
unparseable judge response returns 422. With `fail_open=true`, the request
continues but the trace records the unparseable status (no leak of the raw
response).

## Consequences

- Operators enabling the judge with a token must pass that token to API
  callers. Documented in `docs/dashboard.md` and the dashboard config UI.
- The trace becomes less informative for debugging — operators wanting the
  judge's reasoning must read server logs, not API responses. This is the
  correct security tradeoff.
- Strict mode now blocks more aggressively. Operators who relied on
  `fail_open=false` while accepting `UNPARSEABLE` as a pass should switch to
  `fail_open=true` if that was their intent.
- Updates G-AUTH-008 (auth trigger is `judge_backend.enabled`, not legacy
  `mode in {"anthropic","openai_compatible"}`), G-HTTP-CLEAN-005 (Bulwark may
  call an LLM, but only as a classifier — never returns generative output),
  NG-JUDGE-004 (explicit: `reason` is not in trace), G-JUDGE-005 (UNPARSEABLE
  follows the same path as ERROR).
