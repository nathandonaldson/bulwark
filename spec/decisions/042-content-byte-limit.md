# ADR-042: Enforce `/v1/clean` content cap as bytes, not characters

**Status:** Accepted
**Date:** 2026-04-29
**Related:** ADR-038 (B2 — 256 KB body cap), ADR-039 (PR-B hardening), ADR-040 (Phase A — fail-closed when no detectors)

## Context

`spec/contracts/http_clean.yaml :: G-HTTP-CLEAN-012` (added in ADR-038) caps
the `/v1/clean` request body at 256 KiB (262 144 bytes), tunable via
`BULWARK_MAX_CONTENT_SIZE`. The implementation in
`src/bulwark/dashboard/models.py` enforced it with Pydantic's
`Field(..., max_length=_MAX_CONTENT_SIZE)`.

The `/codex challenge` adversarial review caught the discrepancy: Pydantic's
`max_length` measures `len(str)` — Python characters (Unicode code points),
not bytes. The constant `_MAX_CONTENT_SIZE` is named, documented, and
configured as bytes (the env var `BULWARK_MAX_CONTENT_SIZE` is described as
"positive integer, bytes" in the contract).

Concretely, a payload of 65 537 four-byte UTF-8 characters — e.g.
`"\U0001D54F"` (𝕏, MATHEMATICAL DOUBLE-STRUCK CAPITAL X) — is 65 537
*characters* (well under 262 144) but **262 148 bytes** when UTF-8
encoded (over the cap by 4 bytes). Worse: 65 536 such characters is
1 048 576 bytes (1 MiB) on the wire — exactly the pre-ADR-038 default
that B2 was meant to retire — yet still passes the `max_length` check
(65 536 < 262 144).

**Impact.** The defense-in-depth guarantee from ADR-038 is half-met. Non-ASCII
attackers (UTF-8-heavy languages, mathematical alphanumerics, emoji-rich
payloads) can submit content up to roughly 4× the intended byte budget,
re-exposing the worker-pinning surface that B2 was designed to close. This
hits two cost centers:

1. **Tokenizer / detector latency.** ADR-032 chunks across 512-token
   windows. A 1 MiB UTF-8-heavy payload produces 4× the windows of an
   "in-spec" 256 KiB payload, so detector wall-clock goes up
   proportionally.
2. **Outbound LLM judge round-trip.** When `judge_backend.enabled`, the
   judge sees the same oversized payload and pays oversize tokenization +
   network costs.

The threat is bounded — the caller still has to be authenticated when the
dashboard runs in non-loopback mode (ADR-029) — but defense-in-depth was
the point of B2 in the first place.

## Decision

Replace the `max_length` constraint with a Pydantic `field_validator` that
measures `len(content.encode("utf-8"))` and raises when it exceeds
`_MAX_CONTENT_SIZE`. Translate the resulting `RequestValidationError` into a
**HTTP 413 `content_too_large`** response (RFC 9110 §15.5.14, "Content Too
Large"), matching the structured-error envelope Phase A introduced for
HTTP 503 (ADR-040).

The same enforcement is extended to `GuardRequest.text` as a deliberate
parity choice. `/v1/clean` and `/v1/guard` share the
`_MAX_CONTENT_SIZE` constant and the same worker-pinning surface
(tokenizer cost, optional downstream detector / judge round-trip), so
the byte cap MUST apply to both — otherwise an attacker would simply
route oversized payloads to the output-side endpoint instead of
`/v1/clean`. This parity is captured by the new
`G-HTTP-GUARD-CONTENT-BYTES-001` (see "New contract IDs" below);
`G-HTTP-GUARD-001` itself is the unrelated "200 + safe=true on pass"
guarantee and is not a body-cap rule.

### Why bytes, not characters?

The constant has always been named, documented, and surfaced (env var,
contract guarantee) as bytes. Operators tuning `BULWARK_MAX_CONTENT_SIZE`
expect bytes. The fix aligns the implementation with the spec. This is a
spec-honouring patch, not a policy change.

### Why HTTP 413, not 422?

RFC 9110 §15.5.14 reserves 413 Content Too Large for "the server is
refusing to process a request because the request content is larger than
the server is willing or able to process." Browsers, proxies, and API
clients treat 413 as a size signal — retrying with a smaller payload may
succeed, retrying as-is will not. 422 Unprocessable Content is for
semantically invalid requests; size is not a semantic property.

The request-body byte limit is a server policy, not a schema-shape error.
413 is the correct status; some load balancers (NGINX, Cloudflare) will
even emit it themselves before the request reaches the application. We
emit it consistently here so callers see the same code regardless of
which layer enforced the cap.

### Why a `field_validator`, not a middleware?

A FastAPI/Starlette middleware (`request.body()` then check `len`) would
work, but it forces us to:

- buffer the body ourselves (or trust Content-Length, which clients can
  forge),
- duplicate the cap value in two places (the model + the middleware),
- and special-case `/v1/clean` and `/v1/guard` apart from other routes.

The field-validator route keeps the byte cap in one place
(`models.py::_MAX_CONTENT_SIZE`), runs as part of normal Pydantic
validation, and survives any future endpoint that reuses
`CleanRequest`/`GuardRequest`. The trade-off is that the body is fully
deserialized before the byte check fires; FastAPI applies its own
configurable body-size middleware (uvicorn `--limit-request-line` /
`--limit-request-field-size`) at deployment time for harder limits.
ADR-038's cap is a *defense-in-depth* layer, not a perimeter; the
defence-in-depth scope is exactly what a field-validator can deliver.

### Translation from ValidationError to 413

Pydantic's `field_validator` raises `ValueError`, which FastAPI surfaces
as HTTP 422. Phase A (ADR-040) already established the project pattern
for emitting non-422 status codes — register an
`exception_handler(RequestValidationError)` on the app that inspects the
error context. We tag the `ValueError` with a sentinel (the literal
string `"content_exceeds_byte_limit"` in the message) and the handler
maps that to a 413 response with body
`{"error": {"code": "content_too_large", "message": <human-readable>}}`.
Any other validation error continues to flow through FastAPI's default
422 path unchanged.

## New contract IDs

- **G-HTTP-CLEAN-CONTENT-BYTES-001** — `/v1/clean` MUST reject any request
  whose `content` field exceeds `_MAX_CONTENT_SIZE` bytes when UTF-8
  encoded. The response status code is 413 and the body is
  `{"error": {"code": "content_too_large", "message": "..."}}`.
- **G-HTTP-GUARD-CONTENT-BYTES-001** — `/v1/guard` MUST reject any request
  whose `text` field exceeds `_MAX_CONTENT_SIZE` bytes when UTF-8
  encoded with the same 413 / `content_too_large` envelope. Mirrors the
  `/v1/clean` rule so an attacker cannot bypass the cap by routing
  oversized payloads through the output-side endpoint.

`G-HTTP-CLEAN-012` is unchanged — its summary already says "262144 bytes",
which the implementation now honours faithfully. `G-HTTP-GUARD-001` is
unrelated (it is the "200 + safe=true on pass" rule); the guard byte
cap lives in `G-HTTP-GUARD-CONTENT-BYTES-001`.

## Compatibility

No breaking change for ASCII clients (1 byte per character ≡ same cap).
Non-ASCII clients sending content under the byte cap see no change. The
only callers affected are those that previously relied on submitting up to
~1 MiB of UTF-8-heavy content; they now correctly see 413.

## Tests

`tests/test_content_byte_limit.py` covers, against both `/v1/clean`
(`TestContentByteLimit`) and `/v1/guard` (`TestGuardTextByteLimit`):

1. 4-byte UTF-8 char repeated past the byte cap → 413
   `content_too_large`.
2. ASCII payload at exactly the byte cap → not 413 (may be 200 / 422 /
   503 depending on detector state, but never 413). `/v1/clean` only.
3. Non-ASCII payload under the byte cap → not 413.

The Phase A `BULWARK_ALLOW_NO_DETECTORS=1` opt-in is set in the test
fixture so the body-cap path is exercised independently of the
fail-closed gate (ADR-040).
