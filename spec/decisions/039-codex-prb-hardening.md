# ADR-039: Codex PR-B hardening pass

**Status:** Accepted
**Date:** 2026-04-29
**Related:** ADR-037 (P1 fixes), ADR-038 (detector visibility)

## Context

Six findings remained from the `/codex challenge` adversarial review after PR-A
shipped (ADR-038). All are real but lower-impact than the P1s. The user
requested a single bundled PR rather than splitting them out.

| Item | Finding | Severity |
|------|---------|----------|
| B1 | `encoding_resistant` config field is dead code in `/v1/clean` | P2 |
| B2 | 1 MB request body cap is a DoS surface even with auth | P2 |
| B3 | SSRF validator only checks literal IPs, not resolved hostnames | P2 |
| B4 | `_redteam_result` mutated from a worker thread, read concurrently | P2 |
| B5 | `/v1/clean` route docstring still claims "no LLM is invoked" | P3 |
| B6 | Detector trace omits per-window score and chunk count | P3 |

## Decisions

### B1 — Wire `encoding_resistant` into the sanitizer

`Sanitizer` gains a `decode_encodings: bool = False` field. When true,
`html.unescape` and `urllib.parse.unquote` run BEFORE the strip steps. Two
passes catch one level of nested encoding (`&amp;lt;` → `&lt;` → `<`). The
dashboard wires the flag from `config.encoding_resistant`. Default off in
the dataclass for backwards compatibility; on by default in dashboard
deployments because that's the original config-default. New
`G-SANITIZER-018`; `NG-SANITIZER-003` rewritten to reflect the opt-in.

### B2 — 256 KB default body cap

`/v1/clean` and `/v1/guard` `max_length` drops from 1 MB to 256 KB. Tunable
via `BULWARK_MAX_CONTENT_SIZE` (positive integer, bytes). Even authenticated
clients can pin a worker on tokenization or judge round-trip with 1 MB; the
new floor matches realistic email/document inputs. New `G-HTTP-CLEAN-012`.

### B3 — Hostname-resolving SSRF check

`url_validator.validate_external_url` calls `socket.getaddrinfo(host)` and
checks every resolved IP against the same private/loopback/link-local/
metadata blacklist. Resolutions cached for 60 s per process to avoid DNS
amplification. Hosts in `_ALWAYS_ALLOWED` (`localhost`,
`host.docker.internal`) or `BULWARK_ALLOWED_HOSTS` skip resolution; operators
who self-host are responsible for them. Unresolvable hosts are rejected:
better to fail config-write than to pass through and let runtime resolve
to a private IP. New `G-WEBHOOK-008`. Also enforces ADR-033's
`G-JUDGE-006` via the same path.

### B4 — Lock `_redteam_result`

A `threading.Lock` (`_redteam_lock`) guards the four background-runner
mutation sites that update `_redteam_result["completed"]` and `["total"]`
during a run. `/api/redteam/status` returns a `copy.deepcopy(_redteam_result)`
snapshot taken under the lock so callers never see a half-mutated dict
mid-write or hit `RuntimeError: dictionary changed size during iteration`.
The big "replace whole dict" rebindings don't need the lock — module-level
global rebinding is atomic in CPython — but the per-key updates inside the
loop do. New `G-REDTEAM-REPORTS-006`.

### B5 — `/v1/clean` route docstring

The FastAPI route description in `api_v1.py` and the OpenAPI summary in
`spec/openapi.yaml` are rewritten to reflect ADR-033 (LLM judge optional)
and ADR-037 (judge is detection-only — generative output never reaches the
caller). Existing `G-HTTP-CLEAN-005` was already updated in v2.3.3; this
just brings the human-readable docs in line.

### B6 — Trace per-window observability

`integrations.promptguard.create_check` returns a `dict` on success with
`max_score`, `n_windows`, `top_label`. On block, the
`SuspiciousPatternError` carries the same data as exception attributes
(`max_score`, `n_windows`, `window_index`, `label`). `api_v1.py` reads
these and adds them to the trace entry and to the response `detector`
field. Operators can now see whether a detector "almost blocked" (max
score just below threshold) or had to scan many windows. Existing
test contract in `test_detector_chunking.py` is unaffected because tests
treat the `check` return value as opaque. New `G-HTTP-CLEAN-011`;
`G-HTTP-CLEAN-007` strengthened.

## Consequences

- Existing 1 MB-payload integrations break. Operators run with the env var
  if they need the old cap. Documented in CHANGELOG and `docs/api-reference.md`.
- DNS resolution adds latency to webhook config writes (one-time, cached).
- The new sanitizer step changes some output for callers who used the
  Sanitizer directly with encoded input — but only if they pass
  `decode_encodings=True`. Default behavior unchanged.
- The detector trace adds two fields (`max_score`, `n_windows`). Backwards-
  compatible: clients that don't read them ignore them.
- No behaviour change for `/v1/clean` from B4 — purely an internal
  thread-safety fix.
