# ADR-007: HTTP API Response Codes

**Status:** Accepted
**Date:** 2026-04-14

## Context

`POST /v1/guard` checks text for injection patterns. When injection is detected, should the endpoint return:

- **200** with `{ safe: false, reason: "..." }` — the request succeeded, analysis completed
- **400** with error body — "bad request" because the text is malicious

## Decision

Always return 200 for completed analysis. The HTTP request was valid and the server fulfilled it. The fact that the text contains injection is the result of the analysis, not a request error.

- **200:** Analysis complete. `safe: true` or `safe: false` with reason.
- **422:** Malformed request (missing required fields, wrong types). Pydantic validation.

This follows the pattern of content moderation and virus scanning APIs, where the analysis result is data, not an error condition. Clients parse one response shape regardless of outcome.

## Consequences

### Positive
- Clients always parse the same response shape — no branching on status codes
- Semantically correct: the request succeeded
- Consistent with industry patterns (VirusTotal, perspective API)

### Negative
- Clients must check `safe` field, not just HTTP status
- Monitoring tools that count 4xx as "errors" won't flag injection detections
