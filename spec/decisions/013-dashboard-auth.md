# 013: Dashboard Bearer Token Authentication

## Status
Accepted

## Context
The Codex security review identified unauthenticated config access as Critical.
All 26 dashboard endpoints are public — anyone with network access can disable
defenses, read API keys, or run expensive scans. This is acceptable for localhost
development but dangerous when the dashboard is exposed via Docker (--host 0.0.0.0)
or on a shared network.

## Decision
Add optional bearer token authentication via `BULWARK_API_TOKEN` env var:

- **If no token set**: auth disabled, backwards compatible with existing deployments
- **If token set**: protected endpoints require `Authorization: Bearer {token}` header
  or a `bulwark_token` HttpOnly cookie (for SSE EventSource which can't send headers)

Public endpoints (no auth): `/healthz`, `/v1/clean`, `/v1/guard`, `/v1/pipeline`
Protected endpoints: everything under `/api/*`, dashboard HTML, `/v1/llm/*`

Login flow: `POST /api/auth/login` validates token, sets HttpOnly cookie, returns
success. Dashboard HTML shows a login gate when auth is enabled.

## Consequences
- Zero breaking changes for existing users (auth disabled by default)
- Docker users add `BULWARK_API_TOKEN=secret` to their `.env` file
- The core API endpoints remain public (Wintermute and other consumers don't need tokens)
- SSE streaming works via cookie-based auth
- Token read from env var on each request (no restart needed for rotation)
