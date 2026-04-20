# ADR-025: Canary management is a product feature, not a config-file hack

**Status:** Accepted
**Date:** 2026-04-20

## Context

Canary tokens are one of Bulwark's three-layer defenses — a tripwire that fires when an LLM echoes a configured sentinel string, proving the model read untrusted content. They sit in `bulwark-config.yaml` under `canary_tokens: {label: value}`, loaded on startup and checked on every Phase 1 → Phase 2 transition.

Today, managing them is hostile:

- The dashboard's Configure page shows the configured list but is **read-only**. The page literally instructs users to "Add entries to `bulwark-config.yaml` under `canary_tokens`" (`src/bulwark/dashboard/static/src/page-configure.jsx:311`).
- Adding a canary requires editing YAML directly, or crafting a `curl PUT /api/config` with a JSON body (partial update via the existing `/api/config` PUT).
- There is no token generator. Users have to invent plausibly-real sentinel values themselves. A good canary has specific properties — shape matching a real credential format (so an LLM will plausibly echo it), uniqueness (no overlap with real content), and categorisation (to know *what* leaked). Most users will get this wrong.
- There is no CLI. `bulwark-bench` exists as its own entry point; nothing similar for canaries.

Canary management was designed as "config", but it is actually **policy**. Rotating a leaked canary, adding a new tripwire after deploying a new integration, or removing a stale one are ordinary security-hygiene operations that should not require editing YAML by hand.

## Decision

Treat canary management as a first-class product feature with three surfaces:

1. **HTTP API** — `GET /api/canaries`, `POST /api/canaries`, `DELETE /api/canaries/{label}` — in the public `spec/openapi.yaml`, not the internal allowlist. Integrators can script rotation from CI. Contract: `spec/contracts/canaries.yaml` with `G-CANARY-NNN` guarantees.
2. **Dashboard UI** — Configure page's Canary panel becomes a real form: Add (with optional generator), Remove, and a shape picker for well-known credential formats.
3. **CLI** — `bulwark canary {add, list, remove, generate}` subcommands in the existing `bulwark` click group. Reuses the HTTP API; the CLI is a convenience wrapper over `POST/DELETE /api/canaries`.

Token shapes are a bounded enum: `aws`, `bearer`, `password`, `url`, `mongo`. Each shape emits a string that:
- Matches a recognisable real-credential pattern (so the LLM is likely to echo).
- Contains a UUID-derived suffix guaranteeing uniqueness across generations.
- Is marked internally as "never a real secret" (the user can copy-paste freely).

### What this is NOT

- **Not** an alerting system. Blocks still surface via the existing event bus. Hooking Slack/webhooks is a separate decision (ADR-TBD, not this change).
- **Not** a token store with encryption-at-rest. The file is still `bulwark-config.yaml`, bind-mounted as the user chooses. The container runs as `bulwark` user; file permissions are the operator's concern.
- **Not** a rotation grace period. Removing a canary removes it immediately; re-adding under the same label replaces the value. Grace-period semantics (old + new match during a rotation window) are a deliberate non-goal for this change.
- **Not** an overlap detector (preventing a canary that's a substring of another real value). Also deferred.

## Consequences

### Positive
- Canary adoption goes up because setup is three clicks, not a YAML edit.
- CI-driven rotation works: `bulwark canary add prod-db-url --shape url` becomes a deploy-time hook.
- The shape generator produces consistent, defensible canaries — fewer false positives from values that look too close to real content, fewer false negatives from canaries the LLM wouldn't recognise.
- Dashboard UI aligns with the rest of the Configure page (LLM backend, guard patterns, integrations are all editable; canaries were the odd read-only fish).

### Negative
- Three new endpoints expand the public API surface. They need the full auth middleware; they need OpenAPI entries; they become a stability promise.
- Shape library is bounded to 5 today. New shapes require a code change + contract bump. Users wanting custom shapes must still paste a literal token (the `POST` body accepts `token` directly).

### Neutral
- Storage stays in `bulwark-config.yaml`. No new persistence layer, no migration.
- The existing `PUT /api/config` still accepts `canary_tokens` as a partial update. The new endpoints are additional affordances, not a replacement. This preserves the `docker compose up -d` + curl-PUT flow for users who prefer it.
