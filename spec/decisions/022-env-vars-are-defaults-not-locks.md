# ADR-022: Env-shadowed LLM fields are editable defaults, not hard locks

**Status:** Accepted
**Date:** 2026-04-18

## Context

Stage 7 of the dashboard redesign (ADR-020) rendered any LLM-backend field
covered by a `BULWARK_*` env var as a read-only `<div>` showing the current
value plus the env var name. This was a deliberate correction to the prior UX
bug where the field rendered as an `<input>` that couldn't actually be typed
into — silently ignored keystrokes are worse than no input at all.

The read-only render solved the "confusing ghost input" symptom but created a
new problem: there was no way to try a different key/model/mode from the UI
without restarting the process with a different env var. That matters on the
Docker image where the user wanted to flip Anthropic ↔ local OpenAI-compatible
ad-hoc without rewriting `.env` and restarting.

Tracing the backend:

- `update_from_dict` (`src/bulwark/dashboard/config.py`) honors **non-empty**
  updates to env-shadowed LLM fields. G-ENV-012 only skips empty-string
  updates — exactly the case where the old UI sent `""` for a blanked field
  and would have clobbered the env value.
- `save()` blanks env-shadowed fields before persisting (G-ENV-013), so
  secrets don't land on disk.
- `_apply_env_vars()` only runs on `load()`, not after every `save()`. So a
  UI override lives in the in-memory `config` for the session and is
  restored to the env value on process restart.

So the backend already implements "env var is the default, UI overrides for
the session". The dashboard's read-only render was the only thing blocking it.

## Decision

Env-shadowed LLM fields render as **editable inputs** with an `ENV` badge
next to the label and a dim helper line naming the env var (e.g.
"Env default: `BULWARK_API_KEY` (•••a3f2). Type a new key to override for
this session — env restores on restart."). The UI value always wins for the
active session; the env var reasserts on process restart via `_apply_env_vars`.

- API key: password input, empty initially (don't pre-fill the masked value).
  Placeholder shows the preview (`•••a3f2`).
- Base URL: text input, pre-filled with the current value.
- Mode cards: all three cards clickable, no `disabled` attribute. The click
  routes through `BulwarkStore.setLlm({mode})` as for non-env-shadowed state.
- Analyze/Execute model dropdowns: populated from `/v1/llm/models`, value
  pre-filled with the current setting.
- `save()` always sends every edited field; the backend's G-ENV-012 guard
  protects env defaults from empty-string clobbers, but non-empty edits flow
  through untouched.

## Consequences

### Positive

- Users can swap LLM backends mid-session from the UI without editing env or
  restarting the container. Matches the Docker-first UX the project ships.
- The "can't type into this input" bug is still fixed — we never render an
  `<input>` that ignores keystrokes. Inputs are either editable or replaced
  with a different element entirely.
- The env var retains its role as the persistent-across-restarts default,
  which is what makes Docker + `.env` setups durable.

### Negative

- Users who assume the UI persists their choice will be surprised on
  restart when the env value comes back. Mitigated by the helper line
  naming the env var and the "env restores on restart" phrasing.
- A badly formatted UI edit (e.g. broken API key) can mask an otherwise-working
  env default until restart. Mitigated by the "Test connection" button which
  probes the in-memory config.

### Neutral

- Supersedes G-UI-CONFIG-API-KEY-LOCKED and G-UI-CONFIG-LOCKED-FIELDS-001
  from dashboard_ui.yaml. Those guarantees are removed; replaced by
  G-UI-CONFIG-ENV-BADGE / G-UI-CONFIG-ENV-EDITABLE / G-UI-CONFIG-ENV-OVERRIDE.
- Does not change any backend endpoint or YAML schema. The `env_overrides`
  map in `/api/config` responses keeps its existing shape; the frontend just
  interprets it differently.
