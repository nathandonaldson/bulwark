# ADR-021: Attack presets live in `spec/presets.yaml`

**Status:** Accepted
**Date:** 2026-04-18

## Context

The Test page (both current dashboard and reference design) exposes a "Payload library" of attack presets users can click to populate the test input. Today those literals live in two places:

- `src/bulwark/dashboard/static/index.html` — `const PRESETS = {…}` (8 entries, current UI)
- `bulwark-sentry-design-handoff/project/handoff/reference/src/data.jsx` — `const PRESETS = […]` (8 entries, each with `family`)

They disagree on payloads, names, and the presence of a `family` field. Shipping the redesign without fixing this creates a third copy and violates the no-hardcoding ground rule for the `design-refresh` branch.

Presets are content — part of the product's documented threat-model examples — not an internal implementation detail. They should have a versioned source of truth separate from the UI so that:

- Both the dashboard and future CLI tools (`bulwark test --preset zw`) can read the same list.
- Adding a preset doesn't require a UI commit.
- The red-team suite can cross-reference preset IDs.

## Decision

Create `spec/presets.yaml` as the single source of truth for attack presets. Each preset has:

- `id` — stable identifier (e.g., `zw`, `xml`, `override`)
- `name` — display name (e.g., "Zero-width steganography")
- `family` — the pipeline stage expected to block it (`sanitizer` | `boundary` | `bridge` | `detection`)
- `payload` — the literal string content sent to `/v1/clean`
- `description` — optional longer-form explanation

Expose via `GET /api/presets` returning `{presets: [...]}`. The dashboard fetches this once on load and caches in the store. No DB; the YAML file is read at request time (presets change on deploy, not at runtime).

Loader lives at `src/bulwark/presets.py` with a single function `load_presets() -> list[Preset]` using stdlib `yaml` via the existing `bulwark.dashboard` dependency chain. Presets are validated at load time against a small dataclass schema; malformed YAML raises on startup (fail-loud).

## Consequences

### Positive

- Single source of truth. Removes the `const PRESETS = …` inlined in the old `static/index.html` and the reference `data.jsx`.
- Presets can grow without UI changes.
- Contract spec/contracts/presets.yaml documents guarantees (`G-PRESETS-NNN`) and makes additions testable.
- `family` field carries intent (what should block this) — useful for red-team verdict scoring.

### Negative

- Extra round trip on dashboard load. Small (~1 KB JSON), happens in parallel with config fetch, not user-visible.
- Any change to preset payloads now requires an edit to a spec file, not a quick code tweak. This is intentional — presets are documented behavior, not throwaway examples.

### Neutral

- YAML parser: `yaml` is already a transitive dependency via garak integration; we pin it as a direct dev-extra.
- File location under `spec/` (not `src/bulwark/data/`) emphasizes that presets are product documentation, not library data.
