# ADR-020: Dashboard adopts React + Babel-in-browser

**Status:** Accepted
**Date:** 2026-04-18

## Context

The dashboard redesign (handoff in `bulwark-sentry-design-handoff/`) ships as React/JSX prototypes split across `index.html` + seven `src/*.jsx` files, loaded via Babel Standalone UMD bundles. The current `src/bulwark/dashboard/static/index.html` is ~2,240 lines of single-file vanilla JS.

Two implementation paths were considered:

1. **Port to vanilla.** Rewrite the reference JSX as vanilla JS inside the existing single-file dashboard.
2. **Adopt the reference architecture as-is.** Copy the reference HTML + JSX into `static/`, swap the mock `BulwarkStore` for real API calls.

Option 1 duplicates the reference (two sources of truth that drift). Option 2 keeps the designer's source as the implementation — lower drift risk, faster delivery, but introduces Babel Standalone + React UMD as page-load dependencies.

## Decision

**Adopt Option 2.** The dashboard's new `static/index.html` uses React 18.3.1 UMD + Babel Standalone to load and transpile the JSX component tree at runtime. The `data.jsx` seam is the only module that changes between the handoff reference and production — it swaps the mock store for real `fetch`/SSE calls against existing endpoints.

### Pinned dependencies

- `react@18.3.1` (UMD, development build, SRI-pinned)
- `react-dom@18.3.1` (UMD, development build, SRI-pinned)
- `@babel/standalone@7.29.0` (SRI-pinned)

All three are served from `unpkg.com` with `integrity=""` attributes matching the reference bundle. SRI pinning is the CSP-equivalent defense against CDN compromise for this architecture.

### Scope constraints carried forward

- **Tweaks panel removed.** Production ships a single layout: `data-nav="tabs"`, `data-type="default"`, Shield variant `radial`. The `ShieldData` and `ShieldHybrid` alternate variants are deleted. Type-variant attributes (`data-type="editorial"`, `data-type="mono"`) remain available via CSS but have no runtime toggle.
- **No hardcoding.** Every literal in the reference (model names, preset payloads, layer descriptions, API-key mask format, version string, canary tokens, ring colors) must resolve to either a CSS custom property (tokens) or a value fetched from an existing endpoint. Anything that lacks a source of truth gets one added in a follow-up ADR (e.g., ADR-021 for presets).

## Consequences

### Positive

- Single source of truth — the designer's JSX *is* the implementation, no port-drift possible.
- Component split (primitives / shell / per-page files) scales better than 2,240-line monolith.
- New design tokens (`--accent`, `--border-2`, `--hairline`, etc.) apply globally via `:root`.
- Restricted surface for changes — most future design edits touch one `page-*.jsx` file.

### Negative

- First page load transpiles ~1,600 lines of JSX in the browser via Babel Standalone. Measured cost: ~250ms on mid-tier hardware, cached after first hit via HTTP caching headers on unpkg.
- Three new CDN dependencies. Mitigated by SRI hashes; not mitigated if offline. Offline mode is not a current requirement.
- Development builds of React UMD. For production we could pin `.production.min.js` — deferred to a follow-up; development build gives clearer error traces while design-refresh is settling.

### Neutral

- JSX files are plain text in `static/` and served by FastAPI's existing `StaticFiles` mount. No build step added.
- The existing `test_dashboard_api.py` and `test_dashboard_layers.py` remain valid — they exercise JSON endpoints, not HTML.
- UI behavior contract moves to `spec/contracts/dashboard_ui.yaml` with guarantee IDs (`G-UI-STATUS-NNN`, `G-UI-INCIDENT-NNN`, `G-UI-EMPTY-NNN`) so state matrices in `STATES.md` are enforceable.

## References

- Handoff bundle: `bulwark-sentry-design-handoff/project/handoff/`
- Contract: `spec/contracts/dashboard_ui.yaml`
- Follow-up: ADR-021 (presets source of truth)
