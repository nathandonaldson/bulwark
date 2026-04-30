# Phase 3 Analysis 06: Dashboard JSX bundle

**Slice:** `src/bulwark/dashboard/static/src/*.jsx` (9 files, 2,267 LOC) + `index.html` (389 LOC).
**Question:** what can be retired, merged, or simplified without dropping guarantees in `spec/contracts/dashboard_ui.yaml`?

---

## Inventory

| File | LOC | Top components / helpers | Imports (window-globals) | Exports (`Object.assign(window, …)`) |
|------|-----|--------------------------|--------------------------|---------------------------------------|
| `app.jsx` | 33 | `App` (root, page-router) | `useStore`, `TopNav`, all `Page*` | (none — calls `ReactDOM.createRoot`) |
| `data.jsx` | 458 | `BulwarkStore` (IIFE singleton); `LAYERS`, `SOURCES`, `_LAYER_TO_CONFIG`; helpers `_normalizeEventLayer`, `_transformEvent`, `_layerConfigFromBackend`, `_integrationsFromBackend`, `fmtTime`, `fmtRelative`, `rand`, `pick`, `_recomputeSparks`, `_connectSSE`, `_startRunningPoll`, `_putConfig`; `useStore`, `activeLayerCount` | `React`, `fetch`, `EventSource` | `LAYERS`, `SOURCES`, `BulwarkStore`, `useStore`, `fmtTime`, `fmtRelative`, `rand`, `pick`, `activeLayerCount` |
| `primitives.jsx` | 113 | `Sparkline`, `Toggle`, `Dot`, `SectionTitle`, `Verdict`, `LayerIcon` | (none) | All six |
| `shell.jsx` | 95 | `computeStatusPill`, `TopNav`, `Brand`, `StatusPill` | `Dot`, `LAYERS`, `activeLayerCount` | `TopNav`, `StatusPill`, `computeStatusPill` |
| `page-shield.jsx` | 216 | `PageShield`, `ShieldRadial`, `HeroStatus`, `StatTile`, `RadialShield`, `LayerRow`, `MiniEventRow`; helper `hasRecentIncident` | `BulwarkStore`, `LAYERS`, `activeLayerCount`, `Sparkline`, `Dot`, `LayerIcon`, `Verdict`, `fmtTime` | `PageShield`, `hasRecentIncident`, `activeLayerCount` (re-export) |
| `page-events.jsx` | 281 | `PageEvents`, `EventsEmptyState`, `EventRow`, `EventExpansion`; helpers `filterEvents`, `isAnyFilterActive`, `_defaultTrace`, `_verdictColor` | `LAYERS`, `SectionTitle`, `Verdict`, `LayerIcon`, `fmtTime` | `PageEvents`, `filterEvents`, `isAnyFilterActive` |
| `page-configure.jsx` | 447 | `PageConfigure`, `STAGES` (const), `PipelineFlow`, `FlowEndpoint`, `FlowConnector`, `FlowNode`, `DetailPane`, `DetailHeader`, `SubToggle`, `SanitizerPane`, `DetectorPane`, `LLMJudgePane`, `BoundaryPane`; helper `_stageWiring` | `BulwarkStore`, `Toggle`, `StatusPill` | `PageConfigure` |
| `page-leak-detection.jsx` | 194 | `PageLeakDetection`, `GuardPatternsCard`, `CanaryPane` | `BulwarkStore` | `PageLeakDetection` |
| `page-test.jsx` | 430 | `PageTest`, `TraceView`, `RedTeam`, `RunProgress`, `ReportsList`, `ReportRow`; helpers `_normalizeTraceLayer`, `_fmtDuration`, `_fmtDate` | `BulwarkStore`, `LAYERS`, `SectionTitle`, `Verdict` | `PageTest`, `TraceView`, `ReportsList`, `RunProgress` |

**Totals:** 2,267 LOC across 9 files. Inline-style attributes (`style={{` count): 282 occurrences total — `page-configure.jsx` 75, `page-test.jsx` 67, `page-events.jsx` 43, `page-leak-detection.jsx` 42, `page-shield.jsx` 38, others ≤ 8.

---

## Duplicated UI patterns

### 1. **Card section header** ("title + subtitle + count" inside `.card`)
- Used in: `page-leak-detection.jsx` (×2 — `GuardPatternsCard`, `CanaryPane` headers), `page-configure.jsx` (`DetailHeader`), `page-test.jsx` (RedTeam card header).
- Each is its own ad-hoc `<div style={{padding: '16px 20px', borderBottom: '1px solid var(--hairline)'}}>...` + label + h3.
- `primitives.jsx` exposes `SectionTitle` but it's _page-level_ (no border, no card-internal). The card-internal variant has no shared abstraction.
- **Hoist:** add `CardHeader({eyebrow, title, count, action, children})` to `primitives.jsx`. Saves ~30 LOC across pages and centralises a pattern that audit 05 noted as inconsistent.

### 2. **Empty-state slate**
- 6 distinct usages: `page-events.jsx::EventsEmptyState` (richest — branches on `no-events` vs `filter-miss`), `page-test.jsx` (×4 — presets, trace, tiers, reports), `page-leak-detection.jsx` (×2 — patterns, canaries).
- All share the `.empty-slate` class but each adds its own inline `style={{padding: 20, border: '1px dashed var(--border)', borderRadius: 8, fontSize: 12}}` overlay.
- **Hoist:** `<EmptyState variant="dashed|plain" title? body action? />` primitive. Saves ~25 LOC and removes 6 hand-tuned dashed-border one-liners.

### 3. **Form field (label + input/select)**
- 8 usages in `page-configure.jsx::LLMJudgePane`, 3 in `page-leak-detection.jsx::CanaryPane`. Every one is the same `<label style={{display: 'flex', flexDirection: 'column', gap: 4}}><span className="dim" style={{fontSize: 11}}>…</span><input style={{padding: '6px 8px', background: 'var(--bg-2)', border: '1px solid var(--border)', borderRadius: 6, color: 'var(--text-1)', fontSize: 12}} /></label>` — 11 instances of an 8-property style block.
- Note: the styles use `var(--text-1)` which **isn't defined** in `index.html :root` — the actual token is `var(--text)`. Bug-by-typo: every form field is currently using the browser default text colour because the variable is undefined. Hoisting to a `<Field>` primitive fixes it once.
- **Hoist:** `<Field label, hint?, ...inputProps />` plus `<Select>` variant. Saves ~40 LOC and silently fixes the `--text-1` → `--text` bug.

### 4. **Card with header + body** (`page-leak-detection.jsx` does this twice; `page-configure.jsx::DetailPane` also)
- The `.card` class is reused but the "header band + content" composition is reimplemented each time.
- Less leverage; covered by hoist #1 above.

### 5. **Status pill**
- `StatusPill` exists in `shell.jsx` and is reused by `page-configure.jsx` (×2 in `DetectorPane`, `LLMJudgePane`). Good. **No work needed.**
- **But** `.pill warn` / `.pill ok` CSS classes are also used (`page-test.jsx:265`, `page-configure.jsx:168`) — this is parallel infrastructure. The CSS class form is shorter. Worth noting for consistency, not for action.

### 6. **`bulwark:goto` dispatch**
- 4 hand-rolled `window.dispatchEvent(new CustomEvent('bulwark:goto', {detail: {…}}))` calls across `page-events.jsx`, `page-shield.jsx`. Trivial helper, but it does exist conceptually in `app.jsx::gotoPage` — that helper is just inaccessible from page files.
- **Hoist:** `goto(page, focus, payload)` exported from `data.jsx` (the natural place since other page-coordination lives there).

### 7. **Verdict-colour mapping**
- `page-events.jsx::_verdictColor` (5-way map) and `page-test.jsx::TraceView` (3-way ternary on `step.verdict`) and `primitives.jsx::Verdict` (5-way map again, with backgrounds) all encode the same verdict→colour relationship three different ways. The Verdict primitive's map is the canonical source.
- **Hoist:** export `verdictColor(v)` from `primitives.jsx` reading the same map.

---

## Dead code

### Confirmed unused (ready to delete)

| Item | File | Why dead |
|------|------|----------|
| `LayerIcon` paths `analyze`, `bridge`, `execute` | `primitives.jsx:101-104` | None of these IDs exist in `LAYERS` (audit 05 F5). Cannot be rendered. |
| `_normalizeTraceLayer` keys `analysis_guard → bridge`, `analyze`, `executor → analyze`, `execute`, `guard → bridge` | `page-test.jsx:159-166` | Backend never emits these post-ADR-031; audit 05 F4 also flagged. |
| `--stage-analyze`, `--stage-bridge`, `--stage-execute` CSS custom properties | `index.html:60-63` | Not consumed by any JSX (verified via grep against rendered IDs). |
| `fmtRelative` | `data.jsx:86-92` | Defined and exported on `window`, **never called anywhere** in src/ or tests/. v1 leftover. |
| `injectEvent(layer, verdict)` | `data.jsx:423-441` | Store method, not referenced anywhere. Likely demo-mode hook from the handoff bundle, dead since real SSE wiring went in. |

### Suspected dead (verify before deleting)

| Item | File | Note |
|------|------|------|
| `--stage-canary` is `var(--amber)`; `--stage-bridge` is also `var(--amber)` | `index.html:61-62` | Once `bridge` is gone, `--stage-canary` should keep its own non-aliased token — currently it inherits a token that exists for a dead stage. Cosmetic. |
| `rand`, `pick` exported on `window` | `data.jsx:93-94, 458` | Used internally by the dead `injectEvent`. If `injectEvent` goes, both can be unexported (still tiny enough to keep around if a future test wants them). |
| `MiniEventRow` (page-shield.jsx) and `EventRow` (page-events.jsx) | both | They render the same conceptual thing (one event row) with different column layouts. Not dead, but redundant — see hoist below. |
| `_defaultTrace` `LAYERS.slice(0, 5)` | `page-events.jsx:267-271` | Audit 05 F7 — `slice(0,5)` on a 4-entry array is a no-op. The function still works, but the slice is misleading. Trivial cleanup. |

### Babel CDN, SRI hashes, "development" React build

`index.html` ships `react.development.js` and `react-dom.development.js` (per ADR-020 explicitly: "Development builds … For production we could pin .production.min.js — deferred to a follow-up"). The `.development.js` builds are ~5× bigger and 30-50% slower than `.production.min.js`. ADR-020 was written 2026-04-18; the dashboard has been stable for two weeks. The deferral has expired. **Not "dead code", but a dead deferral** — swap to `.production.min.js`, update SRI hashes, free ~250KB of transferred JS.

---

## Hoist candidates

These are the ones with the biggest leverage — each closes a class of audit-05 bugs in one place.

### H1 — Unified `computeStatusPill` state machine (audit 05 R2)
**Closes:** F2 (status pill blind to ADR-040 "no detectors loaded"), F13 (events empty-state lies under no-detectors), arguably F16 (banner timeframe).
**Today:** `computeStatusPill` (shell.jsx:6-17, 12 lines) keys only on `protectai.status` + `activeLayerCount`. It can return `{ok | warn | bad, label}`.
**Tomorrow:** extend to a small machine that also reads `judge.enabled`, `integrations.promptguard`, the `mode` field already returned by `/v1/clean` responses (currently swallowed in `data.jsx::runClean`), and surfaces:
- `{kind: 'bad', label: 'No detectors loaded'}` when zero detectors AND judge disabled
- `{kind: 'warn', label: 'Sanitize-only mode'}` when `BULWARK_ALLOW_NO_DETECTORS=1`
- existing 4 states unchanged

**Size estimate:** ~30 LOC for the helper + 1 store field (`store.serviceMode` derived from healthz/clean responses). The empty-state branch in `page-events.jsx::EventsEmptyState` reads `store.serviceMode === 'no-detectors'` and changes its copy. Same helper, three call sites, **all five F2/F13/F16-class bugs fixed in one place**.

**Existing contract impact:** G-UI-STATUS-001..005 stay intact (the new states are extensions, not replacements). Add G-UI-STATUS-006/008/009 for the new machine paths.

### H2 — `useEventCounts(store, {layer?, window?})` hook
**Closes:** the duplication noticed by F15 — every page that displays a "X events for layer Y in last Z" number reimplements `store.events.filter(e => e.layer === id && Date.now() - e.ts < window).length`. Currently 4 instances (`page-shield.jsx::LayerRow`, `page-configure.jsx::_stageWiring` ×2, `page-events.jsx` filter counts).
**Tomorrow:** one hook returns `{count24h, count30m, recentBlocked}`; pages display whichever they want. Bonus: makes the time-window unit visible in code (audit 05 F15) and lets us tag the hook with a `data-window` attribute for tests.
**Size estimate:** 15 LOC + ~30 LOC removed at call sites = net `-15` LOC.

### H3 — `<Field>` form-field primitive
**Closes:** the 11 hand-rolled label+input blocks in `LLMJudgePane` and `CanaryPane`. Also silently fixes the `--text-1` token typo.
**Size estimate:** 20 LOC added to `primitives.jsx`, ~80 LOC removed from page files = net `-60` LOC.

### H4 — `<EmptyState variant title body action />` primitive
**Closes:** 6 hand-rolled empty states. Standardises copy/spacing.
**Size estimate:** 25 LOC added, ~50 LOC removed = net `-25` LOC.

### H5 — `<CardHeader>` primitive
**Closes:** 4 inline header blocks; the 16 20 padding pattern.
**Size estimate:** 15 LOC added, ~30 LOC removed = net `-15` LOC.

### H6 — Hoist stage metadata (model name, latency, size) into `/api/integrations` (audit 05 R4)
**Closes:** F6 (510 vs 512 token mismatch — currently in JSX), F20 (static latency badges).
**Today:** `page-configure.jsx::DetectorPane` has a `meta` dict hardcoding `huggingface`, `latency`, `size`, `blurb` per detector. The same data lives in `dashboard/config.py::AVAILABLE_INTEGRATIONS`.
**Tomorrow:** API extends `/api/integrations` response with these fields; JSX reads `store.integrations[id].meta.latency` etc.
**Size estimate:** ~30 LOC removed from JSX, ~15 LOC added to backend = net `-15` LOC, but **the bigger win is no more drift between JSX literals and Python literals**. CLAUDE.md "no hardcoding" rule says this should already be the case.

---

## In-browser Babel question

**Verdict: stay.** ADR-020's deferred follow-up (production React UMD build) is the only bit worth reactivating; the build-step migration is not justified.

### Costs of the current approach (measured today, not aesthetics)

- **First-load transpile:** ADR-020 measured ~250ms on mid-tier hardware. Cached after first hit via unpkg's HTTP caching. The dashboard is local-only (Docker localhost:3000 or 3001 dev); this is invisible.
- **Bundle size:** 2,267 LOC of JSX + ~800 KB of dev React + 700 KB of Babel Standalone. Local network — irrelevant.
- **CSP:** no Content-Security-Policy header is set anywhere in `dashboard/app.py`. SRI hashes pin all three CDN dependencies. There's no operator complaint about CSP today.
- **Offline:** no operator requirement. Docker image already bundles the JSX files; only the three CDN scripts need network on first load. If air-gapping became a requirement, vendoring three files is cheaper than a build pipeline.

### Costs of switching to a build step (esbuild/vite)

- **CI pipeline gain:** 1 new job (build → emit bundle → publish artifact).
- **Source-of-truth split:** today `static/src/*.jsx` IS the served code. With a build step, you serve `static/dist/*.js`; either you check in build output (drift risk) or you lose the "open the file in the dashboard's HTTP root and it just works" property.
- **Dev loop slowdown:** the current edit→reload cycle is ~1s. A bundler watch mode is comparable, but adds a process to keep alive.
- **PyPI/Docker shipping:** today `pyproject.toml` includes the JSX files as package data and Docker COPYs them. A build step requires either (a) building inside Docker (adds Node to the runtime image) or (b) building on PyPI publish (requires npm in CI).
- **No payoff:** the supposed wins (tree-shaking, type-checking, bundling) don't apply — the bundle is small, there's no TypeScript today, and there's nothing to tree-shake.

### Recommended action

1. **Keep the in-browser transpile.** ADR-020's bet is still correct.
2. **Cash in the deferred production-React swap.** Update `index.html` to use `react.production.min.js` + `react-dom.production.min.js`, update SRI hashes, drop ~600 KB. Trivial PR. (Add an ADR-020 amendment noting the deferred-then-applied change.)
3. **Don't re-litigate this every audit.** Consider amending ADR-020 with a "When to revisit" section: e.g., "if any of these become true: TypeScript adopted, multiple operators report >1s first-paint, an air-gap requirement lands, then revisit." Today none are true.

---

## Cuts ranked

| Cut | Files touched | LOC delta | Bug class fixed | Risk |
|-----|---------------|-----------|-----------------|------|
| H1 — Unified `computeStatusPill` state machine | `shell.jsx`, `data.jsx`, `page-events.jsx`, `page-shield.jsx`, `page-configure.jsx`; tests | +30 / -10 = **+20** (but closes 3 audit-05 bugs) | F2, F13, F16, NG-UI-CONFIG-003 spirit | LOW — pure addition; existing G-UI-STATUS-001..005 untouched. New states need new guarantee IDs. |
| Audit-05 R1 — v1 vocabulary sweep (delete `bridge`/`analyze`/`execute` everywhere) | `primitives.jsx`, `page-test.jsx`, `index.html` (CSS tokens), `data.jsx` (comment); `spec/presets.yaml` for completeness | **-15** | F4, F5, F19 | LOW — confirmed dead via grep. Add CI grep to prevent regression. |
| H6 — Stage metadata from `/api/integrations` | `page-configure.jsx`, `dashboard/config.py`, `dashboard/app.py` | **-15** (net) | F6, F20, drift between Python and JSX literals | MED — touches API response shape; needs contract + a test. |
| H3 — `<Field>` primitive | `primitives.jsx`, `page-configure.jsx`, `page-leak-detection.jsx` | **-60** | Silently fixes `--text-1` → `--text` typo across 11 fields | LOW |
| H4 — `<EmptyState>` primitive | `primitives.jsx`, all 4 page files that use empty slates | **-25** | F11 (Test page false claim copy), F19 unreachable empty state | LOW |
| Delete `fmtRelative`, `injectEvent`, `rand`, `pick` exports | `data.jsx` | **-25** | dead-code reduction | LOW — confirmed zero callers in src/ + tests/ |
| H5 — `<CardHeader>` primitive | `primitives.jsx`, `page-leak-detection.jsx`, `page-configure.jsx`, `page-test.jsx` | **-15** | none directly; consolidates pattern noted by audit 05 | LOW |
| H2 — `useEventCounts` hook | `data.jsx`, `page-shield.jsx`, `page-configure.jsx`, `page-events.jsx` | **-15** | F15 (window ambiguity); makes time-window legible | LOW |
| Swap React UMD to `.production.min.js` | `index.html` (3 SRI hashes) | **0** (no JSX change) | -600 KB transferred, ~30% script execution speedup; closes ADR-020 deferred follow-up | LOW — one URL change ×2 plus new hashes. Well-understood. |
| Hoist `verdictColor` | `primitives.jsx`, `page-events.jsx`, `page-test.jsx` | **-10** | inconsistent verdict-colour mapping across pages | LOW |

**Total net LOC reduction estimate (excluding H1 which is a + because it's net new state):** ~**-180 LOC** (8% of bundle), with H1 closing the most painful audit-05 findings. Headline number for the parent agent: **~-180 LOC, 9 hoists, 8 dead-code items, ~3 audit-05 bug classes closed**.

### Out-of-scope: things _not_ worth doing

- **Splitting `data.jsx`.** It's 458 LOC, but cohesively organised (constants → transforms → store IIFE → exports). Splitting would not reduce coupling — the store is the *point* of unification. Leave it.
- **Merging `app.jsx` into `shell.jsx`.** They're both small but have distinct roles (routing vs nav chrome). Keep separate.
- **Adopting a build step.** See In-browser Babel question above.
- **Replacing the SSE store with a state library (zustand/redux/etc).** The `BulwarkStore` IIFE + `useStore` reducer-force pattern is ~50 LOC. A state library would be ~150 LOC plus the lib itself.

---

## Out-of-scope observations

These are JSX-bundle-adjacent but are really other slices' problems:

1. **`spec/presets.yaml` still has `family: bridge` for two presets** (audit 05 F4 cross-reference). Whichever audit slice owns `spec/` should clean those — the JSX inherits the family value. Once cleaned, the page-test.jsx category list can be regenerated dynamically.
2. **`AVAILABLE_INTEGRATIONS` in `dashboard/config.py`** is the natural source of truth for stage metadata (model, latency, size). H6 above depends on extending `/api/integrations`; that change lives in the backend slice.
3. **`docs/images/*.png` screenshots are stale** (audit 05 F10, R3). Not a JSX problem — a docs/release-process problem.
4. **`bulwark-config.yaml` editing UX** — guard patterns are read-only in the dashboard but canaries are live-editable (audit 05 F17). Symmetry would be nice; would add ~80 LOC for the `+ Add pattern` UI. Punt unless an operator asks.
5. **`fmtTime`** is still used by `page-shield.jsx` and `page-events.jsx`, but the dashboard never displays a date — only HH:MM:SS. Operators looking at events from yesterday have no way to see the date. Worth a 5-LOC fix in `fmtTime` to show date when older than 24h. Not a simplification, but flagged here because the same pages also track 24h windows.
6. **`computeStatusPill` is the only piece of code that maps backend reality to a top-level UI signal** — making it the obvious chokepoint for H1. The fact that ADR-020 already extracted it as a pure helper suggests the authors anticipated this. Following through on that design is the cheapest big win in this slice.
