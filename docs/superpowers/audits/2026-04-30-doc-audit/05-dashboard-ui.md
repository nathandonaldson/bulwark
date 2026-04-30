# Audit 05 — Dashboard UI strings & screenshots

**Auditor slice:** `src/bulwark/dashboard/static/src/*.jsx` + `docs/images/*`.
**Source-of-truth cross-references:** `dashboard/app.py`, `dashboard/api_v1.py`, `dashboard/config.py`, `pipeline.py`, `events.py`, `presets.yaml`, `CHANGELOG` v2.5.0–v2.5.9.

The dashboard's visible text is documentation that ships embedded in the binary. Below: every claim that diverges from what the code actually does, plus stale copy from v1 (pre-ADR-031) that should have been pruned.

---

## Findings

### F1 — `page-test.jsx:269` references a removed component (`LLM backend`)

- **File:** `src/bulwark/dashboard/static/src/page-test.jsx:269`
- **Category:** OBSOLETE
- **Severity:** CRITICAL
- **Claim:** `"Sends Garak's attack payloads through your real Bulwark pipeline with the configured LLM backend."`
- **Reality:** ADR-031 (v2.0.0) explicitly removed the LLM backend. `BulwarkConfig.load()` at `dashboard/config.py:184` actively *drops the legacy `llm_backend` field* if it's found in YAML. Bulwark v2 never invokes a generative LLM. Even the in-page Configure copy says so: `page-configure.jsx:22` — *"Bulwark never invokes a generative LLM."*
- **Recommended fix:** Replace with something accurate, e.g. `"Sends Garak's attack payloads through your real /v1/clean pipeline (sanitizer → DeBERTa / PromptGuard / optional LLM judge → trust boundary)."`

---

### F2 — Status pill never reports the ADR-040 / ADR-038 "no detectors loaded" state

- **File:** `src/bulwark/dashboard/static/src/shell.jsx:6-17` (`computeStatusPill`); `data.jsx:106-109` (`detectorStatus` shape)
- **Category:** MISSING
- **Severity:** CRITICAL
- **Claim (rendered):** `"All layers active"` whenever `activeLayerCount(layerConfig) === LAYERS.length`. Or `"X of N layers active"` when fewer toggles are on.
- **Reality:** Per ADR-040 / `api_v1.py:114-147`, a deployment with zero ML detectors loaded and judge disabled returns HTTP 503 + `error.code = "no_detectors_loaded"` from `/v1/clean`. Per ADR-038, an operator who flips `BULWARK_ALLOW_NO_DETECTORS=1` is in `mode: "degraded-explicit"` — the pipeline runs sanitizer-only with no detection. Neither state is surfaced anywhere in the dashboard. The status pill cheerfully reports "All layers active" while `/v1/clean` is responding 503 to every request. There's no JSX literal for `"degraded"` / `"sanitize-only"` / `"503"` / `"no_detectors_loaded"` anywhere in the bundle.
- **Recommended fix:** Extend `computeStatusPill` to also key on `detectorStatus.protectai.status === 'error'` AND `promptguard !== 'active'` AND `judge.enabled === false`, returning `{kind: 'bad', label: 'No detectors loaded'}`. When `BULWARK_ALLOW_NO_DETECTORS` is on, surface `mode: "degraded-explicit"` from `/v1/clean` responses (currently passed through `runClean` but unread) as `{kind: 'warn', label: 'Sanitize-only mode'}`.

---

### F3 — Header has a wired-but-not-wired search button (CLAUDE.md design rule violation)

- **File:** `src/bulwark/dashboard/static/src/shell.jsx:50`
- **Category:** WRONG
- **Severity:** IMPORTANT
- **Claim:** Tooltip `data-hint="Search events (⌘K)"` with a magnifying-glass icon, suggesting global search.
- **Reality:** `onClick={() => {}}` — a no-op. There is no event search modal anywhere in the JSX bundle, no ⌘K keyboard handler, nothing. This violates CLAUDE.md's rule: *"Don't add buttons that aren't wired up."*
- **Recommended fix:** Either wire it up to focus the Events page search input (event-bus dispatch to `bulwark:goto` with focus payload, then have `page-events.jsx` honor it), or delete the button. v2.3.1 (commit `123a314`) explicitly did a sweep of unwired buttons; this one slipped through.

---

### F4 — `page-test.jsx` "Bridge" category filter references a layer that no longer exists

- **File:** `src/bulwark/dashboard/static/src/page-test.jsx:34` (filter UI), `:159, :162-164` (`_normalizeTraceLayer` mapping)
- **Category:** STALE
- **Severity:** IMPORTANT
- **Claim:** Payload-library category buttons are `[All, Sanitizer, Boundary, Bridge]`. `_normalizeTraceLayer` maps `analysis_guard → bridge`, `guard → bridge`, and forwards `analyze`, `executor`, `execute`.
- **Reality:** `data.jsx:10-15` defines only four LAYERS — `sanitizer`, `detection`, `boundary`, `canary`. `data.jsx:38` maps `analysis_guard → canary` (the canonical mapping). The "Bridge" / "analyze" / "execute" / "executor" identifiers are v1 (pre-ADR-031, two-phase) leftovers. The `Layer` enum in `bulwark/events.py:17` no longer contains any of these. Two files (`data.jsx` and `page-test.jsx`) disagree on what `analysis_guard` maps to. The Test page also offers no `Detection` or `Canary` filter though both are valid `_ALLOWED_FAMILIES` values in `presets.py:18-20`.
- **Recommended fix:** Delete the `bridge` button. Replace with `Detection` and `Canary` buttons matching the post-ADR-031 layer set. Remove the `analyze` / `execute` / `executor` / `guard` keys from `_normalizeTraceLayer`. Make `analysis_guard → canary` to match `data.jsx`. Note: `spec/presets.yaml` itself still uses `family: bridge` for two presets (`b64`, `bridge`) — that's a doc-audit-1/2/3 finding (presets-spec stale), but flagging here because the JSX inherits whichever family value the spec uses.

---

### F5 — `primitives.jsx` carries dead-code icons for layers that no longer exist

- **File:** `src/bulwark/dashboard/static/src/primitives.jsx:96-105`
- **Category:** STALE
- **Severity:** MINOR
- **Claim:** `LayerIcon` ships SVG glyphs for `analyze`, `bridge`, `execute` alongside the four real layers.
- **Reality:** None of these IDs exist in the post-ADR-031 `LAYERS` array. They're never rendered (because nothing in the JSX passes those ids), but they're still in the bundle.
- **Recommended fix:** Delete the `analyze`, `bridge`, `execute` entries from the `paths` object.

---

### F6 — Configure page says DeBERTa uses "512-token windows"; CLAUDE.md says 510-token

- **File:** `src/bulwark/dashboard/static/src/page-configure.jsx:40, :256`
- **Category:** WRONG
- **Severity:** MINOR
- **Claim (line 40):** `"chunked across 512-token windows"`
- **Claim (line 256):** `"Inputs over 512 tokens are split into overlapping windows (ADR-032)"`
- **Reality:** Per CLAUDE.md and `bulwark/integrations/promptguard.py:78-83`, the chunking is **510-token windows with 64-token overlap** (model max 512 minus 2 reserved CLS/SEP tokens). The 512 number is the model context, not the window size.
- **Recommended fix:** Line 40: `"chunked across 510-token windows with 64-token overlap"`. Line 256: `"Inputs over 510 tokens are split into 510-token windows with 64-token overlap (ADR-032)…"`.

---

### F7 — `_defaultTrace` comment claims "5-step pipeline view"; LAYERS only has 4 entries

- **File:** `src/bulwark/dashboard/static/src/page-events.jsx:267-271`
- **Category:** STALE
- **Severity:** MINOR
- **Claim:** Comment: `"synthesize a 5-step pipeline view so the expansion pane still shows something useful"`. Code does `LAYERS.slice(0, 5)`.
- **Reality:** `LAYERS` is exactly 4 entries (`data.jsx:10-15`); slice(0,5) is a no-op cap that produces 4 items, not 5. The "5-step" wording dates from v1 (sanitizer → bridge → detection → boundary → canary).
- **Recommended fix:** `return LAYERS.map(l => ({ id: l.id }));` and update the comment to "synthesize a per-layer pipeline view."

---

### F8 — Configure page's hard-coded "3,112 probes / 100% defense" claim drifts whenever Garak ships new probes

- **File:** `src/bulwark/dashboard/static/src/page-configure.jsx:356`
- **Category:** STALE
- **Severity:** IMPORTANT
- **Claim:** `"Bulwark's standard red-team scan (3,112 probes) achieves 100% defense without it."`
- **Reality:** The 3,112 number is a frozen-in-time figure from v2.1.0 (referenced in ADR-033, ADR-035, CHANGELOG line 329). The actual standard-tier probe count is computed dynamically by `_compute_redteam_tiers` in `dashboard/app.py:736-765` from `garak.probes.<family>` introspection — meaning the count moves whenever the operator's installed Garak version ships new probes. The dashboard's own Test page (`page-test.jsx:295`) renders the *real* live count in its tier card, while the Configure page hard-codes the stale 3,112. A user comparing the two pages will see contradictory numbers.
- **Recommended fix:** Either (a) drop the count entirely — `"Bulwark's standard red-team scan achieves 100% defense without it."` — or (b) fetch and interpolate `store.redteamTiers.tiers.find(t => t.id === 'standard').probe_count`. Option (a) is lower-maintenance.

---

### F9 — `data.jsx:11` Sanitizer description omits NFKC / encoding / base64 (the toggles the same store exposes)

- **File:** `src/bulwark/dashboard/static/src/data.jsx:11`
- **Category:** INCOMPLETE
- **Severity:** MINOR
- **Claim:** `desc: 'Strips hidden chars, steganography, control sequences'`
- **Reality:** Same module's `_LAYER_TO_CONFIG` (lines 22-27) wires sanitizer sub-toggles for `nfkc` (Unicode normalization), `encoding_canaries` (HTML/percent decode, ADR-039), and `decode_base64` (ADR-047 base64 rescan). The Configure page's `SanitizerPane` lists all five sub-toggles. The Shield page's layer-row description elides them.
- **Recommended fix:** `desc: 'Strips hidden chars, decodes encodings, normalizes Unicode'` — short enough for the layer card, accurate enough to match what the Configure page exposes.

---

### F10 — Screenshots predate the v2.5.5 base64-decode toggle and v2.5.9 design state

- **Files:** `docs/images/configure.png`, `docs/images/shield.png`, `docs/images/leak-detection.png`, `docs/images/configure-judge.png` (mtimes Apr 23 20:02), `docs/images/test.png`, `docs/images/events.png` (Apr 23 20:16)
- **Category:** STALE
- **Severity:** IMPORTANT
- **Claim:** README v2 prose presents these as the current dashboard.
- **Reality:** `page-configure.jsx` was modified on Apr 30 (commit `c8157cf`, v2.5.5) to add the **Base64 decode-rescan** sub-toggle in the Sanitizer pane. The Apr 23 `configure.png` cannot show this control. The README text adjacent to `configure.png` (line 87-92) doesn't mention base64 either; both halves are stale together.
  - `data.jsx` was likewise modified on Apr 30 (added `decode_base64` to `_LAYER_TO_CONFIG` and `layerConfig`).
  - The other PNGs (Apr 23) predate the recent design tweaks (v2.4.x, v2.5.x). Without opening them I can confirm only the timestamp drift.
- **Recommended fix:** Re-shoot `configure.png` after the Apr 30 changes. Re-shoot all six PNGs at the next dashboard-touching version bump and bake into the release-doc skill (`document-release` already exists). Optionally: add a CI check that fails if `docs/images/*.png` mtime predates the most recent JSX commit by > 2 versions.

---

### F11 — Test page payload-library description claim ("…select a preset, or generate payloads") implies a feature that doesn't exist

- **File:** `src/bulwark/dashboard/static/src/page-test.jsx:71`
- **Category:** WRONG
- **Severity:** MINOR
- **Claim:** `"Paste untrusted content, select a preset, or generate payloads"`
- **Reality:** There is no payload-generation UI on the page. Presets come from `/api/presets` (the static `spec/presets.yaml`); the only ways to populate the editor are paste, click-a-preset, or "Replay in Test" from Events. No generator exists.
- **Recommended fix:** `"Paste untrusted content or select a preset"`.

---

### F12 — Layer-row "events" pluralisation inconsistency

- **File:** `src/bulwark/dashboard/static/src/data.jsx:11-14` (LAYERS array `events: 'events' | 'checks'`); `page-shield.jsx:191` renders `{layer.events}` verbatim under the per-layer count.
- **Category:** INCONSISTENT
- **Severity:** MINOR
- **Claim:** Sanitizer, Detection, Boundary tiles say "events"; Canary tile says "checks".
- **Reality:** All four go through the same `events` array of `BulwarkEvent` records (`events.py:33`). The "checks" word implies a different mechanism — there isn't one.
- **Recommended fix:** Pick one term ("events" — what the column actually is) and use it for all four. Drop the per-layer `events` field from LAYERS.

---

### F13 — Empty state copy ("Your pipeline is running") is confidently false in the no-detectors case

- **File:** `src/bulwark/dashboard/static/src/page-events.jsx:165-166`
- **Category:** WRONG
- **Severity:** IMPORTANT
- **Claim:** `"Your pipeline is running. Requests to /v1/clean will appear here."`
- **Reality:** Same problem as F2 — under ADR-040, the pipeline may be returning 503 to every request (no detectors loaded, judge disabled, env-flag off). The empty state then truthfully shows zero events but lies about *why*. A developer's first-five-minutes experience is them seeing "your pipeline is running" while their probe requests are all 503ing.
- **Recommended fix:** Read the same `detectorStatus` + `judge` state used by F2's improved status pill and branch the empty-state message: `"No detectors loaded. /v1/clean is returning 503 — see ADR-040 / Configure page."` versus the current message.

---

### F14 — Configure-page header copy doesn't mention the Phase H decode-rescan stage in the trace

- **File:** `src/bulwark/dashboard/static/src/page-configure.jsx:21-24`
- **Category:** INCOMPLETE
- **Severity:** MINOR
- **Claim:** `"Untrusted content flows top to bottom through the pipeline, then is returned to the caller."`
- **Reality:** Per `api_v1.py:188-199` + ADR-047, between sanitizer and detector chain, `/v1/clean` builds a list of **decoded variants** (ROT13 always-on, base64 opt-in) and runs each detector once per variant. This is a visible architectural change — operators see `decoded_variants[]` in `/v1/clean` responses and `variant=…` annotations in the Events trace pane — but the Configure page's pipeline visualisation is silent on it. The flow visualization (`STAGES` array, lines 38-44) shows 5 stages with no indication that the detection stage fans out across decoded variants.
- **Recommended fix:** Add a single line to the header copy or to the Sanitizer pane: `"After sanitization, content is decoded (ROT13 always; base64 if opted in) and each detector runs across all variants."` Optionally wire the Sanitizer-pane base64 sub-toggle copy (already accurate at line 236) into a tooltip on the detection stage so the fan-out is discoverable.

---

### F15 — `LayerRow.events` count uses `Date.now() - e.ts < 24*3600*1000` but tile label says "events" (no time window)

- **File:** `src/bulwark/dashboard/static/src/page-shield.jsx:171, :191`
- **Category:** INCONSISTENT
- **Severity:** MINOR
- **Claim:** Right-side count column on each layer row shows a number with the label "events" / "checks" — implying total or all-time.
- **Reality:** Line 171 explicitly filters to `Date.now() - e.ts < 24*3600*1000` — last 24h only. The label is misleading.
- **Recommended fix:** Append the window: `events 24h` / `events / 24h`.

---

### F16 — `page-shield.jsx:42` "Active defense — N attacks blocked" counts the last 30m but the label is undated

- **File:** `src/bulwark/dashboard/static/src/page-shield.jsx:42`
- **Category:** MINOR / INCONSISTENT
- **Severity:** MINOR
- **Claim:** Banner: `"Active defense — N attack(s) blocked"`. Adjacent text correctly says "in last 30m" (line 32).
- **Reality:** The banner text and the line above use the same number but only the line above mentions the time window, so the banner alone reads as a cumulative count.
- **Recommended fix:** `"Active defense — N attack(s) blocked in last 30m"` (move the timeframe into the banner).

---

### F17 — `page-leak-detection.jsx:39-41` claim guard patterns must be edited via YAML; the same store has live add/remove for canaries

- **File:** `src/bulwark/dashboard/static/src/page-leak-detection.jsx:39-41`
- **Category:** STALE / IA-GAP
- **Severity:** MINOR
- **Claim:** `"Edit via bulwark-config.yaml."`
- **Reality:** Patterns *are* served by `/api/config` (line 154 in `data.jsx`) and persisted by `_putConfig`. Canaries on the same page have full add/remove UI. There's no UI for adding guard patterns even though the storage is the same. Telling users to edit the YAML when canaries are live-editable is an IA inconsistency, not a hard error — but it makes the page feel half-finished.
- **Recommended fix:** Either (a) add an inline "+ Add pattern" form analogous to `addCanary`, or (b) acknowledge the asymmetry: `"Defined in bulwark-config.yaml. Edit-from-UI tracked under ADR-XXX."` with a real ADR pinning the deferral.

---

### F18 — `page-test.jsx:296` tier card label "probes" is correct for Garak tiers but wrong for the False Positives tier

- **File:** `src/bulwark/dashboard/static/src/page-test.jsx:294-296`
- **Category:** WRONG
- **Severity:** MINOR
- **Claim:** Every tier card renders the unit as `"probes"`. Including the False Positives tier (`falsepos` id, `app.py:780`).
- **Reality:** The False Positives tier ships *benign emails* through `/v1/clean` (ADR-036). Calling them "probes" is a category error — a probe is by definition an attack. The backend `_falsepos_tier_entries` returns `probe_count: len(corpus)` to fit the existing schema, but operators reading the dashboard see "N probes" against a tier whose whole point is that it's NOT probes.
- **Recommended fix:** Branch the unit label on tier id. For `falsepos` show "samples" or "benign emails"; for the others keep "probes". Alternatively keep "probes" for schema consistency but extend the description for the falsepos tier (which is already custom-templated in `app.py:783` so this is doable backend-side).

---

### F19 — `page-test.jsx:91` "No presets in this category" never fires for the canary or detection families

- **File:** `src/bulwark/dashboard/static/src/page-test.jsx:91`
- **Category:** IA-GAP (consequence of F4)
- **Severity:** MINOR
- **Claim:** Empty state when `category` filter matches nothing: `"No presets in this category."`
- **Reality:** Because the category buttons are hard-coded to `[all, sanitizer, boundary, bridge]`, the user can never select `detection` or `canary`. So the empty-state branch only ever fires when *zero* presets ship under one of the four exposed categories — which today is never (8 presets across `sanitizer`, `boundary`, `bridge`). Useful empty state, unreachable in practice.
- **Recommended fix:** See F4 — wire all 5 family filters and the empty state becomes meaningful.

---

### F20 — Configure-page "Latency" badges are static literals, not measurements

- **File:** `src/bulwark/dashboard/static/src/page-configure.jsx:39-43, :281`
- **Category:** STALE
- **Severity:** MINOR
- **Claim:** `tag: '<1ms'` (sanitizer), `'~30ms'` (DeBERTa), `'~50ms'` (PromptGuard), `'~1–3s'` (judge), `'Output formatter'` (boundary). DetailHeader also displays `meta.latency` from a hardcoded dict.
- **Reality:** These numbers came from the v2.0 spec and never update. The dashboard already renders real per-event durations in the trace and the events page. The Configure cards display stale figures while the live data is right there.
- **Recommended fix:** Either (a) keep the static numbers but mark them as nominal: `'~30ms (typical)'` — same shape, more honest; or (b) compute the running median latency for each detector from `store.events.filter(e => e.layer === 'detection' && e.detection_model === 'protectai')` and display that. (a) is the lower-effort win.

---

## Restructural recommendations

### R1 — Eliminate the v1 vocabulary residue in one PR

There's an internally consistent v2 vocabulary (`sanitizer / detection / boundary / canary` + ADR-047 decode variants + ADR-033 judge) and a stale v1 vocabulary (`bridge / analyze / execute / executor / Phase 1 / Phase 2 / LLM backend`). The latter is dead but still scattered across `page-test.jsx` (filter button, trace mapping, prose), `primitives.jsx` (icons), `data.jsx` (comment), and `spec/presets.yaml` (two preset families). One sweep that deletes every v1 token and adds a CI grep for them (similar to the existing `tests/test_spec_compliance.py` style) would prevent regressions. **Findings F1, F4, F5 are all instances of this.**

### R2 — Fold detector-status & ADR-040/041 awareness into a single pure helper

`computeStatusPill` (shell.jsx) is the only piece of code that maps backend reality to a top-level UI signal. It currently keys only on `detectorStatus.protectai.status` and the layerConfig toggle counts. The system has at least four orthogonal failure modes the user should see: `(a) no detectors loaded + judge off → 503`, `(b) degraded-explicit opt-in mode`, `(c) detector loading`, `(d) detector error`. F2 and F13 are both consequences of `computeStatusPill` being too narrow. Promote it to a small state machine that returns `{kind, label, detail}` covering all four; then the empty-state copy in `page-events.jsx`, the layer descriptions in `page-shield.jsx`, and the pipeline visualisation in `page-configure.jsx` can all read from the same source of truth.

### R3 — Codify the screenshot/JSX coupling

`docs/images/*.png` were last updated Apr 23; multiple JSX files have changed since (notably `page-configure.jsx` on Apr 30 added a new toggle that the screenshot can't show). The shipped CLAUDE.md "Versioning" section says minor bumps follow major features — Phase H (v2.5.4–v2.5.9) was a major feature with visible UI but no screenshot refresh. Either: (a) add a release-checklist item to the `document-release` skill that prompts for screenshot review when JSX changed since the last `docs/images/` mtime, or (b) make the README screenshot section conditional on whether the image is younger than the JSX it depicts (e.g. a CI step that warns "shield.png is older than page-shield.jsx, please re-shoot"). **F10 is the symptom; without coupling enforcement it'll keep happening.**

### R4 — Move per-stage latency / model-size badges from JSX literals to `/api/integrations`

Today the model name, latency hint, and size are duplicated in three places: `dashboard/config.py:34-60` (`AVAILABLE_INTEGRATIONS`), `pipeline.py` defaults, and `page-configure.jsx:252-263` (the `meta` dict). Per CLAUDE.md "no hardcoding, pull from tokens, config, or API" — the JSX should consume `/api/integrations` and render whatever the backend reports. This decouples copy refreshes from JSX edits and removes F6 / F20 from ever recurring.

---

## Summary stats

- **Findings:** 20
  - **CRITICAL:** 2 (F1 stale "LLM backend" prose; F2 status pill blind to no-detectors / degraded-explicit)
  - **IMPORTANT:** 6 (F3 unwired search button; F4 stale `bridge` filter / mapping; F8 hardcoded probe count; F10 stale screenshots; F13 empty-state lies under no-detectors; F11 "generate payloads" feature claim)
  - **MINOR:** 12 (F5 dead-code icons, F6 510 vs 512 token, F7 5-step comment, F9 sanitizer desc incomplete, F12 events/checks split, F14 decode stage absent from header, F15 layer-row count window, F16 banner timeframe, F17 guard-patterns IA-gap, F18 falsepos "probes" label, F19 unreachable empty state, F20 static latency badges)
- **Restructural recommendations:** 4 (R1 v1 vocabulary sweep; R2 unified status state machine; R3 screenshot/JSX coupling; R4 stage badges from `/api/integrations`)
- **Categories present:** OBSOLETE, MISSING, WRONG, STALE, INCONSISTENT, INCOMPLETE, IA-GAP
- **Highest-leverage fix:** R2 (unified status state machine) — closes F2, F13, and arguably F16 with a single helper. Operators currently get a green "All layers active" pill while the system 503s every request; nothing else on the page tells them otherwise.
