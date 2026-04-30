# Dashboard

The Bulwark dashboard runs at `http://localhost:3000` (Docker default;
source-tree dev uses 3001 — see [`docs/README.md` "Which port am I
on?"](README.md#which-port-am-i-on)) and ships in the same Docker image
as the HTTP API. Five tabs.

## Shield

Live status. Shows the radial defense visualisation, layer activity (sanitizer,
detection, boundary, canary), 24-hour stats, and a recent-activity feed.
"Active defense — N attacks blocked" appears as a banner whenever a block
happened in the last 30 minutes; click **Review ›** to jump to the Events
page filtered to the recent block.

## Events

Live-updating event log. Filter by verdict (passed / blocked / modified),
by layer, or full-text search across detail/source. Each row expands to a
diff pane (for modified events) or a "Replay in Test" button (for blocked
events).

## Configure

Pipeline visualisation, top to bottom:

1. **Sanitizer** — strip hidden chars, steganography, emoji smuggling
2. **DeBERTa (mandatory)** — `protectai/deberta-v3-base-prompt-injection-v2`
3. **PromptGuard (optional)** — Meta mDeBERTa second-opinion detector
4. **LLM Judge (optional)** — opt-in third detector, off by default (ADR-033)
5. **Trust Boundary** — output formatter (XML / markdown / delimiter)

Click any stage to open its settings pane on the right. The Sanitizer
pane toggles emoji-smuggling / bidi-override / NFKC / encoding-resistant
/ base64 decode-rescan sub-options. Detector panes show model name,
latency, size, and an Enable button (PromptGuard / LLM Judge only —
DeBERTa is mandatory). The LLM Judge pane carries a high-latency warning
since enabling it adds 1–3 s per request.

## Leak Detection

Output-side detection. Two cards:

- **Canary tokens** — add tokens by literal value or by shape (aws / bearer /
  password / url / mongo). The token gets generated, stored in
  `bulwark-config.yaml`, and watched by `/v1/guard` on caller LLM output.
- **Guard patterns** — read-only list of regex patterns also applied by
  `/v1/guard`. Edit via `bulwark-config.yaml`.

Neither check runs on `/v1/clean` input — both are output-side only.

## Test

Top half: send a payload through `/v1/clean` and see the live trace step by
step. Pick from the curated attack-preset library (sourced from
`spec/presets.yaml`) or paste your own.

Bottom: red-team scans. Four tier cards:

- **Smoke Test** — 10 probes across core families, verifies the pipeline.
- **Standard Scan** — every active probe pulled from your installed
  garak version, comprehensive defense check. The probe count is
  computed at runtime from `garak.probes.<family>` introspection and
  shown on the tier card.
- **Full Sweep** — every probe including extended payload variants, slowest.
- **False Positives** — sends the curated benign corpus from
  `spec/falsepos_corpus.jsonl` through `/v1/clean` and inverts the metric so
  a low number is bad. Reports save with a `redteam-falsepos-*.json` filename
  and appear in the same Past Reports list as red-team scans.

Past Reports lists every saved scan with a download (JSON) and Retest button
(re-runs only the non-defended probes from the original).

## Auth

With `BULWARK_API_TOKEN` set, every `/api/*` call (reads + mutations)
and every `/v1/clean` from non-loopback callers requires Bearer auth
(ADR-041). With the token unset, reads stay open to any caller and only
mutating methods (POST/PUT/DELETE/PATCH) require a loopback client
(ADR-029). Public dashboards must always set the token.

## Source of truth

UI source: `src/bulwark/dashboard/static/src/*.jsx` — Babel-compiled in the
browser. The store contract is in `data.jsx`; pages are `page-*.jsx`.

The shipped UI is opinionated and minimal. Variants and the ⌘K palette are
intentionally not shipped (NG-UI-SHELL-001/002 in `spec/contracts/dashboard_ui.yaml`).
