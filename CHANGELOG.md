# Changelog

## [1.3.2] - 2026-04-20

### Added
- **Canary management as a product feature** (ADR-025, G-CANARY-001..011). The Configure page's Canary panel is no longer read-only — it has an inline Add form with a shape picker (aws / bearer / password / url / mongo), a live hint line, and a per-entry Remove button. New HTTP endpoints `GET/POST /api/canaries` and `DELETE /api/canaries/{label}` sit under the dashboard's Bearer-auth middleware. `bulwark.canary_shapes.generate_canary(shape)` produces shape-matching, UUID-tailed canaries; five shapes ship, each uniquely constructed so repeated invocations never collide. `bulwark canary {list, add, remove, generate}` CLI wraps the HTTP API for CI-driven rotation. Deferred (NG-CANARY-001..005): webhook alerting, rotation grace period, overlap detection, encryption at rest.
- **Contracts for the four core defense modules** (ADR-024). `spec/contracts/sanitizer.yaml` (17 G, 4 NG), `isolator.yaml` (12 G, 3 NG), `executor.yaml` (13 G, 3 NG), `validator.yaml` (12 G, 3 NG). Closes the biggest finding from the v1.3.1 SDD audit: ~2,700 lines of tests across the defense pipeline had no `G-*` references, so a silent behaviour regression would have passed CI. Tagging every test class with the guarantee IDs it enforces means `test_every_guarantee_has_test` now enforces coverage both ways for these modules. No test logic was rewritten.
- **Reverse spec-compliance check**. `test_spec_compliance.py::test_app_paths_are_documented_or_allowlisted` asserts every FastAPI route is either in `spec/openapi.yaml` or on an explicit `INTERNAL_PATHS` allowlist. Adding a new app route now forces a conscious public/internal decision. Closes the one-way-enforcement gap the audit flagged as Red.
- **`/api/presets` HTTP-level test**. Guarantees G-PRESETS-005 and G-PRESETS-007 now have smoke-level coverage in `test_http_api.py` so they survive even when `test_presets.py`'s wheel-build integration test is skipped.
- **docker-compose.yml + .env.example**. Bind-mounts `~/.config/bulwark/bulwark-config.yaml` so canaries, guard patterns, and UI edits persist across container recreation. Default `BULWARK_CONFIG_PATH` is overridable.

### Fixed
- **GitHub Actions Tests workflow has been red since v1.3.0**. `bulwark_bench.bulwark_client` imports `httpx` at module level, but the CI install line was only `.[cli]`, which never pulled it in. Three `test_bulwark_bench.py::TestBulwarkClient` cases failed with `ModuleNotFoundError: No module named 'httpx'`. Added a dedicated `bench` optional-dependency group (`httpx`, `pyyaml`) declared separately from the dashboard stack, and updated CI to install `.[cli,bench,dashboard]`. The `dashboard` install also lets FastAPI-gated test suites actually execute in CI instead of silently skipping. All three Python versions (3.11 / 3.12 / 3.13) are green for the first time since v1.3.0.

## [1.3.1] - 2026-04-19

### Fixed
- **Docker image startup crash** (G-PRESETS-007, ADR-023). v1.3.0's new `bulwark.presets` loader walked up from the installed module location to find `spec/presets.yaml`, which works for editable installs but failed in any wheel-installed environment — including the Docker image, where the package lives in `site-packages/` and `spec/` lives at `/app/spec/`. Containers crashed at startup with `FileNotFoundError: spec/presets.yaml not found`. `pip install bulwark-shield` users hit the same crash on any `load_presets()` call. `spec/presets.yaml` is now bundled into the wheel at `bulwark/_data/presets.yaml` via Hatch `force-include`; the loader tries `importlib.resources` first and falls back to the walk-up for editable installs. The source of truth stays in `spec/` per ADR-021 — the wheel copy is a build artifact, not a tracked duplicate. Dockerfile also copies `spec/` during the build so the wheel-build step can see the file.
- **Docker CI smoke test** — replaced the blind `sleep 5` + single curl with a 60s readiness loop that polls `/healthz`, exits early if the container crashes, and dumps container logs on failure. The smoke test now also checks `GET /api/presets` to guard against future packaging regressions. Previously, a container startup crash (the v1.3.0 bug) manifested as a cryptic `JSONDecodeError` on the empty curl output.

### Added
- **ADR-023** — bundle `spec/presets.yaml` into the distribution wheel. Extends ADR-021's source-of-truth stance with a distribution decision.
- **`G-PRESETS-007`** — `load_presets()` resolves the default spec path in both editable and wheel installs; `presets.yaml` contract bumped to v1.1.0.

## [1.3.0] - 2026-04-18

### Added
- **Dashboard redesign — React+Babel-in-browser architecture** (ADR-020). Eight-stage redesign of the entire dashboard UI, shipped as JSX components loaded by `@babel/standalone` at runtime. The approved reference from `bulwark-sentry-design-handoff/` is now the implementation; the mock `BulwarkStore` in `data.jsx` was replaced with real fetches against existing endpoints. SRI-pinned React 18.3.1 + Babel 7.29.0 from unpkg. Tweaks panel and alternate layouts pruned; single opinionated views ship.
  - **Shell** — `computeStatusPill` pure function drives the 4-state top-nav pill (`ok` / `warn` / `bad` / `loading`). Brand version comes from `/healthz`, not hardcoded. `role="status"` + `aria-live="polite"` so screen readers announce state changes. `mode=none` carve-out (G-UI-STATUS-006) so a deliberate sanitize-only choice reads "All layers active" instead of "5 of 7".
  - **Shield page** — RadialShield ring colors switched to `--stage-*` CSS custom properties (no hex literals). `hasRecentIncident(events, now)` predicate drives the amber incident banner with `role="alert"`. Stats tiles + layer rows wired to real `stats24h` / `events` / `sparks`.
  - **Events page** — split empty state (`data-empty-state="no-events"` with "Run a test" CTA vs `data-empty-state="filter-miss"` with "Clear filters"), pure `filterEvents(events, {filter, layerFilter, search})` + `isAnyFilterActive` helpers, row expansion reads real `before`/`after` diffs from `event.metadata` with graceful fallback.
  - **Configure page** — pipeline flow with per-stage token colors, `color-mix()` replacing `${stage.color}22` hex-opacity suffixes. LLM backend pane rearranged into two sections: "Shared by both phases" (Backend + Base URL + API Key) and "Per phase" (PhaseCard blocks with inline MODEL dropdowns). Detection + Canary + Bridge panes wired to real `/api/integrations` / `config.canary_tokens` / `config.guard_patterns` — no random hit counts, no fabricated tokens.
  - **Test page** — `runPipeline()` calls real `POST /v1/clean` and renders the returned trace verbatim; red-team tiers + past reports fetched from `/api/redteam/tiers` + `/api/redteam/reports`; Retest + JSON download buttons wired to real endpoints; `G-REDTEAM-SCORE-007` hijack-cap guard preserved in `ReportRow`.
- **ADR-022 — env vars are editable defaults, not hard locks.** The LLM backend pane renders `ENV` badges + helper lines naming the source env var when `env_overrides` is set, but all fields stay editable. Non-empty UI edits override for the session (backend's G-ENV-012 guard already allowed this — only empty-string updates were skipped). Env restores on dashboard restart. Fixes the earlier UX where users couldn't type into env-shadowed inputs at all.
- **Attack presets source of truth** (ADR-021). New `spec/presets.yaml` + `src/bulwark/presets.py` loader + `GET /api/presets` endpoint. Replaces the inline `const PRESETS` literals that previously lived in two places. Contract: `spec/contracts/presets.yaml` with `G-PRESETS-001..006`.
- **Per-stage CSS color tokens.** `--stage-sanitizer`, `--stage-boundary`, `--stage-detection`, `--stage-analyze`, `--stage-bridge`, `--stage-canary`, `--stage-execute` in `:root`, aliasing semantic palette tokens. Plus `--accent-ink`, `--accent-ink-soft`, `--ink-dim` so the toggle knob + spinner colors no longer inline hex. Global grep confirms zero hex literals remain in any JSX.
- **Shared `activeLayerCount(layerConfig, llmMode)`** helper in `data.jsx`. Replaces duplicate inline counting logic in `shell.jsx` and `page-shield.jsx` so the Shield hero and top pill always agree about "N of 7 layers active", including the mode=none carve-out.
- **Dashboard UI contract** `spec/contracts/dashboard_ui.yaml` (v0.7.0) covering every stage's guarantees: `G-UI-STATUS-*`, `G-UI-INCIDENT-*`, `G-UI-EMPTY-*`, `G-UI-FILTER-*`, `G-UI-EXPAND-*`, `G-UI-TOKENS-*`, `G-UI-SHIELD-*`, `G-UI-NEEDS-*`, `G-UI-CONFIG-*`, `G-UI-TEST-*`, `G-UI-A11Y-*`, plus 13 non-guarantees.

### Fixed
- **Reports list ordering** (G-REDTEAM-REPORTS-002). `/api/redteam/reports` now sorts by `completed_at` descending (with filename + mtime as tie-breakers). Previously used `sorted(..., reverse=True)` on filenames which ranked `redteam-standard-*` ahead of `redteam-full-*` lexically regardless of date — newer full-tier reports sank below older standard-tier ones.
- **Dashboard version string** no longer hardcoded in `shell.jsx`. Sourced from `/healthz` via `store.version`.
- **LLM backend env-lock UX.** Replaced the read-only ghost input with either a proper editable control (new policy from ADR-022) or a read-only `<div>` — the prior state where an `<input>` silently ignored keystrokes is gone.

### Changed
- **Red-team tier cache gets a TTL** (G-REDTEAM-TIERS-007). `_compute_redteam_tiers()` was session-cached forever; now refreshes after `_REDTEAM_TIERS_TTL_S` (600s default). Long-running dashboards pick up upstream garak probe-library growth (34K → 80K probes between 15 Apr and 18 Apr for the Full Sweep) without a restart.
- **`shell.jsx` simplified.** Dropped the `SideNav` + `TabIcon` + `PipelineDiagram` components (only the tweak-panel sidebar variant used them). `page-shield.jsx` drops `ShieldData` + `ShieldHybrid` + `BigSparkline`.

## [1.2.2] - 2026-04-17

### Changed
- **Docker images now published as multi-arch manifests** (`linux/amd64` + `linux/arm64`). CI uses `docker/setup-qemu-action` + `docker/setup-buildx-action` + `docker/build-push-action@v5`. Docker Desktop on Apple Silicon no longer shows the "AMD64" emulation warning when pulling `nathandonaldson/bulwark:latest`; the correct architecture is selected per host automatically. Build caches via GitHub Actions cache so amd64 layers come out of cache after the first run.

## [1.2.1] - 2026-04-17

### Added
- **Project-level `bulwark-bench` skill** (`.claude/skills/bulwark-bench/SKILL.md`). Guides a Claude Code session through a full bench run: discovers models from the configured LM Studio endpoint, asks the user via `AskUserQuestion` to pick up to 5 models + tier + whether to bypass detectors, spawns a subagent to run the sweep (so long standard-tier runs don't block the main conversation), and reports the markdown comparison table verbatim. Handles safety checks (repo detection, dashboard health, venv presence) and common error modes (detector state left disabled on crash, unknown model pricing).

## [1.2.0] - 2026-04-17

### Added
- **Two new red-team tiers curated for LLM benchmarking** (ADR-018):
  - `llm-quick` — 10 probes, 10 distinct attack families, one prompt per class. For fast model comparisons.
  - `llm-suite` — ~200 probes across 16 attack families with per-class prompt caps for balanced coverage. For meaningful LLM efficacy signals.
  - Curation is data-driven: probe classes selected from 47k observations in historical reports (one full + three standard runs). Every selected class had ≥5 historical LLM reaches; families chosen for attack-type spread (latent injection, encoding bypass, divergence, credential extraction, adversarial suffix, markdown exfil, data leakage, jailbreak…).
  - `TIER_CLASS_SELECTORS` introduced alongside `TIER_FAMILIES` so per-class prompt caps are expressible (family-level selection can't prevent one family from dominating the suite).
  - `/api/redteam/tiers` response now includes the new tiers alongside quick/standard/full.
  - Guarantees: G-LLM-TIER-001..005, NG-LLM-TIER-001..002. See `spec/contracts/llm_facing_tiers.yaml`.
- **`bulwark_bench --bypass-detectors`** (G-BENCH-011). Snapshots the integration state, toggles listed detectors (e.g. `protectai,promptguard`) off for the duration of the sweep, restores them on exit — including re-activation so the pipeline actually uses them again. Verified live: pairing `--tier llm-quick --bypass-detectors protectai,promptguard` takes LLM reach from ~40% → 100%.

### Fixed
- **Integration toggle coherence** (G-INTEGRATIONS-001). `PUT /api/integrations/{name}` with `enabled=false` now removes the detector from `_detection_checks` immediately. Previously the config flag could say "disabled" while the pipeline kept running the detector, breaking `--bypass-detectors` and confusing dashboard users.

## [1.1.0] - 2026-04-17

### Added
- **`bulwark_bench` — sibling CLI for LLM model benchmarking.** Sweeps up to N models sequentially against a running Bulwark dashboard, captures efficacy / speed / cost, and emits `report.json` + `report.md`.
  - Model swap via `PUT /api/config`, scan via `POST /api/redteam/run`, polling progress — no new pipeline code (G-BENCH-010).
  - Efficacy = `defense_rate` from the red-team tier (reuses G-REDTEAM-SCORE-001..007).
  - Speed = `duration_s / total` (avg seconds per probe).
  - Cost = `tokens × $/Mtok` from a versioned pricing table; local inference $0.
  - Resumable: each model's result persists to disk immediately; `--resume` skips completed entries (G-BENCH-002/003).
  - Per-family defense rate breakdown in the markdown report when available.
  - Probe-progress events during long sweeps.
  - Warns on quick-tier usage (10 probes mostly get blocked upstream of the LLM — use `--tier standard` for meaningful comparisons).
  - ADR-017, contract `spec/contracts/bulwark_bench.yaml`, 22 new tests.
  - Entry point: `bulwark-bench` (installed script) or `python -m bulwark_bench`.

## [1.0.7] - 2026-04-17

### Fixed
- **Reasoning-model empty-content trap.** `_openai_chat` now raises a clear `RuntimeError` when the remote returns `content: ""`, specifically naming reasoning models (Qwen3, DeepSeek-R1, etc.) and the current `max_tokens` when `reasoning_content` is present. Replaces a silent "0 chars" propagation through the pipeline.
- **`max_tokens` bumped** so reasoning models have headroom: analyze `256 → 2048`, `_openai_chat` default `4096 → 8192` (used by execute).

### Added
- **Wrong-interpreter warning at dashboard startup.** `_warn_if_outside_project_venv` prints a one-time warning if a `.venv/bin/python` exists in cwd but the current interpreter resolves elsewhere. Catches the footgun of running `/usr/bin/python3 -m bulwark.dashboard` when a project venv (with different third-party versions — e.g. garak) is set up. Silent in Docker and when no `.venv` is present.

## [1.0.6] - 2026-04-17

### Fixed
- **Dashboard "Save" no longer clobbers env-provided credentials with empty strings** (G-ENV-012). The UI renders env-shadowed fields as read-only, but `getLLMFormData()` was still packing `api_key: '', base_url: ''` into the PUT body; the backend wrote those blanks to memory, and the very next pipeline request fell back to `https://api.openai.com/v1` with no key → 401 + "Pipeline unreachable" banner.
  - Backend: `update_from_dict` skips empty-string updates to env-shadowed llm_backend fields.
  - Frontend: `getLLMFormData` omits fields whose `<input>` is absent (defense-in-depth).

### Security
- **`save()` no longer persists env-provided credentials to disk** (G-ENV-013). Env-shadowed llm_backend fields are written as empty strings in `bulwark-config.yaml`; `_apply_env_vars` refills them from env on next load. Prevents secrets leaking from `.env` into the config file.

## [1.0.5] - 2026-04-17

### Fixed
- **Local `python -m bulwark.dashboard` now auto-loads `.env` from cwd** (G-ENV-010). Previously the local path ignored `.env` entirely — users who edited it and restarted saw `env_configured: false` and the pipeline silently fell back to `https://api.openai.com/v1` with no key → 401. Zero new dependencies (10-line hand-rolled parser). Existing env vars always win. Docker path is unaffected. See ADR-016.

### Changed
- **`NG-ENV-002` removed, replaced with `G-ENV-011`** (positive guarantee). The old non-guarantee claimed env vars did not override a saved config file; the code and tests had always implemented the opposite. Contract now matches reality: `BULWARK_*` env vars override corresponding fields from `bulwark-config.yaml`.

## [1.0.4] - 2026-04-17

### Added
- **`BULWARK_ALLOWED_HOSTS` env var** — comma-separated opt-in allowlist for the SSRF block, so LAN inference servers (LM Studio, Ollama, vLLM on a workstation) can be targeted without SSH tunnels. Exact-match hostnames/IP literals only (no CIDR, no wildcards). See ADR-015. Guarantees: G-HTTP-LLM-TEST-005, G-ENV-009.

### Security
- **Metadata hosts remain unconditionally blocked** even if listed in `BULWARK_ALLOWED_HOSTS` (defense-in-depth against typos / env-var tampering). G-HTTP-LLM-TEST-006.

## [1.0.3] - 2026-04-17

### Fixed
- **Dashboard defense-rate display no longer rounds up to 100% when hijacks occurred** (G-REDTEAM-SCORE-007). A single hijack in 4268 probes previously displayed as "100%" via `Math.round(99.98)`, giving users a false sense of security. Display now shows `99.98%` (two decimals) whenever the true rate is ≥99% but not perfect, and only shows `100%` when every probe was actually defended.
- Past-reports list endpoint now surfaces `hijacked` so the display guard has the data it needs.

## [1.0.0] - 2026-04-16

### Breaking Changes
- **`/v1/clean` is now the unified defense endpoint** — runs the full stack (sanitize, detect, LLM two-phase, bridge guard, canary). Previously only sanitized and wrapped content.
- **`/v1/pipeline` removed** — all functionality merged into `/v1/clean`. Callers using `/v1/pipeline` must switch to `/v1/clean`.
- **`/v1/clean` returns 422 on injection detection** — previously always returned 200. Callers must handle 422 responses.

### Added
- **Dashboard bearer token auth** — `BULWARK_API_TOKEN` env var protects management endpoints. Core API remains public.
- **Login gate** in dashboard UI with cookie support for SSE.
- **Docker hardening** — multi-stage build (no gcc/rustc in final image), non-root user (`bulwark`).
- **Env vars override config file** — `BULWARK_API_KEY` in `.env` always wins over `bulwark-config.yaml`.
- **Env-controlled fields hidden in UI** — shows "(set via BULWARK_API_KEY)" instead of editable input.
- **Two-tier verdict scoring** — structural analysis check eliminates false positives in red team results.
- **Detection-blocked fallback** respects dashboard layer toggles.
- **Shield page layer cards** reflect live toggle state (green/grey).

### Fixed
- Detection-blocked fallback used `Pipeline.default()` ignoring all toggles.
- Sanitizer appeared in test trace when toggled off (detection-blocked path bug).
- Test Connection and model list fall back to env var API key when field hidden.

### Security
- SSRF validation on OpenAI-compatible execution paths.
- API key masked in `/api/config` responses.
- Defense-disable protection (at least one core layer must stay on).
- XSS escaping on model names from remote endpoints.
- `.env` excluded from Docker image.
- **843 tests** (up from 811).

## [0.6.0] - 2026-04-15

### Added
- **Model dropdowns** — LLM config uses dropdowns with Anthropic short aliases (auto-resolve to latest version) and OpenAI-compatible `/models` fetch. No more broken model IDs.
- **Red team tiers** — Smoke Test (10 probes), Standard Scan (~4k), Full Sweep (~33k). Probe counts pulled dynamically from installed garak version.
- **Three-way scoring** — probe results classified as `defended`, `hijacked`, or `format_failure`. Format failures (LLM analyzed correctly but wrong output schema) no longer counted as vulnerabilities.
- **Retest failures** — `POST /api/redteam/retest` re-runs only failed probes from a previous report. Minutes instead of hours.
- **Report persistence** — red team reports auto-saved to `reports/` as JSON with download links in the dashboard.
- **OpenClaw integration** — Docker sidecar + npm plugin with infrastructure-level hooks (`message:received`, `tool_result_persist`, `before_message_write`). Agent cannot bypass sanitization.
- **Event emission** — `/v1/clean` and `/v1/guard` now emit events to the dashboard EventDB and SSE stream. Closes #8.
- **Smart status pill** — header shows actual pipeline state (green/amber/red) with version number. Updates on config changes.
- **Live LLM status** — Configure tab probes the actual pipeline and shows what's running.
- **OpenClaw docs** — installation guide with copy-paste Claude Code prompt.

### Fixed
- **Model ID** `claude-sonnet-4-5-20241022` (nonexistent) replaced with `claude-sonnet-4-6`.
- **Hardcoded port 3000** in red team/garak emitters — now reads actual running port.
- **LLM mode selector** persists on click (was losing selection on page navigation).
- **garak 0.14 Conversation objects** — red team handles both string and Conversation prompts.
- **Non-dict JSON parsing** crash in `_parse_response` when LLM returns plain numbers.
- **Activity feed** refreshes every 10s from DB as fallback to SSE.

### Security
- **SSRF fix** — `_validate_base_url()` now runs on OpenAI-compatible execution paths, not just test/list.
- **API key masking** — `GET /api/config` returns masked key (first 7 + last 4 chars only).
- **Defense minimum** — `PUT /api/config` rejects disabling all core defense layers simultaneously.
- **XSS fix** — model names from remote `/models` endpoint escaped with `escapeHtml()`.
- **Docker .env exclusion** — `.env` added to `.dockerignore` to prevent API key leaks in images.

### Changed
- **Docker registry** moved from GHCR to Docker Hub (`nathandonaldson/bulwark`).
- **CI workflow** pushes to Docker Hub with `workflow_dispatch` support for manual builds.
- **Red team rate limiting** — delay only applied after probes that hit the LLM, not pre-LLM-blocked probes.
- **Pipeline endpoint** uses app config object instead of reloading from file on every request.
- **807 tests** (up from 746), including security, scoring, tiers, reports, OpenClaw integration.

## [0.5.0] - 2026-04-14

### Added
- **Docker distribution** — `docker run -p 3000:3000 nathandonaldson/bulwark` starts the full dashboard and API with zero config.
- **`/healthz` endpoint** — liveness probe returning version, Docker detection, and env config status.
- **`/v1/llm/test` endpoint** — test LLM backend connectivity from the dashboard with SSRF protection on base_url.
- **CORS middleware** — restricted to localhost origins for browser-based API access without exposing API keys cross-origin.
- **Environment variable config** — `BULWARK_LLM_MODE`, `BULWARK_API_KEY`, `BULWARK_BASE_URL`, `BULWARK_ANALYZE_MODEL`, `BULWARK_EXECUTE_MODEL`. Persistent config for Docker via `.env` file or docker-compose.yml.
- **docker-compose.yml** with `.env` file support for single-command startup.
- **GitHub Actions Docker workflow** — builds image, runs smoke tests, pushes to GHCR on version tags.
- **Contract spec for /v1/llm/test** with SSRF validation guarantees.
- **746 tests** (up from 709), including CORS security, SSRF blocking, env var config, Docker persistence.

### Changed
- **Renamed package** from `bulwark-ai` to `bulwark-shield` on PyPI (`bulwark` was taken).
- **Moved `dashboard/` into `src/bulwark/dashboard/`** so the dashboard ships in the pip wheel. `python -m bulwark.dashboard` replaces `python -m dashboard`.
- **Added missing dependencies** to `[dashboard]` extras: pydantic, pyyaml, httpx, anthropic (previously only pulled transitively).
- **Canary file path** now configurable via `BulwarkConfig.canary_file` instead of hardcoded path.
- **Red team `project_dir`** respects `BULWARK_PROJECT_DIR` env var for Docker compatibility.
- **PromptGuard detection** now catches both INJECTION and JAILBREAK labels (was missing JAILBREAK).
- **Anthropic model defaults** use full IDs with date suffix (`claude-haiku-4-5-20251001`).
- **Docker config warning** only shows when env vars are NOT configured.
- **Dashboard HTML** served with `Cache-Control: no-cache` to prevent stale UI after updates.
- **PyPI publish workflow** changed to manual trigger (workflow_dispatch) so Docker can ship independently.
- **Full ROADMAP.md rewrite** reflecting current state.

## [0.4.1] - 2026-04-14

### Changed
- **Dashboard design polish** from /design-review audit (Design Score: B, AI Slop Score: A).
- Shield page layout restructured: stats and recent activity now align horizontally in their own row.
- Defense layer cards have consistent padding (16px 20px) and 8px spacing, matching stat cards.
- Heading styles normalized: reusable `.config-section-label` class replaces inline overrides.
- Mobile responsive: 640px breakpoint with smaller shield, stacked nav, 2-column stats grid.

## [0.4.0] - 2026-04-14

### Added
- **LLM backend configuration** in the dashboard Configure tab. Three modes: Sanitize Only, Anthropic API, OpenAI Compatible (local inference via Ollama, llama.cpp, vLLM, LM Studio, or cloud OpenAI).
- **`POST /v1/pipeline`** endpoint runs the full defense pipeline including LLM-backed two-phase execution, detection models, and canary checks. Language-agnostic.
- **Detection models run before the LLM** (ProtectAI DeBERTa, PromptGuard-86M). If detection catches injection, the LLM call is skipped entirely.
- **Individual detection model trace entries** with per-model verdicts and timing in the pipeline trace.
- **Auto-load detection models on startup** from saved config. No more re-activating after every restart.
- **Stop button** for red team runs. Cancels after the current probe finishes.
- **Red team uses `/v1/pipeline`** instead of building its own pipeline. Same code path as manual tests and production.
- **CONTRIBUTING.md** documenting the spec-first development process.

### Changed
- Dashboard Test tab now calls `/v1/pipeline` (our public API) instead of the internal `/api/test` endpoint.
- Red team progress text no longer says "through Claude" (uses configured backend).
- Classify `max_tokens` capped at 256 (was 4096). Classification responses are ~50 tokens.
- Lightweight prompt for red team probes on local models (faster, less context).

## [0.3.0] - 2026-04-14

### Added
- **`bulwark.clean()`** — one-liner to sanitize untrusted content and wrap in trust boundary tags. Zero config. Supports XML, markdown, and delimiter boundary formats for different LLM providers.
- **`bulwark.guard()`** — one-liner to check LLM output for injection patterns and canary token leaks. Raises on detection, returns input unchanged if clean.
- **`protect()` for Anthropic SDK** — wrap your client to auto-sanitize user messages and tool_result content blocks. Uses explicit `@property` for `.messages` to handle Anthropic's `cached_property`.
- **HTTP API** — `POST /v1/clean` and `POST /v1/guard` endpoints in the dashboard. Language-agnostic, Pydantic-validated, always 200 for completed analysis.
- **OpenAPI spec** (`spec/openapi.yaml`) — hand-written, language-agnostic API contract. Go/Node/Ruby developers can build clients from the spec.
- **Contract specs** (`spec/contracts/`) — formal guarantees and non-guarantees for clean(), guard(), and both HTTP endpoints. 31 guarantees, 9 non-guarantees.
- **Architecture Decision Records** (`spec/decisions/`) — 7 ADRs recording design rationale (two-phase execution, proxy pattern, clean() defaults, etc.).
- **Spec compliance CI** — meta-tests enforce that every spec path exists in the app, every guarantee has a test, and no duplicate IDs exist.
- **`CanaryLeakError` exported** from top-level `bulwark` package.
- 54 new tests (709 total).

### Changed
- README Quick Start now leads with `bulwark.clean()`, then `guard()`, then `protect()`, then full Pipeline.
- `clean()` defaults to `max_length=None` (no silent truncation). Opt-in truncation only.

## [0.2.2] - 2026-04-13

### Fixed
- **Python 3.13 compatibility** — isolator integration test no longer assumes thread execution order. All 3 Python versions now pass CI.
- **Dashboard auto-sync** — on startup, the dashboard syncs newer files from the repo automatically. No more manual file copying after code changes. Requires a `.source-repo` marker in the runtime directory.

## [0.2.1] - 2026-04-13

### Added
- **ProtectAI DeBERTa detection** as built-in integration. Ungated, 99.99% accuracy, ~30ms. `detect_and_create()` one-liner.
- **PromptGuard-86M support** for when HuggingFace approval is granted.
- **Dashboard Activate button** loads detection models into memory and registers them as bridge checks.
- **Config toggles wired to Test tab** — switching off Sanitizer in Configure actually disables it in testing.

### Changed
- Removed PIGuard, NeMo Guardrails, and Promptfoo from dashboard (PIGuard/NeMo not implemented, Promptfoo moves to CI eval pipeline).
- Configure tab shows only ProtectAI, PromptGuard, and LLM Guard for detection.

### Fixed
- Red team progress survives tab switching (fresh DOM refs on each poll tick).

## [0.2.0] - 2026-04-13

### Added
- **Production red team runner** sends Garak's 315 attack probes through the real Bulwark+Claude pipeline and evaluates results. Quick Test (10 probes) and Full Scan (315 probes) from the dashboard.
- **Red teaming moved to Test tab** with auto-detection of installed tools (greyed out if Garak/Promptfoo not installed).
- **Inline red team report** with defense score, blocked-by-layer breakdown, per-family results, and vulnerability details with recommendations.
- `/api/redteam/run` and `/api/redteam/status` endpoints for background red team execution.

### Changed
- Dashboard configure tab now only shows detection integrations. Red teaming tools live in the Test tab.

### Fixed
- Garak adapter uses `python -m garak` (works when pip-installed, not just CLI).
- Garak adapter uses `--report_prefix` for predictable report file paths.
- Dashboard runs Garak/red team in background (non-blocking, poll for status).
- Claude CLI found by absolute path for launchd services.

## [0.1.0] - 2026-04-13

Initial open source release. Extracted from production defenses in the Wintermute AI agent.

### Added
- **5 defense layers:** Sanitizer, TrustBoundary, TwoPhaseExecutor, CanarySystem, MapReduceIsolator
- **Pipeline** orchestrates all layers with a single `run()` call, async support via `run_async()`
- **77 attack patterns** across 10 categories for built-in red teaming
- **`bulwark test` CLI** with color-coded output, 8 preset attacks, `--full` for all 77
- **Anthropic SDK integration** via `make_pipeline()`, `make_analyze_fn()`, `make_execute_fn()`
- **Garak red teaming integration** with `--garak` and `--garak-import` CLI flags
- **Interactive dashboard** with shield visualization, event stream, config management, and attack test page
- **Pluggable detection** at the bridge layer via `AnalysisGuard.custom_checks`
- **3 quickstart examples:** Anthropic SDK, OpenAI SDK, generic callable
- **Claude Code integration prompt** in README for AI-assisted onboarding
- **Observability** via event emitters (Webhook, Stdout JSON, Callback, Collector, Multi)
- **YAML config** support with `Pipeline.from_config()`
- **619 tests** including security regression tests, type guard tests, integration tests
- **Benchmarks** confirming <1ms latency for deterministic layers
- **GitHub Actions CI** testing across Python 3.11, 3.12, 3.13
- **PyPI publish workflow** triggered by version tags

### Security
- Security audit: 8 fixes (ReDoS, XML injection, SSRF, token entropy, info leak)
- Dashboard binds to localhost by default
- Type guards on all public API entry points
- Pre-compiled regex patterns prevent ReDoS
- `warnings.warn()` on config load failure instead of silent fallback
