# Changelog

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
