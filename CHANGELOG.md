# Changelog

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
