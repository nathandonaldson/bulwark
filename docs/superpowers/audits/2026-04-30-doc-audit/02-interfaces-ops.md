# Doc Audit 02 — Interfaces & Operations

Auditor slice: `docs/README.md`, `docs/cli.md`, `docs/dashboard.md`, `docs/config.md`, `docs/api-reference.md`, `docs/batch.md` cross-referenced against the source-of-truth code in `src/bulwark/cli.py`, `src/bulwark/dashboard/{app.py, api_v1.py, config.py, models.py}`, `spec/openapi.yaml`, `spec/contracts/{clean.yaml, env_config.yaml}`, and ADRs 029, 038, 040, 041, 042.

---

## CRITICAL findings

### F-01 — `/v1/clean` content cap claim contradicts the actual byte limit

- **File:** `/Users/musicmac/Documents/bulwark-shield/docs/api-reference.md:49`
- **Category:** WRONG
- **Severity:** CRITICAL
- **Claim:** Request-shape table row says `content` is `Up to 1 MB. The untrusted payload.`
- **Reality:** ADR-042 + `src/bulwark/dashboard/models.py:46-90` cap content at 262 144 bytes (256 KiB) of UTF-8, with HTTP 413 `content_too_large` over the cap. The doc's own 413 section (line 100) and env-var table (line 157) both correctly say 256 KiB / 262 144. The shape table is inconsistent with itself and with the implementation.
- **Recommended fix:** Change to `Up to 262144 bytes (256 KiB) of UTF-8. Tunable via BULWARK_MAX_CONTENT_SIZE. Over-cap → 413.`

### F-02 — `bulwark canary-check` example will fail at runtime (.yaml file path)

- **File:** `/Users/musicmac/Documents/bulwark-shield/docs/cli.md:86`
- **Category:** WRONG
- **Severity:** CRITICAL (the example, copied verbatim, errors out)
- **Claim:** `echo "output text" | bulwark canary-check --tokens canaries.yaml`
- **Reality:** `CanarySystem.from_file` (`src/bulwark/canary.py:191-193`) calls `json.loads(...)`. A `.yaml` file is not parsed as YAML; the call raises `json.JSONDecodeError`. The CLI option help string `--tokens` itself says "Path to canary tokens JSON file" (`src/bulwark/cli.py:54`).
- **Recommended fix:** Use `canaries.json` in the example, and align the surrounding `bulwark canary-generate` description (see F-04) to drop the YAML claim.

---

## IMPORTANT findings

### F-03 — Dashboard URL stated as `localhost:3001` while default port is 3000

- **File:** `/Users/musicmac/Documents/bulwark-shield/docs/dashboard.md:3`, `/Users/musicmac/Documents/bulwark-shield/docs/api-reference.md:13`, `/Users/musicmac/Documents/bulwark-shield/docs/batch.md:20`, `/Users/musicmac/Documents/bulwark-shield/docs/config.md:119`
- **Category:** INCONSISTENT
- **Severity:** IMPORTANT
- **Claim:** Multiple docs use `http://localhost:3001` as the canonical base URL.
- **Reality:** `src/bulwark/dashboard/__main__.py:111` defaults to port **3000**, the published Docker image binds 3000 (`docs/README.md:6`, `docs/config.md:101-102`), and the `bulwark canary` CLI defaults to `http://localhost:3000` (`src/bulwark/cli.py:395`). 3001 is the dev-only port reserved per CLAUDE.md.
- **Note:** `spec/openapi.yaml:22` declares `http://localhost:3000` as the canonical server URL.
- **Recommended fix:** Either standardize on 3000 (recommended; matches the Docker image) and add a one-line dev-port note, or call out 3001=dev / 3000=Docker explicitly at the top of every example block. Currently `docs/README.md` says 3000 but the rest say 3001 — pick one.

### F-04 — `bulwark canary-generate` doc claims YAML output; only JSON is supported

- **File:** `/Users/musicmac/Documents/bulwark-shield/docs/cli.md:74`
- **Category:** WRONG
- **Severity:** IMPORTANT
- **Claim:** "Pre-ADR-025 command — generates a YAML/JSON canary file for offline use".
- **Reality:** `CanarySystem.save` (`src/bulwark/canary.py:186-188`) writes JSON only. There is no YAML codepath.
- **Recommended fix:** Drop "YAML/" — say "generates a JSON canary file for offline use".

### F-05 — `docs/cli.md` example writes to `canaries.yaml` but tool emits JSON

- **File:** `/Users/musicmac/Documents/bulwark-shield/docs/cli.md:78`
- **Category:** WRONG
- **Severity:** IMPORTANT
- **Claim:** `bulwark canary-generate user_data --output canaries.yaml --prefix MY-APP`
- **Reality:** Output is JSON regardless of file extension. A user copying this example ends up with a file named `.yaml` containing JSON, then trips on F-02 when feeding it back into `canary-check`.
- **Recommended fix:** Use `--output canaries.json` consistently.

### F-06 — `docs/dashboard.md` Standard Scan probe count claim is misleading

- **File:** `/Users/musicmac/Documents/bulwark-shield/docs/dashboard.md:57`
- **Category:** WRONG
- **Severity:** IMPORTANT
- **Claim:** `**Standard Scan** — every active probe (~3,000), comprehensive defense check.`
- **Reality:** `app.py:_compute_redteam_tiers` (lines 676-794) computes the standard count *dynamically* from the installed garak version — it instantiates each active probe class and sums `len(probe.prompts)`. A specific number is not a stable contract; the audit mention of "~3,000" pins a moving target. The dashboard's own description string (line 750) carefully avoids a number ("All active probes").
- **Recommended fix:** Drop the "~3,000" parenthetical; either match the dashboard description or say "thousands of probes pulled from your installed garak version".

### F-07 — `docs/cli.md` claims `bulwark test --full` runs "all 77 attacks"

- **File:** `/Users/musicmac/Documents/bulwark-shield/docs/cli.md:11`, `/Users/musicmac/Documents/bulwark-shield/docs/cli.md:15`
- **Category:** STALE
- **Severity:** IMPORTANT
- **Claim:** Documentation lines say `# All 77 attacks`. The CLI option help also says it (`src/bulwark/cli.py:182`).
- **Reality:** The number of attacks loaded from `AttackSuite()` is whatever `bulwark/attacks.py` registers; it's a runtime quantity. It's plausible, but the doc has no way of staying truthful as the suite grows. The header rendering at `cli.py:249` already uses a dynamic count (`f"Bulwark Defense Test — Full suite, {total} attacks"`).
- **Recommended fix:** Either change the doc + the option `help=` to "every registered attack" or have the option `help=` interpolate from `len(AttackSuite().attacks)`. (CLI option `help` text is auditor-1 territory — for this audit, just make the doc say "the full attack suite" without a number.)

### F-08 — `docs/dashboard.md` says LLM Judge adds 1–3 s, but `page-configure.jsx` uses Unicode en-dash and the figure is correctly 1–3 s

- **File:** `/Users/musicmac/Documents/bulwark-shield/docs/dashboard.md:35`
- **Category:** N/A (verified — leaving here only because the audit framework asks for every claim's status)
- **Severity:** none — the doc and JSX agree.

(Removing — not a finding. Numbering preserved for clarity.)

### F-09 — `docs/dashboard.md` "click any stage to open its settings pane" maps to a real interaction but Sanitizer pane controls are described as toggles for "emoji-smuggling / bidi-override / NFKC"; verify the `nfkc` toggle wires to `normalize_unicode`

- **File:** `/Users/musicmac/Documents/bulwark-shield/docs/dashboard.md:33-34`
- **Category:** Verified (agrees with `page-configure.jsx:230-247`).
- **Severity:** none.

(Removing — not a finding.)

### F-10 — `docs/api-reference.md` endpoints table omits several public-surface endpoints

- **File:** `/Users/musicmac/Documents/bulwark-shield/docs/api-reference.md:17-31`
- **Category:** MISSING
- **Severity:** IMPORTANT
- **Claim:** The endpoints table lists `/healthz`, `/v1/clean`, `/v1/guard`, `/api/canaries[/{label}]`, `/api/presets`, `/api/redteam/tiers`, `/api/redteam/run`. It says the rest are "dashboard-internal" and references `tests/test_spec_compliance.py::INTERNAL_PATHS`.
- **Reality:** `spec/openapi.yaml` declares **public** contracts for `GET /api/redteam/reports`, `GET /api/redteam/reports/{filename}`, and `POST /api/redteam/retest` (lines 378-469). These are not internal — they're what the dashboard's saved-report download/retest UI uses, and they're contractually frozen. Omitting them from `api-reference.md` makes integrators think they don't exist.
- **Recommended fix:** Add three rows to the endpoints table: `GET /api/redteam/reports`, `GET /api/redteam/reports/{filename}`, `POST /api/redteam/retest`.

### F-11 — `docs/api-reference.md` does not document `/v1/clean` 200 fields `decoded_variants` and `blocked_at_variant`

- **File:** `/Users/musicmac/Documents/bulwark-shield/docs/api-reference.md:55-74`
- **Category:** MISSING
- **Severity:** IMPORTANT
- **Claim:** The 200 response example shows `result, blocked, source, format, content_length, result_length, modified, trace, detector, mode`.
- **Reality:** ADR-047 added `decoded_variants` and `blocked_at_variant` to `CleanResponse` (`models.py:120-134`), and `spec/openapi.yaml:560-603` documents them. The api-reference doc does mention `BULWARK_DECODE_BASE64` in the env-vars table (line 160) but the response shape doesn't surface the new fields. Operators consuming the JSON have no idea these keys are in the contract.
- **Recommended fix:** Add `decoded_variants: [...]` and `blocked_at_variant: null` to the 200 example, plus a one-line table-row each.

### F-12 — `docs/config.md` env-var block mentions BULWARK_DECODE_BASE64 but the file shape config block does not list `decode_base64`

- **File:** `/Users/musicmac/Documents/bulwark-shield/docs/config.md:51-92`
- **Category:** MISSING
- **Severity:** IMPORTANT
- **Claim:** `bulwark-config.yaml` example shows pipeline layers: `sanitizer_enabled`, `trust_boundary_enabled`, `canary_enabled`, `encoding_resistant`, `strip_emoji_smuggling`, `strip_bidi`, `normalize_unicode`.
- **Reality:** `BulwarkConfig` (`config.py:106-138`) also exposes `decode_base64: bool = False` and `_apply_env_vars` reads it from the env. Operators using YAML-only config can set it through the file too; the doc hides this.
- **Recommended fix:** Add `decode_base64: false  # ADR-047 — opt-in base64 rescan; ROT13 always on` under the pipeline-layers section.

### F-13 — `docs/api-reference.md` Detector configuration block omits `api_key` and `mode`

- **File:** `/Users/musicmac/Documents/bulwark-shield/docs/api-reference.md:181-196`
- **Category:** INCONSISTENT
- **Severity:** IMPORTANT
- **Claim:** The judge_backend example in api-reference.md lists `enabled, mode, base_url, model, threshold, fail_open, timeout_s`.
- **Reality:** `JudgeBackendConfig` (`config.py:94-103`) also has an `api_key: str = ""` field, returned masked from `/api/config`. The `docs/config.md` example correctly includes it; api-reference.md silently drops it. Operators reading only api-reference.md won't realise they can/should set it.
- **Recommended fix:** Add `api_key: ""              # optional for local LM Studio / Ollama` between `mode` and `base_url`.

### F-14 — `docs/dashboard.md` says auth covers `/api/*` reads; this is wrong when the token is unset

- **File:** `/Users/musicmac/Documents/bulwark-shield/docs/dashboard.md:69-73`
- **Category:** WRONG
- **Severity:** IMPORTANT
- **Claim:** "Set `BULWARK_API_TOKEN` to require Bearer auth on mutating endpoints (POST/PUT/DELETE) and on the dashboard's `/api/*` reads. With the token unset, mutations require a loopback client (ADR-029)".
- **Reality:** ADR-029 (`spec/decisions/029-loopback-only-mutations-when-token-unset.md` §"What this is NOT") is explicit: "Not applied to reads. `GET /api/config`, `GET /api/events`, `GET /api/metrics` still succeed from remote clients without a token." The middleware behaviour at `app.py:131-144` confirms: when token is unset, only mutating methods are gated; reads pass through. The dashboard.md sentence implies reads are also gated when token is set — that part is true — but the ADR-029 framing then misleads the reader by suggesting reads are gated whenever auth is "on."
- **Recommended fix:** Reword to: "With token set: Bearer required on every `/api/*` call (reads + mutations) and on `/v1/clean` from non-loopback (ADR-041). With token unset: reads are open to any caller; only mutating methods (POST/PUT/DELETE/PATCH) require a loopback client (ADR-029)."

### F-15 — `docs/api-reference.md` "Errors" lists 403 as "Token unset, remote client tried to mutate" but the response body shape isn't documented

- **File:** `/Users/musicmac/Documents/bulwark-shield/docs/api-reference.md:212-218`
- **Category:** MISSING
- **Severity:** MINOR (data is in app.py:136-143 but consumers might want to know shape)
- **Recommended fix:** Note that 403 returns `{"error": "Mutating endpoints require BULWARK_API_TOKEN..."}` (string error, not the structured envelope used by 413/503).

### F-16 — `docs/dashboard.md` describes "Replay in Test" button on blocked events; `page-events.jsx` only declares the dispatch on the receiving end

- **File:** `/Users/musicmac/Documents/bulwark-shield/docs/dashboard.md:18-20`
- **Category:** Verified — `page-test.jsx:10` has the comment `Events page's "Replay in Test" dispatches bulwark:goto with {payload}.`
- **Severity:** none.

(Removing — not a finding.)

### F-17 — `docs/cli.md` "bulwark canary" subgroup auth note conflicts with code about who attaches the token

- **File:** `/Users/musicmac/Documents/bulwark-shield/docs/cli.md:45`
- **Category:** Verified — `_canary_client` (`cli.py:378-391`) reads `BULWARK_API_TOKEN` and attaches `Authorization: Bearer`.
- **Severity:** none.

(Removing — not a finding.)

### F-18 — `docs/cli.md` `bulwark wrap` flag section omits `--max-length` though it's not actually a flag for `wrap`; verify

- **File:** `/Users/musicmac/Documents/bulwark-shield/docs/cli.md:41`
- **Category:** Verified — `wrap()` in `cli.py:82-95` has only `--source`, `--label`, `--format`. Doc is correct.
- **Severity:** none.

(Removing — not a finding.)

### F-19 — `docs/cli.md` sanitize example uses literal `​` in shell command, which won't expand

- **File:** `/Users/musicmac/Documents/bulwark-shield/docs/cli.md:27`
- **Category:** WRONG
- **Severity:** IMPORTANT (the example, copied verbatim into a default zsh/bash, sends the literal 12-character backslash sequence — not a zero-width char)
- **Claim:** `echo "text with​hidden​chars" | bulwark sanitize --no-html`
- **Reality:** Standard `echo` (and the zsh default) does not interpret `​`. To inject the actual U+200B you'd need `printf` or `echo -e $'...'` or `python -c`. The intent of the example — show a hidden zero-width char being stripped — fails silently for the user.
- **Recommended fix:** Use `printf 'text with​hidden​chars' | bulwark sanitize --no-html` (printf interprets `\u`) or `python -c 'print("text with​hidden​chars")' | bulwark sanitize --no-html`. Also note that this example has `--no-html` which **disables** HTML stripping — irrelevant to the zero-width point. Drop the flag.

### F-20 — `docs/api-reference.md` describes `detector` 200-response field but doesn't note label values

- **File:** `/Users/musicmac/Documents/bulwark-shield/docs/api-reference.md:71`
- **Category:** MISSING
- **Severity:** MINOR (downgraded — moved to MINOR section below)

---

## MINOR findings

### F-M1 — `docs/api-reference.md` calls the package CLI commands `bulwark_bench` and `bulwark_falsepos` (underscores) — fine for `python -m`, but PyPI-installed scripts use hyphens

- **File:** `/Users/musicmac/Documents/bulwark-shield/docs/cli.md:91-117`
- **Category:** INCONSISTENT
- **Severity:** MINOR
- **Reality:** `pyproject.toml:48-51` defines entry points `bulwark`, `bulwark-bench`, `bulwark-falsepos` (hyphens). The doc shows only the `python3 -m bulwark_bench` / `python3 -m bulwark_falsepos` form, which is correct as a module invocation but doesn't tell users the installed script names.
- **Recommended fix:** Add a one-line note showing the post-install entry points: `bulwark-bench --configs ...` is equivalent to `python -m bulwark_bench ...`.

### F-M2 — `docs/api-reference.md` "Endpoints" table mixes shapes; `/api/redteam/run` is documented but not the matching `/api/redteam/status` and `/api/redteam/stop`

- **File:** `/Users/musicmac/Documents/bulwark-shield/docs/api-reference.md:25-27`
- **Category:** MISSING
- **Severity:** MINOR (these are not in `spec/openapi.yaml` — so by the spec compliance contract they're internal — but the Test page uses them and the table already includes the sibling `/api/redteam/run`)
- **Recommended fix:** Either add a footnote pointing to `/api/redteam/status` + `/api/redteam/stop` for poll/cancel, or remove `/api/redteam/run` from the public table to match the spec scope.

### F-M3 — `docs/api-reference.md` 200 example trace shows `"detection:protectai"` but real responses also emit `detection_model`, `duration_ms`, `max_score`, `n_windows`

- **File:** `/Users/musicmac/Documents/bulwark-shield/docs/api-reference.md:66-69`
- **Category:** MISSING
- **Severity:** MINOR
- **Reality:** `api_v1.py:286-296` adds `detection_model`, `duration_ms`, `max_score`, `n_windows` to per-detector trace entries. Useful for operators reading the trace.
- **Recommended fix:** Add `"detection_model": "protectai", "duration_ms": 28.5, "max_score": 0.0021` to the second trace row.

### F-M4 — `docs/dashboard.md` calls the Sanitizer "stage 1" of "five stages" but the running list shows the right five — verify count

- **File:** `/Users/musicmac/Documents/bulwark-shield/docs/dashboard.md:23-29`
- **Category:** Verified — `page-configure.jsx:39-44` has exactly five `STAGES` entries.
- **Severity:** none.

(Removing — not a finding.)

### F-M5 — `docs/api-reference.md` "Configuration" → "Detector configuration" YAML example sets `judge_backend.mode: openai_compatible` but elides `# or "anthropic"` comment; no impact, just less helpful

- **File:** `/Users/musicmac/Documents/bulwark-shield/docs/api-reference.md:189`
- **Category:** MINOR cosmetic
- **Severity:** MINOR
- **Recommended fix:** Mirror docs/config.md:85 — `mode: openai_compatible      # or "anthropic"`.

### F-M6 — `docs/README.md` index links a "Detectors" doc; verify it exists

- **File:** `/Users/musicmac/Documents/bulwark-shield/docs/README.md:15`
- **Category:** Verified — `docs/detection.md` exists. (Auditor 3 owns content.)
- **Severity:** none.

### F-M7 — `docs/README.md` references `../ROADMAP.md`

- **File:** `/Users/musicmac/Documents/bulwark-shield/docs/README.md:24`
- **Category:** Verified — `/Users/musicmac/Documents/bulwark-shield/ROADMAP.md` exists.
- **Severity:** none.

### F-M8 — `docs/api-reference.md` env-var table lists `BULWARK_ALLOWED_HOSTS` but no link to ADR/contract

- **File:** `/Users/musicmac/Documents/bulwark-shield/docs/api-reference.md:156`
- **Category:** MINOR
- **Severity:** MINOR
- **Recommended fix:** Append `(G-ENV-009 / ADR-015)` to match the citation style of the other rows.

### F-M9 — `docs/dashboard.md` Source-of-truth pointer says `data.jsx` carries the "store contract"; verify

- **File:** `/Users/musicmac/Documents/bulwark-shield/docs/dashboard.md:77-78`
- **Category:** Verified — `data.jsx` is in `src/bulwark/dashboard/static/src/`.
- **Severity:** none.

### F-M10 — `docs/api-reference.md` 503 error code list says only `no_detectors_loaded`; OpenAPI matches

- **File:** `/Users/musicmac/Documents/bulwark-shield/docs/api-reference.md:218`
- **Category:** Verified — `spec/openapi.yaml:140-141` enum is `["no_detectors_loaded"]`.
- **Severity:** none.

### F-M11 — `docs/api-reference.md` `BULWARK_ALLOW_SANITIZE_ONLY` description says "lets `/healthz` report `ok`"; doc says "(with `mode: degraded-explicit`)" but `/healthz` does not return `mode`

- **File:** `/Users/musicmac/Documents/bulwark-shield/docs/api-reference.md:159`
- **Category:** WRONG
- **Severity:** MINOR (operator-facing but `/healthz` returns `status: "ok" | "degraded"`, not a `mode` field)
- **Reality:** `/healthz` in `app.py:230-261` returns `{status, version, docker, auth_required, detectors, [reason]}` — never a `mode` key. The `mode` field belongs to `/v1/clean` 200 responses (`models.py:107-114`). The api-reference table conflates the two.
- **Recommended fix:** Change the row to: `1` lets `/healthz` report `status: "ok"` even with no detectors loaded (instead of `degraded`, ADR-038).

### F-M12 — `docs/config.md` env-var block describes BULWARK_ALLOW_SANITIZE_ONLY semantics but defaults the var to `0`, which it isn't (env vars default to *unset*)

- **File:** `/Users/musicmac/Documents/bulwark-shield/docs/config.md:32`, `/Users/musicmac/Documents/bulwark-shield/docs/config.md:28`, `/Users/musicmac/Documents/bulwark-shield/docs/config.md:39`
- **Category:** WRONG
- **Severity:** MINOR
- **Claim:** Code blocks like `BULWARK_ALLOW_SANITIZE_ONLY=0`, `BULWARK_ALLOW_NO_DETECTORS=0`, `BULWARK_DECODE_BASE64=0` suggest these env vars have a default of `0`.
- **Reality:** `env_truthy` (`config.py:73-80`) returns False for *unset* env vars; the operator only ever sets them to `1` to opt in. Showing `=0` lines invites the reader to actually set them to `0` (which works, but is meaningless noise) and conceals the "leave unset" default.
- **Recommended fix:** Annotate as `# default: unset`, or drop the example assignment and render only as a doc-comment line in the env block.

### F-M13 — `docs/api-reference.md` "Versioning" footer says v1→v2 was ADR-031; sanity-check link

- **File:** `/Users/musicmac/Documents/bulwark-shield/docs/api-reference.md:222`
- **Category:** Verified — `spec/decisions/031-detection-only-pipeline.md` exists (per ADR pattern).
- **Severity:** none.

### F-M14 — `docs/batch.md` "30 RPS on DeBERTa-only" benchmark not anchored to a methodology

- **File:** `/Users/musicmac/Documents/bulwark-shield/docs/batch.md:38-39`
- **Category:** STALE risk
- **Severity:** MINOR
- **Recommended fix:** Either anchor the figure (CPU/GPU, model, batch shape) or convert to "single-process throughput is detector-bound; benchmark on your hardware."

---

## Restructural recommendations

### R-01 — Pick one canonical localhost port and propagate

The split between 3000 (Docker, OpenAPI server URL, CLI default) and 3001 (CLAUDE.md dev port, used everywhere in `/docs`) is the highest-leverage cleanup. Settling on **3000** in `/docs` (with one note "PYTHONPATH=src python -m bulwark.dashboard --port 3001 for source dev") would make every example copy-paste-runnable against the published Docker image and remove F-03 from a half-dozen surfaces at once.

### R-02 — Fold the env-var table into one source

`docs/config.md` env-var block, `docs/api-reference.md` env-var table, and `spec/contracts/env_config.yaml` describe overlapping but non-identical sets:

- `docs/config.md` enumerates: `BULWARK_API_TOKEN`, `BULWARK_WEBHOOK_URL`, `BULWARK_ALLOWED_HOSTS`, `BULWARK_MAX_CONTENT_SIZE`, `BULWARK_ALLOW_NO_DETECTORS`, `BULWARK_ALLOW_SANITIZE_ONLY`, `BULWARK_DECODE_BASE64`.
- `docs/api-reference.md` adds nothing new but words BULWARK_ALLOW_SANITIZE_ONLY differently (F-M11).
- `spec/contracts/env_config.yaml` only enumerates G-ENV-006/009/010/011/014/015 — has the auth + allowlist + dotenv + override semantics but not the `BULWARK_ALLOW_*` family or `BULWARK_DECODE_BASE64`.
- The dashboard runtime additionally honours `BULWARK_DASHBOARD_PORT`, `BULWARK_FALSEPOS_CORPUS`, and `BULWARK_PROJECT_DIR` (`app.py:884, 898, 1099, 1223`) — none documented in any of the three.

Recommendation: extend `spec/contracts/env_config.yaml` to be the single canonical list (it already says "canonical" in `docs/config.md:42`), then have `docs/config.md` and `docs/api-reference.md` link into it instead of duplicating. Surface the three currently-undocumented runtime vars (`BULWARK_DASHBOARD_PORT`, `BULWARK_FALSEPOS_CORPUS`, `BULWARK_PROJECT_DIR`) explicitly — at minimum in api-reference.md.

### R-03 — Move the "Configuration" half of `docs/api-reference.md` into `docs/config.md`

`docs/api-reference.md:147-196` duplicates roughly half of `docs/config.md` (env-var table, file shape, judge config block). Split-source makes drift inevitable; F-13 (`api_key` missing in api-reference) and F-M11 (`BULWARK_ALLOW_SANITIZE_ONLY` worded differently) are both consequences. Strip the Configuration section out of api-reference.md, leave only a one-line link to config.md.

### R-04 — `docs/dashboard.md` should mention port 3000 (default) and reflect ADR-029/041 reads vs writes accurately

Single-paragraph rewrite of the "Auth" section per F-14 to tighten the ADR-029/-041 distinction. The existing copy reads as though `/api/*` reads are gated even when the token is unset — they aren't, and that gap is precisely what ADR-029 documents.

### R-05 — `docs/api-reference.md` 200 response example needs ADR-047 fields (`decoded_variants`, `blocked_at_variant`)

These fields are now part of the response contract (`spec/openapi.yaml:560-603`); leaving them out of the docs hides a debugging-relevant surface. See F-11.

### R-06 — Cross-reference between `docs/cli.md` `canary-generate` (legacy) and `docs/cli.md` `canary` (subgroup) is currently top-down; consider de-emphasising the legacy command

The legacy `bulwark canary-generate` + `bulwark canary-check` flow is a pre-ADR-025 artefact still kept "for scripted pipelines that pre-date the HTTP API" (`docs/cli.md:74`). Given F-02 + F-04 + F-05, the legacy commands are the single largest concentration of doc bugs in this slice. Worth either modernising the snippets to JSON-only (and naming them so) or moving the legacy section to a clearly marked "Pre-ADR-025 commands" appendix.

---

## Summary statistics

- **CRITICAL:** 2 (F-01 wrong byte cap; F-02 canary-check JSON/YAML mismatch)
- **IMPORTANT:** 11 active findings (F-03 port; F-04 YAML claim; F-05 example extension; F-06 probe-count drift; F-07 attack count drift; F-10 missing endpoints; F-11 missing 200 fields; F-12 missing config field; F-13 missing api_key; F-14 auth wording wrong; F-19 echo `​` non-expansion)
- **MINOR:** 8 active findings (F-M1, F-M2, F-M3, F-M5, F-M8, F-M11, F-M12, F-M14)
- **Verified-no-finding entries:** 7 (F-08, F-09, F-15, F-16, F-17, F-18, F-20, F-M4, F-M6, F-M7, F-M9, F-M10, F-M13 — kept inline for reviewer audit trail; will not appear in fix lists)
- **Restructural recommendations:** 6 (R-01 port; R-02 env-var single source; R-03 collapse Configuration; R-04 dashboard auth; R-05 ADR-047 fields; R-06 legacy canary commands)
