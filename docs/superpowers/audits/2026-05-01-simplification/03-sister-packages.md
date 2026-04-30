# Phase 3 Analysis 03: Sister packages (bulwark_bench, bulwark_falsepos)

## Inventory

| Package | Files | LOC (.py) | Public symbols | External deps |
|---------|-------|-----|----------------|---------------|
| `bulwark_bench` | 7 (`__init__`, `__main__`, `bulwark_client`, `configs`, `pricing`, `report`, `runner`) | 961 | `BulwarkClient`, `DetectorConfig`, `PRESETS`, `parse_configs`, `BenchRunner`, `stderr_progress`, `render_json`, `render_markdown`, `Pricing`, `lookup`, `compute_cost`, `__version__="2.0.0"` | `httpx` only (declared as `bulwark-shield[bench]`); stdlib otherwise |
| `bulwark_falsepos` | 6 (`__init__`, `__main__`, `corpus`, `report`, `runner`, no `bulwark_client.py`) | 643 | `CorpusEmail`, `load_corpus`, `categories`, `FalseposRunner`, `stderr_progress`, `render_json`, `render_markdown`, `__version__="1.0.0"` | `httpx` (transitively via bench), `bulwark_bench` itself |
| **Combined** | **13** | **1604** | — | `httpx`, `pyyaml` |

Test surface: `tests/test_bulwark_bench.py` (279 LOC), `tests/test_bulwark_falsepos.py` (326 LOC), `tests/test_falsepos_error_classification.py` (168 LOC) = **773 LOC of tests**.

Spec surface: `spec/contracts/bulwark_bench.yaml`, `spec/contracts/bulwark_falsepos.yaml`, ADR-034, ADR-036, ADR-038 (FP error classification), ADR-035 (LLM-tier removal that broke v1 bench).

PyPI: both packaged into the **single** `bulwark-shield` wheel via `pyproject.toml` `[tool.hatch.build.targets.wheel] packages = ["src/bulwark", "src/bulwark_bench", "src/bulwark_falsepos"]`. They are not separate distributions — they ship together. Two console scripts on `$PATH`: `bulwark-bench` and `bulwark-falsepos`. The corpus is `force-include`'d into `bulwark_falsepos/_data/falsepos_corpus.jsonl` so it survives the wheel/Docker (CHANGELOG v2.3.2 patched the bug where it didn't).

## Cross-package edges

**Neither sister imports from `bulwark.*`.** Both talk to the dashboard exclusively over HTTP via `httpx`. They are library-independent of the main package by design (ADR-034 §"Bench client").

**`bulwark_falsepos` hard-imports from `bulwark_bench`** at 5 sites:

| Importer | Imported |
|----------|----------|
| `bulwark_falsepos/__main__.py:11` | `from bulwark_bench.bulwark_client import BulwarkClient` |
| `bulwark_falsepos/__main__.py:12` | `from bulwark_bench.configs import PRESETS, parse_configs` |
| `bulwark_falsepos/runner.py:16` | `from bulwark_bench.configs import DetectorConfig` |
| `tests/test_bulwark_falsepos.py:14` | `from bulwark_bench.configs import parse_configs` |
| `tests/test_falsepos_error_classification.py:35,114` | `from bulwark_bench.configs import DetectorConfig` |

So **falsepos cannot be installed without bench**. Independence test: bench is installable standalone (no upward dep); falsepos is not.

**`bulwark` (main) imports from `bulwark_falsepos`** at 3 sites in `src/bulwark/dashboard/app.py`:

- `app.py:773` — `from bulwark_falsepos.corpus import load_corpus, categories` (inside `_falsepos_tier_entries()`)
- `app.py:907` — `files("bulwark_falsepos") / "_data" / "falsepos_corpus.jsonl"` (corpus path resolution)
- `app.py:924` — `from bulwark_falsepos.corpus import load_corpus` (inside `_run_falsepos_in_background()`)

The dashboard reuses the `corpus.py` module to load + categorize the JSONL. This is the only `bulwark → bulwark_falsepos` edge; `bulwark → bulwark_bench` has **zero** edges. (One test, `tests/test_llm_judge.py:383`, imports `bulwark_bench.bulwark_client` for HTTP-stub purposes, but that's test-only.)

**Edge graph:**

```
bulwark (main) ──[corpus.py only]──▶ bulwark_falsepos
                                         │
                                         ▼ (hard dep)
                                     bulwark_bench (standalone)
```

## Duplication

Concrete reimplementations between `runner.py` files (bench 253 LOC vs falsepos 302 LOC):

| Concern | bench/runner.py | falsepos/runner.py | LOC dup |
|---------|----------------:|-------------------:|--------:|
| `_safe_id(s)` regex helper | 18-19 | 20-21 | ~3 |
| `_persist()` write-tmp-replace | 30-37 | 28-34 | ~10 |
| `_snapshot()` (read promptguard + judge) | 75-88 | 72-84 | ~16 |
| `_restore()` (write promptguard + judge) | 90-114 | 86-108 | ~25 |
| `_run_one*` orchestration shell (event, ensure_idle, apply_config, settle 0.3s, try/except, persist) | 116-185 | 172-245 | ~25 |
| `stderr_progress(event)` printer | 230-253 | 279-302 | ~10 |
| **Runner duplication subtotal** | | | **~89 LOC** |

Concrete reimplementations between `__main__.py` files (bench 126 LOC vs falsepos 153 LOC):

| Concern | LOC dup |
|---------|--------:|
| argparse `--configs`, `--bulwark`, `--token`, `--judge-base-url`, `--judge-model`, `--judge-mode`, `--judge-api-key`, `--title`, `--version`, `--resume`, `--output` | ~30 |
| Validation: `parse_configs` errors → exit 2; judge-needs-model precondition; run-dir stamping | ~15 |
| Health-check probe + dashboard print + run/restore wrapper | ~10 |
| **CLI duplication subtotal** | | **~55 LOC** |

Concrete reimplementations between `report.py` files (bench 117 LOC vs falsepos 122 LOC):

| Concern | LOC dup |
|---------|--------:|
| `render_json` shape (`schema`, `generated_at`, `configurations` list) | ~10 |
| `render_markdown` skeleton (title, generated_at line, results table loop, errored block, footer) | ~25 |
| `_fmt_pct` helper | ~8 |
| **Report duplication subtotal** | | **~43 LOC** |

**Dead code:** `bulwark_bench/pricing.py` (95 LOC) is dormant per ADR-034 §"Cost reporting drops out": "the pricing module stays in the repo for reference but is unused." No call site in any `runner.py` / `report.py` / `__main__.py`. Could be deleted today regardless of merge choice.

**Total duplicated LOC across the two packages: ~187 LOC of structural duplication + 95 LOC of dead `pricing.py` = ~282 LOC reducible without changing user-visible behavior.**

## Scenario A: keep as-is

**Pros**
- Spec/contract scaffolding (`spec/contracts/bulwark_bench.yaml`, `spec/contracts/bulwark_falsepos.yaml`) is already organized around these names. ADRs 034, 036, 038 reference them.
- Console scripts `bulwark-bench` / `bulwark-falsepos` are user-facing surface that has been documented (`docs/cli.md`, `docs/red-teaming.md`, README, the project-level `bulwark-bench` Claude skill at `.claude/skills/bulwark-bench/SKILL.md`).
- Independence story: `pip install bulwark-shield[bench]` pulls *just* `httpx`+`pyyaml` (declared explicitly in pyproject) — no FastAPI/uvicorn. Useful for a CI job that runs the bench without needing the dashboard stack installed locally.

**Cons / ongoing cost**
- Both runners reimplement `_snapshot`/`_restore`/`_safe_id`/`_persist` and CLI plumbing. Bug fixes have to land in two files (cf. CHANGELOG v2.3.2: ADR-038's error classification was applied in both `_run_falsepos_in_background` and `bulwark_falsepos.runner` separately).
- The `pricing.py` 95 LOC is dead weight per ADR-034.
- The `bulwark_falsepos → bulwark_bench` dep is real but undocumented. There's no top-level `bulwark-shield[falsepos]` extra; falsepos rides on `[bench]` implicitly because they're packaged together.
- Three top-level packages under `src/` is structural drag for new contributors trying to map the codebase.
- `bulwark.dashboard.app` reaches into `bulwark_falsepos.corpus`, which means the dashboard package is not actually independent of the falsepos package despite the directory layout suggesting otherwise.

## Scenario B: merge into `bulwark.tools.{bench, falsepos}`

Move the trees:

```
src/bulwark_bench/         → src/bulwark/tools/bench/
src/bulwark_falsepos/      → src/bulwark/tools/falsepos/
                              (with shared bits hoisted up)
src/bulwark/tools/_client.py     ← shared BulwarkClient (was bench/bulwark_client.py)
src/bulwark/tools/_configs.py    ← shared DetectorConfig + PRESETS + parse_configs
src/bulwark/tools/_runner_base.py ← shared _safe_id, _persist, _snapshot, _restore, _config_loop_skeleton
src/bulwark/tools/_report.py     ← shared render_json scaffold, _fmt_pct
src/bulwark/tools/_cli.py        ← shared argparse base for --configs/--bulwark/--token/--judge-*
```

**LOC delta**

- Delete `pricing.py`: **−95 LOC** (already dead).
- Hoist `_safe_id`/`_persist`/`_snapshot`/`_restore`/CLI base/`render_json` scaffolding/`_fmt_pct` to shared modules: **−180..200 LOC** net (one copy survives instead of two).
- Add ~30 LOC of thin shims to keep `bulwark_bench` / `bulwark_falsepos` import paths working as deprecated aliases for one release cycle (so existing scripts and `from bulwark_bench.bulwark_client import BulwarkClient` in `tests/test_llm_judge.py` keep passing).
- **Net: ~−250 LOC** in `src/`. Tests likely shrink ~20 LOC by reusing fixtures.

**What breaks**

| Surface | Break? | Mitigation |
|---------|:------:|-----------|
| `pip install bulwark-shield` (single wheel) | No | Same wheel still ships everything. |
| Console script `bulwark-bench` | No (if entry point points to new path: `bulwark.tools.bench.__main__:main`) | One-line `pyproject.toml` change. |
| Console script `bulwark-falsepos` | No | Same. |
| `python -m bulwark_bench` | **Yes** unless aliased | Add `src/bulwark_bench/__init__.py` re-export shim or accept the break and bump major. |
| `python -m bulwark_falsepos` | **Yes** unless aliased | Same — shim or bump. |
| `from bulwark_bench.bulwark_client import BulwarkClient` (tests) | Yes unless aliased | Update 1 test file (`tests/test_llm_judge.py:383`) and the falsepos sources/tests that import bench symbols (5 sites). |
| `pyproject.toml` `[tool.hatch.build.targets.wheel] packages` | Yes (drop two entries, the third still covers `src/bulwark`) | One-line edit. |
| Wheel `force-include` for `falsepos_corpus.jsonl` | Yes (path becomes `bulwark/tools/falsepos/_data/...`) | One-line edit; `app.py:907` resource lookup updates too. |
| Spec contracts `bulwark_bench.yaml` / `bulwark_falsepos.yaml` `module:` field | Cosmetic | Update `module:` strings. Guarantee IDs (`G-BENCH-*`, `G-FP-*`) stay stable. |
| Docs (`docs/cli.md`, `docs/red-teaming.md`, README, ADR-034/036, CHANGELOG, the `bulwark-bench` Claude skill) | Wording change only | Search/replace on `python3 -m bulwark_bench` → preferred form. |
| Claude skill `.claude/skills/bulwark-bench/SKILL.md` | Yes if it shells out to the module path | Update to use the entry-point script `bulwark-bench` (already preferred per audit F-M1). |
| External users with their own scripts using `python -m bulwark_bench …` | Yes (without shim) | Recommend keeping a 30-LOC re-export shim and a deprecation note for one minor. |

**Migration steps (read-only sketch)**

1. Move files to `src/bulwark/tools/{bench,falsepos}/`. Add `src/bulwark/tools/__init__.py`.
2. Hoist `bulwark_client.py` + the dup helpers into `src/bulwark/tools/_client.py` and `_runner_base.py`. Both runners import from there.
3. Delete `src/bulwark_bench/pricing.py` (ADR-034 sanctions removal).
4. Update `pyproject.toml`: remove the two extra `packages` entries; update the `force-include` path; update both `[project.scripts]` entry points to `bulwark.tools.bench.__main__:main` / `bulwark.tools.falsepos.__main__:main`.
5. Update `app.py` 3 import sites + the `importlib.resources.files("bulwark_falsepos")` call.
6. Add deprecation shim `src/bulwark_bench/__init__.py` and `src/bulwark_falsepos/__init__.py` that re-export from the new location, raise a `DeprecationWarning`, and keep `python -m` working.
7. Update tests (5–6 import lines).
8. Append an ADR-NNN: "Collapse sister packages into `bulwark.tools.*`".

**Risk grade:** Low. The `bulwark → bulwark_falsepos` edge already exists; merging removes it rather than complicating it. No runtime contract changes — guarantee IDs unchanged.

## Scenario C: spin out into separate repos

Move `bulwark_bench` to its own repo (`bulwark-bench`), `bulwark_falsepos` to another (`bulwark-falsepos`), each published as its own PyPI distribution.

**LOC delta in this repo:** −1,604 LOC src + −773 LOC tests + −95 LOC dead pricing already counted = **~−2,470 LOC** off the main repo. But repo count goes from 1 to 3, and the cross-repo dep `bulwark-falsepos → bulwark-bench` becomes a real PyPI version constraint.

**What breaks**

- `bulwark.dashboard.app` `from bulwark_falsepos.corpus import load_corpus` becomes a runtime dep on a separately-versioned package. Either:
  - Add `bulwark-falsepos` as a runtime dep of `bulwark-shield` (so the dashboard can still surface the False Positives card) — defeats the purpose of spinning out.
  - Or copy `corpus.py` + the JSONL into `src/bulwark/_data/` and have `bulwark-falsepos` *also* read from there as the source of truth — two sources of corpus, version skew between dashboard and CLI.
- Hatch `force-include` of `spec/falsepos_corpus.jsonl` would have to live in two repos, with mirroring, since the dashboard tier card needs it but the CLI also wants it as its bundled default. Source-of-truth drift is the failure mode.
- Spec contracts (`spec/contracts/bulwark_bench.yaml`, `bulwark_falsepos.yaml`) currently sit alongside the implementation; splitting the repos splits the contract. `tests/test_spec_compliance.py` would need to grow cross-repo awareness or be split.
- ADRs 034/035/036/038 reference both packages and the dashboard interplay. They'd no longer live in a single decision log.
- CI becomes 3 pipelines. Release becomes 3 version bumps. The "Patch bump VERSION every commit" rule (CLAUDE.md) gets harder to enforce.
- Existing v2.3.2 fix ("package bulwark_falsepos + bundle corpus into wheel") was specifically about ensuring these ship together with the main wheel for Docker users. Spinning out reverses that fix.
- **No external user is currently importing these packages as libraries** (zero `from bulwark_bench import …` outside this repo's own code, per ADR design — they're CLI/HTTP tools). So there's no external community asking for separate releases.

**Risk grade:** High coordination cost, low payoff. The dashboard ↔ falsepos coupling is real (3 import sites + corpus JSONL bundling) and would either be papered over with a runtime dep (no win) or duplicated (worse).

## Recommendation

**Scenario B — merge into `bulwark.tools.{bench, falsepos}`.**

Argument from data:

1. **Independence story is mostly fictional.** `bulwark_falsepos` already hard-depends on `bulwark_bench` (5 import sites), and `bulwark` already depends on `bulwark_falsepos.corpus` (3 import sites in `dashboard/app.py`). The "three independent packages" arrangement is a directory layout, not a real boundary. They ship together (one wheel), version together (one VERSION file), test together (one tests/ dir), and document together (one CHANGELOG). The `[bench]` extra (`httpx`+`pyyaml`) is the only real install-flexibility argument, and those two deps are already required by `[dashboard]` — no realistic install path actually uses bench without also installing the dashboard.

2. **Concrete duplication is real and growing.** ~187 LOC of `_snapshot`/`_restore`/`_safe_id`/`_persist`/CLI plumbing duplicated, plus 95 LOC of dead `pricing.py`. The CHANGELOG already shows two-place fixes (v2.3.2 ADR-038 had to land in both `_run_falsepos_in_background` and `bulwark_falsepos.runner`). Every future detector-config change is paid for twice.

3. **User-facing breakage is minimal and shimmable.** Console scripts (`bulwark-bench`, `bulwark-falsepos`) are the documented entry points and they don't change. `python -m bulwark_bench` keeps working with a 5-line shim. Spec contracts keep their guarantee IDs.

4. **Spin-out (C) has no constituency.** No external user imports these as libraries; all consumption is via CLI or HTTP. Splitting repos creates corpus-drift risk and triples release overhead for no gain.

**Estimated savings:** ~250 LOC in `src/` (deletes ~282 LOC of dup+dead, adds ~30 LOC of shims), 3 → 1 top-level package under `src/`, single source of truth for the BulwarkClient / preset list / snapshot-restore pattern. One ADR + one minor version bump.

If a smaller first step is preferred: **delete `bulwark_bench/pricing.py`** today as a free −95 LOC cleanup (sanctioned by ADR-034). That alone is risk-free and unblocks nothing, but it shrinks the surface that any future merge has to move.

---

Analysis 03 written: 1604 LOC inventory across 13 files (bench 961 + falsepos 643), ~250 LOC saved if merged (95 dead pricing + ~187 dup runner/CLI/report scaffolding minus ~30 shim LOC), recommendation: B (merge into `bulwark.tools.{bench,falsepos}`).
