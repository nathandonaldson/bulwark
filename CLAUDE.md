# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Bulwark Shield

Prompt injection defense through architecture, not detection. v2 is **detection-only**: the pipeline classifies and either returns sanitized content or raises an error. No LLM generation is exposed through `/v1/clean`. See ADR-031.

## Spec-driven development (MANDATORY)

Every new feature follows this sequence. Complete each step before moving to the next.

1. **Start with the spec.** Update `spec/openapi.yaml` for any new or changed HTTP endpoints.
2. **Write the contract.** Create or update `spec/contracts/*.yaml` with guarantee IDs and non-guarantees.
3. **Record the decision.** Add an ADR in `spec/decisions/NNN-title.md` when making architectural choices.
4. **Write the tests.** Reference guarantee IDs (e.g., `G-HTTP-HEALTHZ-001`). Watch them fail.
5. **Implement.** Make the tests pass.

`tests/test_spec_compliance.py` enforces spec/implementation agreement in CI. Always ask before deciding a change doesn't need spec/contract/tests.

## Architecture

The detection pipeline (`src/bulwark/pipeline.py`) runs five stages in order:

1. **Sanitizer** (`sanitizer.py`) — strips HTML/zero-width/invisible tricks
2. **DeBERTa / ProtectAI** (`integrations/promptguard.py`) — mandatory ML classifier, chunked across 510-token windows with 64-token overlap (ADR-032)
3. **PromptGuard-86M** (`integrations/promptguard.py`) — optional second classifier; already integrated, don't suggest "adding" it
4. **LLM Judge** (`detectors/llm_judge.py`) — optional third detector with high-latency warning (ADR-033). Detection-only: NG-JUDGE-004 forbids returning generative output to `/v1/clean` callers. System prompt is hardcoded in `_SYSTEM_PROMPT` (NG-JUDGE-003).
5. **Trust Boundary** (`trust_boundary.py`) — wraps output in XML/JSON envelope

Both DeBERTa and PromptGuard live in `integrations/promptguard.py` (the file name predates the rename — same loader, two model IDs).

`ADR-029`: mutating endpoints require `BULWARK_API_TOKEN` when accessed from non-loopback clients (Docker bridge IP triggers this).
`ADR-031`: v2 detection-only architecture. /v1/clean classifies and either returns sanitized content or raises an error. No LLM generation through /v1/clean.
`ADR-033`: optional LLM judge as third detector. Detection-only (NG-JUDGE-004 forbids returning generative output). System prompt hardcoded (NG-JUDGE-003). Per-request nonce-delimited markers wrap user input.
`ADR-040`: `/v1/clean` returns HTTP 503 + `error.code = "no_detectors_loaded"` when zero detectors are loaded and judge is disabled. Operators opt into sanitizer-only via `BULWARK_ALLOW_NO_DETECTORS=1` (response carries `mode: "degraded-explicit"`).
`ADR-041`: `/v1/clean` auth predicate keys on token presence + non-loopback origin alone — judge state is no longer load-bearing.
`ADR-042`: `/v1/clean.content` and `/v1/guard.text` are byte-capped (default 256 KiB) via `BULWARK_MAX_CONTENT_SIZE`. Over-cap requests get HTTP 413 + `error.code = "content_too_large"`.
`ADR-044`: `Pipeline.from_config(path)` loads the same detector chain the dashboard uses. The `Pipeline(detect=callable)` constructor was REMOVED in v2.5.0 — pass `detectors=[callable, ...]` instead.
`ADR-046`: long-range split-evasion (≥~50 tokens of benign filler between trigger and instruction) is a documented non-guarantee — the dilution is a model-context limit, not a chunking artefact.
`ADR-047`: `/v1/clean` decodes base64 + ROT13 substrings as detection variants; trust boundary still wraps the original cleaned text. `decode_base64` is opt-in (default off).
`ADR-048`: `bulwark.detector_chain.run_detector_chain` is the single source of truth for chain execution; `Pipeline.run()` and `api_v1.api_clean` both delegate to it. Don't fork.

## Sister packages

- `src/bulwark_bench/` — Detector-config sweep harness (ADR-034). Talks to a running dashboard over HTTP.
- `src/bulwark_falsepos/` — False-positive harness (ADR-036). Curated benign corpus at `spec/falsepos_corpus.jsonl`. Surfaced as the 4th tier card on the Test page, using the same `/v1/clean` pipeline as red-team tiers.

## Running tests

```bash
# Full suite
PYTHONPATH=src python3 -m pytest tests/ -v

# Single test file
PYTHONPATH=src python3 -m pytest tests/test_pipeline.py -v

# Single test
PYTHONPATH=src python3 -m pytest tests/test_pipeline.py::test_name -v
```

## Running the dashboard

```bash
# From source (port 3001 reserved for dev)
PYTHONPATH=src python -m bulwark.dashboard --port 3001

# Docker (port 3000 = published image)
docker run -p 3000:3000 -v $(pwd)/bulwark-config.yaml:/app/bulwark-config.yaml \
  -e BULWARK_API_TOKEN=<token> nathandonaldson/bulwark
```

The dashboard is FastAPI + React/Babel JSX compiled in-browser. Sources live in `src/bulwark/dashboard/static/src/page-*.jsx`.

## Versioning

Patch bump `VERSION` every commit. Minor bump on a major feature. Update `CHANGELOG.md` in the same commit.

## Design rules

No hardcoding in dashboard styles or values — pull from tokens, config, or API. No magic numbers, no inline styles. Buttons: ghost-by-default with subtle hover (`.btn`); filled teal only for primary CTAs (`.btn-primary`). Don't add buttons that aren't wired up.

## Package names

PyPI: `bulwark-shield` (the name `bulwark` is taken by an unrelated package)
Docker: `nathandonaldson/bulwark`
Import: `import bulwark`
