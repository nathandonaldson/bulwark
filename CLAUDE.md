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
2. **DeBERTa / ProtectAI** (`detectors/`) — mandatory ML classifier, chunked across 512-token windows (ADR-032)
3. **PromptGuard-86M** (`detectors/`) — optional second classifier; already integrated, don't suggest "adding" it
4. **LLM Judge** (`detectors/llm_judge.py`) — optional third detector with high-latency warning (ADR-033). Detection-only: NG-JUDGE-004 forbids returning generative output to `/v1/clean` callers. System prompt is hardcoded in `_SYSTEM_PROMPT` (NG-JUDGE-003).
5. **Trust Boundary** (`trust_boundary.py`) — wraps output in XML/JSON envelope

`ADR-029`: mutating endpoints require `BULWARK_API_TOKEN` when accessed from non-loopback clients (Docker bridge IP triggers this).

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
