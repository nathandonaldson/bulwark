# ADR-044: Library `Pipeline` reaches dashboard parity

**Status:** Accepted
**Date:** 2026-04-29
**Related:** ADR-031 (pipeline simplification — "DeBERTa is mandatory"), ADR-033 (LLM judge), ADR-038 (mandatory detector visibility), ADR-040 (fail closed when no detectors)

## Context

Phase E of the Codex efficacy hardening review caught a parity gap that
no prior phase touched. Both the dashboard `/v1/clean` handler and the
library `Pipeline` abstraction read the same `bulwark-config.yaml`, but
they did very different things with it.

The dashboard's startup hook (`bulwark.dashboard.app._auto_load_detection_models`)
walked `config.integrations` and called
`bulwark.integrations.promptguard.load_detector` + `create_check` for
every enabled entry, then attached the resulting checks to the in-memory
`_detection_checks` dict. `/v1/clean` later iterated that dict, plus
`config.judge_backend.enabled`, to compose the three-detector chain
ADR-031 declared mandatory.

The library `Pipeline.from_config()` did none of this:

```python
@classmethod
def from_config(cls, path: str, detector=None) -> "Pipeline":
    config_data = _load_config(path)
    sanitizer = ...
    trust_boundary = ...
    return cls(
        sanitizer=sanitizer,
        trust_boundary=trust_boundary,
        detector=detector,  # <-- never populated from config
    )
```

The detector parameter was a single optional callable that defaulted to
`None`. The `integrations` block of the config was never read. The
`judge_backend.enabled` flag was never read. A library user calling
`Pipeline.from_config("bulwark-config.yaml")` got sanitizer + trust
boundary only — strictly weaker than the dashboard reading the same
file.

ADR-031's "DeBERTa is mandatory" claim was therefore enforced only on
one of two code paths. Phase A (ADR-040) hardened the dashboard
`/v1/clean` to fail-closed when no detectors loaded; library users
silently got the failure mode the dashboard now refuses.

## Decision

`Pipeline.from_config(path)` MUST compose the same detector chain the
dashboard composes from the same config file. The chain is:

1. ProtectAI / DeBERTa, when `integrations.protectai.enabled is True`.
2. PromptGuard-86M, when `integrations.promptguard.enabled is True`.
3. LLM judge, when `judge_backend.enabled is True`.

The library `Pipeline` dataclass replaces its single
`detector: Optional[callable]` field with `detectors: list[Callable]`.
`Pipeline.run()` iterates the list in order and any check raising
`SuspiciousPatternError` blocks the pipeline — same propagation contract
the dashboard implements via the for-loop over `_detection_checks`.

### New guarantee

- **`G-PIPELINE-PARITY-001`** — A `Pipeline.from_config(path)`
  constructed from the same config the dashboard uses MUST raise (or
  surface as `PipelineResult.blocked`) for any input the dashboard's
  `/v1/clean` blocks with HTTP 422.

The guarantee lives in `spec/contracts/clean.yaml` because the parity
claim is about the same surface the existing `G-CLEAN-*` and
`G-CLEAN-DETECTOR-REQUIRED-*` guarantees describe. Tests reference the
guarantee ID in docstrings; `tests/test_pipeline_parity.py` is the
regression rig.

### What's still NOT guaranteed

- **Observability surface stays dashboard-only.** `/healthz`,
  `/api/integrations`, the EventDB / SSE event stream, the WARNING log
  emitted on `BULWARK_ALLOW_NO_DETECTORS=1` — none of these have a
  library-side analogue. A library caller embedding `Pipeline` in their
  own service must wire their own observability if they want it. This
  ADR closes the *defense* parity gap, not the *visibility* gap.
- **Library users do not inherit the `BULWARK_ALLOW_NO_DETECTORS=1`
  fail-closed gate.** ADR-040 fails `/v1/clean` closed at the HTTP
  layer; the library `Pipeline` does not refuse to run when zero
  detectors load. A library caller who builds a Pipeline from a
  no-integrations config gets the legacy sanitize-only result and must
  inspect `pipeline.detectors` themselves if they want to enforce a
  detection-required policy. (Adding a library-side fail-closed gate
  would require deciding the library's contract for "no detectors":
  raise on construction? raise on `run()`? deferred to a future ADR if
  use cases emerge.)
- **No backwards-compat shim for the old single-callable `detector=`
  kwarg.** The `Pipeline.detector` field is removed. Callers
  constructing `Pipeline(detector=my_fn)` directly must switch to
  `Pipeline(detectors=[my_fn])`. No live tests in this repo used the
  old shape — `tests/benchmark.py` references stale kwargs that
  predate ADR-031 and is not part of the test suite.

### Why no `enforce_detectors_loaded` flag at construction time

Considered: a `Pipeline.from_config(path, require_detectors=True)`
parameter that raises if the resulting chain is empty. Rejected because
the library and the dashboard answer different questions:

- The dashboard answers an HTTP request and has a clear "refuse to
  serve" semantic at the wire (HTTP 503).
- The library `Pipeline` is a Python object. A Python caller can — and
  should — decide for themselves whether a 0-detector Pipeline is
  acceptable for their use case (e.g. a corpus-sanitization batch job
  that runs entirely offline). Forcing the dashboard's policy on every
  library caller is a layering violation. The parity guarantee is
  about the *defense the chain delivers when detectors ARE configured*,
  not about whether to have detectors at all.

### Detector loading lives in the integrations module, not a new shared module

Considered: factor the detector-load logic out of
`bulwark.dashboard.app._auto_load_detection_models` into a new
`bulwark.detection_chain` (or similar) module that both the dashboard
and the library import. Rejected for now because the existing
`bulwark.integrations.promptguard.load_detector` / `create_check` pair
is already the correct "shared module" — it's where all detector
construction lives. The dashboard's startup hook is an `async`
ThreadPoolExecutor wrapper around those calls; the library
`from_config()` calls the same functions synchronously. Both call sites
are short, the duplicated logic is "iterate
`config.integrations`, build a check, append" — three lines. Lifting
it into yet another module is overkill until a third caller appears.

The ADR notes this as a possible future refactor but does not require
it.

## Consequences

### Positive

- Library users get the documented v2 pipeline. `import bulwark`,
  `Pipeline.from_config("bulwark-config.yaml")`, `pipeline.run(...)` —
  same defense the dashboard delivers.
- ADR-031's "DeBERTa is mandatory" claim is now enforced on both code
  paths, not just the dashboard's startup.
- The parity test (`test_pipeline_parity.py`) catches future regressions
  where a new detector slot is added to the dashboard but missed in
  `from_config()`. New phases adding a fourth detector type now have to
  update both call sites or the parity test fails.

### Negative

- **Breaking change for library callers passing `detector=callable` to
  `Pipeline()` directly.** No backwards-compat shim. The migration is
  trivial (`detector=fn` → `detectors=[fn]`) but it IS a breaking
  change, hence the MINOR version bump (v2.4.6 → v2.5.0).
- **`from_config()` now imports the detector loaders eagerly.** The
  call path `Pipeline.from_config(path)` previously was free of
  transformer / huggingface imports. Now it pulls them when an
  integration is enabled. A library caller on a read-only config with
  no integrations enabled still gets the lightweight path — the
  imports happen lazily inside the loader, not at module import.

### Neutral

- No HTTP-layer behaviour change. `/v1/clean` already loaded its
  detectors via the dashboard's startup hook; that path is unchanged.
- `/api/pipeline-status` is updated to read `pipeline.detectors` (now a
  list) instead of the removed `pipeline.detector` (singleton). The
  reported field becomes `detectors_loaded: int` (count). The legacy
  `detector: bool` field initially shipped alongside it for back-compat
  was dropped in v2.5.1 after a tree-wide audit found no JSX, test, or
  doc consumer of the old name; folded into the same MINOR bump's
  breaking-change set rather than deferred to a deprecation window.
- VERSION 2.4.6 → 2.5.0 (MINOR — public library API change).
- v2.5.1 (follow-up): `Pipeline.from_config` consolidates two parallel
  YAML loaders into a single `_load_bulwark_config` helper that returns
  `Optional[BulwarkConfig]`. Sanitizer / trust-boundary toggles are
  read from the dataclass directly (`cfg.sanitizer_enabled`,
  `cfg.trust_boundary_enabled`) instead of `BulwarkConfig.to_dict()`
  followed by a YAML re-parse. A malformed config now produces ONE
  WARNING instead of two; the loader-failure degrade path
  (sanitizer + trust-boundary defaults, empty detector chain) is
  covered by `tests/test_pipeline_parity.py::TestLoaderFailureDegrades`.
