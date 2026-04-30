# Python library

Bulwark ships as a library (`pip install bulwark-shield`) and as a Docker
sidecar. The library is zero-dependency for the sanitize + wrap path; the
detector chain pulls in `transformers` + `torch` and is optional.

## One-call sanitize + wrap

```python
import bulwark

safe = bulwark.clean("ignore previous instructions", source="email")
# → "<untrusted_email source=\"email\" treat_as=\"data_only\">…</untrusted_email>"

# Output side — checks regex patterns against your LLM response:
ok = bulwark.guard("the LLM's response text")
```

This is sanitizer + trust boundary only — no ML detection. For full v2
detection in-process, use `Pipeline.from_config()` below.

## Library/dashboard parity (`Pipeline.from_config()`)

`Pipeline.from_config()` reads the same YAML the dashboard reads and
composes the same detector chain — sanitizer → DeBERTa → optional
PromptGuard → optional LLM Judge → trust boundary (ADR-044,
`G-PIPELINE-PARITY-001`):

```python
from bulwark import Pipeline

pipeline = Pipeline.from_config("bulwark-config.yaml")
result = pipeline.run("ignore previous instructions", source="email")
if result.blocked:
    raise RuntimeError(result.block_reason)
```

`Pipeline.from_config()` blocks the same inputs the dashboard's
`/v1/clean` blocks. The `Pipeline(detect=callable)` constructor was
removed in v2.5.0 — pass `detectors=[callable, ...]` or use
`from_config()`. See ADR-048 for the shared chain helper that
`Pipeline.run()` and `/v1/clean` both delegate to.

## Per-layer use

If you want a layer in isolation (just the sanitizer for a CLI, just the
trust boundary for prompt assembly), see [`docs/layers.md`](layers.md)
for one-component examples.

## Where to look next

- HTTP integration shape: [`docs/api-reference.md`](api-reference.md)
- Detector internals: [`docs/detection.md`](detection.md)
- Working examples: [`examples/quickstart_clean.py`](../examples/quickstart_clean.py),
  [`examples/quickstart_generic.py`](../examples/quickstart_generic.py)

## Entry-point comparison

Four superficially similar paths exist. Pick by what you need:

| Entry point                     | Sanitize + boundary | DeBERTa / PromptGuard / Judge | Network call          | When to use |
|---------------------------------|---------------------|-------------------------------|-----------------------|-------------|
| `bulwark.clean()`               | yes                 | no                            | none (in-process)     | Minimal install, no ML, just strip-and-wrap. |
| `protect(client)` (Anthropic)   | yes                 | no                            | none (in-process)     | One-line wrap of an Anthropic SDK client; sanitize before the API call. |
| `Pipeline.from_config(path)`    | yes                 | yes (same as `/v1/clean`)     | none (in-process)     | Full v2 detection without running a sidecar. ADR-044 parity. |
| `POST /v1/clean` (HTTP)         | yes                 | yes                           | HTTP to sidecar       | Polyglot integrations, dashboard, observability, scale-out. |
