# Bulwark Roadmap

## Current State (v0.4)

8 modules, 356 tests, defense-in-depth hardened. All in `bulwark-ai/`.

### Modules shipped:
| Module | File | Tests | Status |
|--------|------|-------|--------|
| Sanitizer | `sanitizer.py` | 91 | ✅ Complete — emoji smuggling, bidi, NFKC normalization |
| TrustBoundary | `trust_boundary.py` | 35 | ✅ Complete |
| CanarySystem | `canary.py` | 54 | ✅ Complete — encoding-resistant (base64, hex, reversed) |
| TwoPhaseExecutor | `executor.py` | 52 | ✅ Complete — bridge hardened (AnalysisGuard, sanitize_bridge, require_json) |
| MapReduceIsolator | `isolator.py` | 49 | ✅ Complete |
| AttackSuite | `attacks.py` | 35 | ✅ 41 attacks, 10 categories |
| PipelineValidator | `validator.py` | 29 | ✅ Complete |
| CLI | `cli.py` | 11 | ✅ sanitize, canary-check, canary-generate, wrap, test |

### Also shipped:
- `README.md` — full docs with quick start
- `examples/email_triage.py` — end-to-end example
- `pyproject.toml` — pip install ready
- `tests/conftest.py` — shared fixtures

## Next Steps (v1.0)

### Ready to ship:
1. **PyPI publish** — `pip install bulwark-ai`. pyproject.toml is ready. Need to create PyPI account and publish.

2. **Pipeline class** — A convenience wrapper that chains Sanitizer → TrustBoundary → MapReduceIsolator → TwoPhaseExecutor → CanarySystem into one `Pipeline.run()` call. Design exists in the research doc but not yet coded.

3. **YAML config** — `bulwark.yaml` declarative config for all modules. `Pipeline.from_config("bulwark.yaml")`. Design exists but not coded.

4. **Anthropic SDK integration** — Helper that creates `analyze_fn` and `execute_fn` from an Anthropic client with proper tool restrictions. `from bulwark.integrations.anthropic import make_analyze_fn, make_execute_fn`.

### Future (v1.0+):
5. **LangChain integration** — `bulwark.integrations.langchain` with BulwarkSanitizer, BulwarkCanaryChecker, BulwarkTwoPhaseChain
6. **MCP server** — Expose stateless utilities as MCP tools
7. **Async support** — `await executor.run_async()`
8. **Observability** — Structured logging, OpenTelemetry spans
9. **More attack patterns** — Expand from 41 to 75+ attacks
10. **CaMeL-style capability tracking** — Fine-grained information flow control
11. **PromptGuard-86M / PIGuard integration** — Pluggable model-based detection at the AnalysisGuard layer (complement regex-based defaults with ML classifiers)
12. **Garak plugin** — Red-team Bulwark pipelines with Garak's full attack library
13. **Promptfoo provider** — CI testing of Bulwark pipeline effectiveness

## Design Context

The full design document was produced by a research agent during this session. Key decisions:
- Provider-agnostic: LLM calls via `Callable[[str], str]`, not tied to Anthropic/OpenAI
- Defense-in-depth: 5 layers, each independent, any combination valid
- Architectural > detection: two-phase split is deterministic, not probabilistic
- Born from production: extracted from Wintermute agent's real email triage defenses

## Running Tests

```bash
cd bulwark-ai
PYTHONPATH=src python3 -m pytest tests/ -v
```

## Origin

Extracted from prompt injection defenses built for Wintermute (personal AI agent) on 2026-04-08/09. The defenses in `bin/scheduled-check`, `bin/morning-briefing`, `bin/classify-email`, `bin/sanitize-email-body`, and `bin/check-canary` are the production implementations. Bulwark is the generalized, reusable toolkit.
