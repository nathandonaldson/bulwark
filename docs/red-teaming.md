# Red Teaming

Prove your defenses work. Run attacks, not just tests.

## Built-in attacks

77 patterns across 10 categories. No LLM calls needed, runs locally in seconds.

| Category | Count | What it tests |
|---|---|---|
| instruction_override | 9 | Direct override, role switch, completion hijack |
| social_engineering | 11 | Urgency, authority, context switching |
| encoding | 10 | Base64, hex, ROT13, Unicode escapes |
| steganography | 10 | Zero-width, invisible HTML, emoji smuggling |
| data_exfiltration | 8 | Canary extraction, credential leaks |
| cross_contamination | 6 | Cross-item injection, multi-email poisoning |
| delimiter_escape | 6 | XML tag injection, boundary escapes |
| bridge_exploitation | 6 | Analysis-to-execution bridge attacks |
| tool_manipulation | 6 | Tool parameter injection, unauthorized calls |
| multi_turn | 5 | Multi-message injection chains |

```bash
bulwark test                  # 8 preset attacks, 2 seconds
bulwark test --full           # All 77 with details
bulwark test --full -v        # Verbose per-attack breakdown
bulwark test -c steganography # Filter by category
```

## Production red team

The dashboard's Test tab includes a production red team runner. This is not a simulation. It sends Garak's 315 attack payloads through your actual pipeline: Sanitizer, TrustBoundary, real LLM call (Claude via CLI), canary check. Then evaluates whether the LLM followed its instructions or the injection hijacked it.

Two modes:
- **Quick Test** (10 probes, ~2 min) for fast validation
- **Full Scan** (315 probes, ~50 min) for complete coverage

The report shows:
- Overall defense rate
- Which layer caught each attack (sanitizer, trust boundary, LLM judgment)
- Per-probe-family breakdown
- Specific vulnerabilities with recommendations

Requires `pip install garak` for the probe payloads. LLM calls use your existing claude CLI auth.

## Programmatic validation

```python
from bulwark import PipelineValidator, Sanitizer, TrustBoundary, CanarySystem

validator = PipelineValidator(
    sanitizer=Sanitizer(),
    trust_boundary=TrustBoundary(),
    canary=CanarySystem(),
)

report = validator.validate()
print(f"Score: {report.score}/100")
print(f"Blocked: {report.blocked}/{report.total}")
print(f"Exposed: {report.exposed}/{report.total}")
```

## Production red team (programmatic)

```python
from bulwark.integrations.redteam import ProductionRedTeam

runner = ProductionRedTeam(
    project_dir="/path/to/your/project",
    max_probes=10,  # 0 for all 315
    delay_ms=200,   # rate limiting between LLM calls
)
summary = runner.run()
print(f"Defense rate: {summary.defense_rate:.0%}")
print(f"By layer: {summary.by_layer}")
```

## External tools

- [Garak](https://github.com/leondz/garak) — LLM vulnerability scanner (probe payloads used by the production red team)
- [Promptfoo](https://github.com/promptfoo/promptfoo) — red-team evaluation framework
- [PromptBench](https://github.com/microsoft/promptbench) — benchmark for prompt robustness
