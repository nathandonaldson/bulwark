# Red Teaming

Prove your defenses work. Don't trust claims, run attacks.

## Built-in attacks

77 patterns across 10 categories:

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
bulwark test --full -v    # All 77 with details
```

## Garak integration

[Garak](https://github.com/leondz/garak) is an LLM vulnerability scanner with constantly-updated probe libraries.

```bash
pip install bulwark-ai[testing]

# Run Garak probes against Bulwark
bulwark test --garak

# Or run Garak externally and import results
garak --model_type test.Blank --probes promptinject -o results.jsonl
bulwark test --garak-import results.jsonl
```

Results flow into the dashboard event stream for visualization.

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

## External tools

- [Garak](https://github.com/leondz/garak) — LLM vulnerability scanner
- [Promptfoo](https://github.com/promptfoo/promptfoo) — red-team evaluation framework
- [PromptBench](https://github.com/microsoft/promptbench) — benchmark for prompt robustness
