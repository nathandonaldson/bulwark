# Two-Phase Execution

The core of Bulwark's defense. Separates reading untrusted content from acting on it.

## Direct setup

```python
from bulwark import TwoPhaseExecutor, CanarySystem

executor = TwoPhaseExecutor(
    analyze_fn=my_readonly_llm_call,    # No tools available
    execute_fn=my_restricted_llm_call,  # Has tools, restricted
    canary=CanarySystem(),
    sanitize_bridge=True,               # Strip hidden chars from Phase 1 output
    guard_bridge=True,                  # Block suspicious patterns
    require_json=True,                  # Force structured output from Phase 1
)

result = executor.run(analyze_prompt=tagged_content)
print(result.analysis)    # Phase 1 output
print(result.execution)   # Phase 2 output
print(result.blocked)     # True if bridge caught something
```

## Bridge configuration

The bridge between Phase 1 and Phase 2 applies three checks:

1. **Sanitize** — strips hidden characters that Phase 1 output might carry
2. **Guard** — regex patterns catch injection artifacts (`ignore previous`, `<system>`, tool call syntax)
3. **Canary check** — detects if sensitive data was exfiltrated through the analysis

```python
from bulwark import AnalysisGuard

# Custom guard with additional patterns
guard = AnalysisGuard(
    custom_patterns=["my_custom_pattern"],
    custom_checks=[my_detection_function],
)

executor = TwoPhaseExecutor(
    analyze_fn=my_fn,
    analysis_guard=guard,
)
```

## require_json

Forces Phase 1 to produce valid JSON. This constrains the output format, making it harder for injected content to sneak through as free-form text.

```python
executor = TwoPhaseExecutor(
    analyze_fn=my_fn,
    require_json=True,  # Phase 1 output must parse as JSON
)
```
