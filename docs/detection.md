# Detection Plugins

Bulwark's architecture handles structural defense. For detection, plug any classifier into the `AnalysisGuard` at the bridge layer. The architecture holds even when every detector fails. Detection is the alarm system on top of the vault.

## Built-in integration module

The fastest path. One import, model downloads automatically.

```python
from bulwark.integrations.promptguard import detect_and_create
from bulwark import Pipeline, AnalysisGuard

guard = AnalysisGuard(custom_checks=[detect_and_create()])
pipeline = Pipeline.default(analyze_fn=my_fn)
pipeline.analysis_guard = guard
```

This loads the ProtectAI DeBERTa model (ungated, no approval needed, 99.99% accuracy on injection detection). ~30ms per check, ~180MB RAM.

## Available models

| Model | Key | Gated | Latency | Accuracy |
|---|---|---|---|---|
| ProtectAI DeBERTa v3 | `protectai` | No | ~30ms | 99.99% |
| Meta PromptGuard-86M | `promptguard` | Yes (HF approval) | ~50ms | High |

```python
# ProtectAI (default, recommended)
check = detect_and_create("protectai")

# PromptGuard-86M (requires huggingface-cli login + Meta approval)
check = detect_and_create("promptguard")
```

## Dashboard activation

In the dashboard Configure tab, click "Activate" on any detection model. The model downloads and loads into memory. Once active, it runs on every payload tested in the Test tab. The model stays loaded while the dashboard service is running.

## Manual integration

If you want more control, load the model and create the check function separately:

```python
from bulwark.integrations.promptguard import load_detector, create_check

detector = load_detector("protectai")
check_fn = create_check(detector, threshold=0.9)

guard = AnalysisGuard(custom_checks=[check_fn])
```

Adjust `threshold` to control sensitivity. Lower = more aggressive (catches more, more false positives). Higher = more conservative.

## Custom detectors

Any function that takes a string and raises `AnalysisSuspiciousError` works:

```python
from bulwark import AnalysisGuard, AnalysisSuspiciousError

def my_detector(analysis: str) -> None:
    if looks_suspicious(analysis):
        raise AnalysisSuspiciousError("Custom check failed")

guard = AnalysisGuard(custom_checks=[my_detector])
```

## LLM Guard

ProtectAI's broader scanner suite. Covers PII, toxicity, and prompt injection.

```python
from llm_guard.input_scanners import PromptInjection
from bulwark import AnalysisGuard, AnalysisSuspiciousError

scanner = PromptInjection()

def llm_guard_check(analysis: str) -> None:
    sanitized, is_valid, score = scanner.scan(analysis)
    if not is_valid:
        raise AnalysisSuspiciousError(f"LLM Guard: {score:.3f}")

guard = AnalysisGuard(custom_checks=[llm_guard_check])
```

## Stack multiple detectors

Each runs on the bridge output. If any raises, the pipeline blocks.

```python
guard = AnalysisGuard(custom_checks=[
    detect_and_create("protectai"),  # fast model-based
    llm_guard_check,                  # broader coverage
    my_custom_check,                  # domain-specific rules
])
```

## Why pluggable?

Detection is an arms race. New attacks bypass old classifiers. By keeping detection pluggable:

- Swap classifiers without changing your pipeline
- Add new detectors as they're released
- Stack multiple for defense in depth
- The architecture holds even when every detector fails
