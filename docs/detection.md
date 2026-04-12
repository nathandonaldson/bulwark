# Detection Plugins

Bulwark's architecture handles structural defense. For detection, plug any classifier into the `AnalysisGuard` at the bridge layer.

## How it works

The bridge between Phase 1 (analyze) and Phase 2 (execute) runs guard checks on the analysis output. By default, these are regex patterns. Add model-based classifiers for higher catch rates.

```python
from bulwark import AnalysisGuard, AnalysisSuspiciousError

def my_detector(analysis: str) -> None:
    """Raise AnalysisSuspiciousError if suspicious."""
    if is_injection(analysis):
        raise AnalysisSuspiciousError("Injection detected")

guard = AnalysisGuard(custom_checks=[my_detector])
pipeline = Pipeline.default(analyze_fn=my_fn)
pipeline.analysis_guard = guard
```

## PromptGuard-86M

Meta's dedicated prompt injection classifier. Fast (~10ms), good at paraphrased attacks.

```python
from transformers import pipeline as hf_pipeline
from bulwark import AnalysisGuard, AnalysisSuspiciousError

detector = hf_pipeline("text-classification", model="meta-llama/Prompt-Guard-86M")

def promptguard_check(analysis: str) -> None:
    result = detector(analysis)
    if result[0]["label"] == "INJECTION" and result[0]["score"] > 0.9:
        raise AnalysisSuspiciousError(f"PromptGuard: {result[0]['score']:.3f}")

guard = AnalysisGuard(custom_checks=[promptguard_check])
```

## LLM Guard

Protectai's scanner suite. Multiple detection strategies.

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

## Multiple detectors

Stack them. Each runs on the bridge output. If any raises, the pipeline blocks.

```python
guard = AnalysisGuard(custom_checks=[
    promptguard_check,
    llm_guard_check,
    my_custom_check,
])
```

## Why pluggable?

Detection is an arms race. New attacks bypass old classifiers. By keeping detection pluggable:

- Swap classifiers without changing your pipeline
- Add new detectors as they're released
- Remove underperforming ones
- Stack multiple for defense in depth
- Bulwark's architecture holds even when every detector fails
