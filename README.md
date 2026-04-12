# Bulwark

**Architectural defense against prompt injection. One import, zero dependencies, attacks can't cause harm.**

Every other tool tries to *detect* prompt injection. Bulwark makes it *structurally harmless*. Even if an attack gets past every classifier, it still can't trigger actions, exfiltrate data, or contaminate other items.

The difference: detection is a filter. Bulwark is an architecture. Filters have false negatives. Architecture doesn't.

## Why not Rebuff / LLM Guard / PromptGuard / LlamaFirewall?

Those are detection layers. They classify input as safe or unsafe, then pass or block. This is fundamentally an arms race -- every new classifier spawns new evasion techniques, and a 95% catch rate means 5% of attacks succeed.

Bulwark works differently. It separates *reading* from *acting* so the LLM that sees untrusted content has no tools. It isolates items so one poisoned email can't see the others. It plants canary tokens so exfiltration gets caught on the way out. These are structural properties -- they hold regardless of how clever the attack is.

You should use Bulwark *and* a detection tool. Bulwark is the architecture. Detection is the alarm system. A building needs both load-bearing walls and smoke detectors.

## See it work in 60 seconds

Install and run the built-in attack suite:

```bash
# Available now
pip install "git+https://github.com/nathandonaldson/bulwark.git#egg=bulwark-ai[cli]"

# When PyPI is live
pip install bulwark-ai[cli]

# Run the attack suite
bulwark test
```

```
Bulwark Validation Report
========================
Score: 92.2/100

  Blocked:  68/77
  Reduced:  5/77
  Exposed:  4/77

  instruction_override: 8/9 blocked
  data_exfiltration: 7/8 blocked
  cross_contamination: 6/6 blocked
  steganography: 9/10 blocked
  delimiter_escape: 5/6 blocked
  encoding: 9/10 blocked
  social_engineering: 8/11 blocked
  multi_turn: 5/5 blocked
  bridge_exploitation: 5/6 blocked
  tool_manipulation: 6/6 blocked
```

77 attack patterns across 10 categories. The exposed ones are attacks that require model-based detection (AnalysisGuard is regex-based by default -- plug in PromptGuard-86M for those).

## Add it to your project with Claude Code

Paste this into Claude Code or any AI coding assistant:

```
I have a Python application that calls an LLM with untrusted content from
[email/web/calendar/documents]. Add Bulwark to protect against prompt injection.
My LLM calls use [Anthropic SDK / OpenAI SDK / raw HTTP]. Show me the minimal
integration using Bulwark's Pipeline.
```

## Quick start

### Anthropic SDK (fastest path)

```python
import anthropic
from bulwark.integrations.anthropic import make_pipeline

pipeline = make_pipeline(anthropic.Anthropic())
result = pipeline.run("untrusted email body", source="email")

if result.blocked:
    print(f"Blocked: {result.block_reason}")
else:
    print(result.analysis)
```

Two lines to go from unprotected to five-layer defense. `make_pipeline` wires up Haiku for Phase 1 (analysis, no tools) and Sonnet for Phase 2 (execution, restricted tools).

### OpenAI SDK or any provider

```python
from openai import OpenAI
from bulwark import Pipeline

client = OpenAI()

def analyze(prompt: str) -> str:
    """Phase 1: read-only, no tools."""
    return client.chat.completions.create(
        model="gpt-4o-mini",
        messages=[{"role": "user", "content": prompt}],
    ).choices[0].message.content

pipeline = Pipeline.default(analyze_fn=analyze)
result = pipeline.run("untrusted document text", source="document")
```

### Generic callable

```python
from bulwark import Pipeline

pipeline = Pipeline.default(analyze_fn=my_llm_call)
result = pipeline.run(untrusted_content, source="web")
```

Any function with signature `(str) -> str` works. Async functions work too -- use `pipeline.run_async()`.

## Architecture

```
                    Untrusted content
                          |
                    [1. Sanitizer]
                    Strip zero-width chars, hidden HTML,
                    CSS-hidden text, control characters
                          |
                    [2. Trust Boundary]
                    Wrap in XML tags that mark content
                    as untrusted data, not instructions
                          |
                    [3. Phase 1: Analyze]
                    LLM reads content — NO tools available.
                    Even successful injection can't act.
                          |
                    [4. Bridge]
                    Sanitize analysis output, guard against
                    suspicious patterns, check canary tokens
                          |
                    [5. Phase 2: Execute]
                    LLM acts on the analysis — never sees
                    raw untrusted content. Restricted tools only.
```

Each layer is independent. Use one, use all five, or compose your own pipeline. The `Pipeline.default()` constructor wires them in the right order with sensible defaults.

For batch processing (multiple emails, documents, etc.), `MapReduceIsolator` processes each item in complete isolation -- one compromised item cannot see or affect the others.

## How it works

The key insight is **two-phase execution**. Most AI agents have one LLM call that both reads untrusted content *and* has access to tools. This is the root vulnerability -- injection in the content can invoke tools.

Bulwark splits this into two phases:

**Phase 1 (Analyze):** The LLM sees the untrusted content but has no tools. It can only produce text output -- a classification, summary, or structured analysis. Even if the injection completely compromises this phase, the worst it can do is produce bad analysis text.

**Phase 2 (Execute):** A separate LLM call receives only the sanitized analysis from Phase 1. It has tools, but never sees the raw untrusted content. It acts on the analysis, not the attack.

Between the phases, the **bridge** applies three checks:
1. **Sanitize** -- strip any hidden characters that Phase 1's output might carry
2. **Guard** -- regex patterns that catch common injection artifacts (`ignore previous`, `<system>`, tool call syntax)
3. **Canary check** -- detect if sensitive data was exfiltrated through the analysis

The other layers reinforce this:

- **Sanitizer** strips steganographic payloads (zero-width Unicode, invisible HTML, CSS tricks) *before* the LLM sees the content. Deterministic, <1ms.
- **Trust Boundary** wraps untrusted content in XML tags (`<untrusted_content source="email">...</untrusted_content>`) that tell the LLM this is data to process, not instructions to follow. Claude respects these well; other models vary.
- **Canary Tokens** are hidden tripwires embedded in sensitive data. If the LLM output contains a canary token (even base64-encoded, hex-encoded, or reversed), Bulwark catches the exfiltration attempt.
- **MapReduceIsolator** ensures that when processing a batch of items, each gets its own isolated LLM call. Injection in item 3 cannot read items 1, 2, or 4.

## How it compares

| | Bulwark | Rebuff | LLM Guard | PromptGuard-86M | LlamaFirewall | NeMo Guardrails |
|---|---|---|---|---|---|---|
| **Approach** | Architecture | Detection | Detection | Detection | Detection | Flow control |
| **Two-phase execution** | Yes | - | - | - | - | - |
| **Cross-item isolation** | Yes | - | - | - | - | - |
| **Canary tokens** | Yes | Yes | - | - | - | - |
| **Input sanitization** | Deterministic | - | Model-based | - | PromptGuard | - |
| **Detection** | Pluggable | LLM-based | Built-in | Built-in | Built-in | Built-in |
| **Built-in red teaming** | 77 attacks | - | - | - | - | - |
| **Zero dependencies** | Yes | No | No | No | No | No |
| **Provider-agnostic** | Yes | Yes | Yes | Yes | No (Meta) | No (NVIDIA) |
| **Latency overhead** | <1ms | 100-500ms | 50-200ms | 10-100ms | 10-100ms | 50-500ms |

**Bulwark is the architectural layer. Other tools are the detection layer. Use both.**

You can plug PromptGuard-86M or any classifier into Bulwark's `AnalysisGuard` via `custom_checks`:

```python
from transformers import pipeline as hf_pipeline
from bulwark import AnalysisGuard, AnalysisSuspiciousError

detector = hf_pipeline("text-classification", model="meta-llama/Prompt-Guard-86M")

def promptguard_check(analysis: str) -> None:
    result = detector(analysis)
    if result[0]["label"] == "INJECTION" and result[0]["score"] > 0.9:
        raise AnalysisSuspiciousError(f"Injection: {result[0]['score']:.3f}")

guard = AnalysisGuard(custom_checks=[promptguard_check])
pipeline = Pipeline.default(analyze_fn=my_fn, execute_fn=my_exec)
pipeline.analysis_guard = guard
```

## Dashboard

Bulwark includes an interactive dashboard where you can paste attacks and watch the pipeline trace in real time. Each layer lights up as it processes the input -- you can see exactly what got sanitized, where trust boundaries were applied, and whether the bridge caught anything suspicious.

```bash
# Quick start (requires FastAPI + Uvicorn)
pip install fastapi uvicorn
cd dashboard && uvicorn app:app --port 3000

# Or install as a persistent macOS service
bash dashboard/install-service.sh install
```

Open http://localhost:3000. The test page lets you throw any attack at your pipeline and see a step-by-step trace of what each defense layer did.

Connect your pipeline to the dashboard with the `WebhookEmitter`:

```python
from bulwark import Pipeline
from bulwark.events import WebhookEmitter

pipeline = Pipeline.default(
    analyze_fn=my_fn,
    emitter=WebhookEmitter("http://localhost:3000/api/events"),
)
```

## Manual integration

### Per-layer usage

Each layer works independently if you don't want the full pipeline:

```python
from bulwark import Sanitizer, TrustBoundary, CanarySystem

# Sanitize untrusted input
clean = Sanitizer().clean(untrusted_email_body)

# Wrap in trust boundaries
boundary = TrustBoundary()
tagged = boundary.wrap(clean, source="email", label="inbox")

# Generate and check canary tokens
canary = CanarySystem()
canary.generate("user_data")
canary.generate("api_keys")
result = canary.check(llm_output)
if result.leaked:
    print(f"Data exfiltration detected from: {result.sources}")
```

### Two-phase execution (direct)

```python
from bulwark import TwoPhaseExecutor, CanarySystem

executor = TwoPhaseExecutor(
    analyze_fn=my_readonly_llm_call,    # No tools available
    execute_fn=my_restricted_llm_call,  # Has tools, restricted
    canary=CanarySystem(),
    sanitize_bridge=True,               # Strip hidden chars from Phase 1 output
    guard_bridge=True,                  # Block suspicious patterns in analysis
    require_json=True,                  # Force structured output from Phase 1
)

result = executor.run(analyze_prompt=tagged_content)
```

### Batch isolation

```python
from bulwark import MapReduceIsolator

isolator = MapReduceIsolator(
    process_fn=my_llm_call,
    prompt_template="Classify this email:\n{item}",
)
results = isolator.run(emails)
# Each email processed independently -- injection in one can't see others
```

### Async support

Pipeline supports both sync and async. If your LLM calls are async, use `run_async`:

```python
result = await pipeline.run_async("untrusted content", source="email")
```

Both `analyze_fn` and `execute_fn` can be sync or async callables -- Bulwark detects and handles both.

### Pipeline from config

Load configuration from YAML (connects to dashboard toggles):

```python
pipeline = Pipeline.from_config("bulwark-config.yaml", analyze_fn=my_fn)
```

## Testing and red teaming

### Quick check

```bash
bulwark test
```

Runs all 77 built-in attack patterns against the default pipeline. Covers 10 categories: instruction override, data exfiltration, cross-contamination, steganography, delimiter escape, encoding, social engineering, multi-turn, bridge exploitation, and tool manipulation.

### Filtered by category

```bash
bulwark test -c steganography -c encoding
```

### Verbose output

```bash
bulwark test -v
```

Shows per-attack details: which layer caught it, how much payload was removed, what defense verdict was applied.

### External red teaming

For thorough adversarial testing beyond Bulwark's built-in patterns, use [Garak](https://github.com/leondz/garak) (LLM vulnerability scanner) or [Promptfoo](https://github.com/promptfoo/promptfoo) (red-team evaluation framework) against your pipeline.

## CLI

```bash
# Sanitize stdin
echo "Hello<script>evil()</script>" | bulwark sanitize

# Wrap in trust boundaries
echo "untrusted content" | bulwark wrap --source email

# Generate canary tokens
bulwark canary-generate user_data config --output canaries.json

# Check for canary leaks
echo "output text" | bulwark canary-check --tokens canaries.json

# Run attack suite
bulwark test
```

## Installation

```bash
# Core library (zero dependencies)
pip install bulwark-ai

# With CLI
pip install bulwark-ai[cli]

# With Anthropic SDK integration
pip install bulwark-ai[anthropic]

# Everything
pip install bulwark-ai[all]
```

From Git (available now):

```bash
pip install "git+https://github.com/nathandonaldson/bulwark.git#egg=bulwark-ai"
pip install "git+https://github.com/nathandonaldson/bulwark.git#egg=bulwark-ai[all]"
```

Python 3.9+. No dependencies for the core library.

## Honest limitations

- **AnalysisGuard patterns are regex-based.** Paraphrasable attacks will get past them. For stronger bridge defense, plug in PromptGuard-86M or your own classifier via `custom_checks`.
- **Canary tokens catch naive exfiltration.** They're resistant to base64, hex, and reversed encoding, but not semantic paraphrasing. If the LLM restates the sensitive data in its own words, canaries won't catch it.
- **Trust boundaries depend on LLM training.** Claude respects XML boundary tags well. Other models may not. Test with your specific model.
- **The Phase 1 to Phase 2 bridge is a residual risk.** Analysis output is sanitized and guarded, but a sufficiently clever attack could craft benign-looking analysis that manipulates Phase 2 behavior.
- **English-focused.** Attack patterns and security instructions are primarily in English. Multilingual attacks may have lower detection rates.
- **This is not a silver bullet.** Bulwark raises the cost of successful prompt injection from trivial to very hard. It does not make it impossible. Defense in depth means using Bulwark alongside detection tools, monitoring, and least-privilege access controls.

## License

MIT
