# Per-Layer Library Usage

Each Bulwark layer works independently. Use one, combine a few, or use
`Pipeline.from_config('bulwark-config.yaml')` to compose the same
DeBERTa + PromptGuard + LLM-judge chain the dashboard's `/v1/clean`
runs (ADR-044, `G-PIPELINE-PARITY-001`). The bare `Pipeline.default()`
returns sanitizer + trust boundary only — the detector chain is
loaded by `from_config` from your YAML.

For an entry-point comparison (`bulwark.clean()` vs `protect()` vs
`Pipeline.from_config()` vs HTTP `/v1/clean`), see
[`python-library.md`](python-library.md). The detector chain itself
lives in [`detection.md`](detection.md); this page covers the
library-side per-layer SDK.

## Sanitizer

Strips hidden payloads before the LLM sees the content. Deterministic, <1ms.

```python
from bulwark import Sanitizer

s = Sanitizer()
clean = s.clean(untrusted_email_body)
```

What it removes (defaults shown):

- Zero-width Unicode characters (U+200B, U+200C, U+200D, U+FEFF, etc.)
- `<script>` and `<style>` content
- CSS hide-text patterns (`display:none`, `font-size:0`, `color:white`, etc.)
- Variation selectors and supplementary variation selectors
- Control characters and bidirectional overrides
- Emoji tag sequences used for steganography
- HTML entity + percent-encoding decode (when `decode_encodings=True`,
  ADR-039 / B1)

NFKC Unicode normalization is **off by default** (`normalize_unicode=False`);
opt in if you want lookalike collapse.

Configuration (the dataclass exposes ~12 toggles plus
`custom_patterns: list[str]` and an optional `EventEmitter` —
`Sanitizer`'s docstring is the full reference):

```python
s = Sanitizer(
    max_length=3000,
    strip_html=True,
    strip_css_hidden=True,
    strip_zero_width=True,
    strip_emoji_smuggling=True,
    strip_bidi=True,
    decode_encodings=False,
    normalize_unicode=False,
    # ... and a handful more — see the dataclass
)
```

## Trust Boundary

Wraps untrusted content in XML tags that tell the LLM this is data to process, not instructions to follow.

```python
from bulwark import TrustBoundary

boundary = TrustBoundary()
tagged = boundary.wrap(clean, source="email", label="inbox")
# <untrusted_email_data source="email" label="inbox">...content...</untrusted_email_data>
```

Formats: XML (default), markdown fence, delimiter.

```python
from bulwark.trust_boundary import BoundaryFormat
boundary = TrustBoundary(format=BoundaryFormat.MARKDOWN_FENCE)
```

Batch wrapping:

```python
items = [("email body 1", "email"), ("email body 2", "email")]
tagged = boundary.wrap_batch(items)
```

## Canary Tokens

Hidden tripwires embedded in sensitive data. If the LLM output contains
a token (even encoded), Bulwark catches it.

```python
from bulwark import CanarySystem

canary = CanarySystem()  # default prefix "BLWK-CANARY"
canary.generate("user_data")
canary.generate("api_keys")

# Tokens are emitted as BLWK-CANARY-<TAG>-<16-hex>, e.g.
#   BLWK-CANARY-USER_DATA-3f9a2c81d6b04e57

# Check LLM output for leaked tokens
result = canary.check(llm_output)
if result.leaked:
    print(f"Exfiltration from: {result.sources}")
```

Encoding-resistant: catches base64, hex, and reversed versions of tokens.

Save and load tokens:

```python
canary.save("canaries.json")
canary = CanarySystem.from_file("canaries.json")
```

Both `save()` and `from_file()` use JSON.
