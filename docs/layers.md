# Per-Layer Usage

Each Bulwark layer works independently. Use one, combine a few, or use `Pipeline.default()` for all five.

## Sanitizer

Strips hidden payloads before the LLM sees the content. Deterministic, <1ms.

```python
from bulwark import Sanitizer

s = Sanitizer()
clean = s.clean(untrusted_email_body)
```

What it removes:
- Zero-width Unicode characters (U+200B, U+200C, U+200D, U+FEFF, etc.)
- Invisible HTML tags and CSS-hidden content
- Control characters and bidirectional overrides
- Emoji tag sequences used for steganography
- NFKC normalization (collapses Unicode lookalikes)

Configuration:

```python
s = Sanitizer(
    max_length=3000,        # Truncate after N chars
    strip_html=True,        # Remove HTML tags
    strip_css_hidden=True,  # Remove CSS-hidden text
    strip_zero_width=True,  # Remove zero-width chars
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

Hidden tripwires embedded in sensitive data. If the LLM output contains a token (even encoded), Bulwark catches it.

```python
from bulwark import CanarySystem

canary = CanarySystem()
canary.generate("user_data")
canary.generate("api_keys")

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
