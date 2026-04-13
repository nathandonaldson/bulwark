# ADR-004: clean() Defaults

**Status:** Accepted
**Date:** 2026-04-14

## Context

`clean()` is the simplest entry point. Two default values matter:

1. **max_length:** The underlying `Sanitizer` defaults to 3000 chars. Should `clean()` inherit this?
2. **format:** Trust boundaries can be XML, markdown fence, or delimiter. Which default?

## Decision

- **`max_length=None`** (no truncation). Silent truncation is a data loss bug for a general-purpose convenience function. A 10K email silently chopped to 3K would surprise users. The Sanitizer's 3000 default makes sense as defense-in-depth for users constructing their own pipeline, but `clean()` should not drop content without being asked.

- **`format="xml"`** (XML trust boundaries). Claude is trained to respect XML structural boundaries, making this the strongest option for the primary use case (Anthropic SDK users). Non-Claude models may work better with `"markdown"` or `"delimiter"` — the parameter is explicit so users can choose.

## Consequences

### Positive
- No data loss surprises
- Developers opt into truncation explicitly when they want it

### Negative
- Very long inputs are not truncated — could produce very long prompts
- Non-Claude users must discover and set the format parameter themselves
