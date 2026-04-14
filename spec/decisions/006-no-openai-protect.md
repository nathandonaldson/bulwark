# ADR-006: No OpenAI protect() Wrapper

**Status:** Accepted
**Date:** 2026-04-14

## Context

Should we provide `protect()` for OpenAI's SDK like we do for Anthropic?

The OpenAI SDK accesses completions via `client.chat.completions.create()` — three levels deep. A proxy would need `ProtectedOpenAIClient` -> `_ProtectedChat` -> `_ProtectedCompletions`.

OpenAI has already broken their SDK API between 0.x and 1.x. The three-level proxy must match the exact internal structure.

## Decision

No OpenAI `protect()`. The existing patterns work fine:

- `bulwark.clean()` directly on untrusted content before passing to any LLM
- `Pipeline.default(analyze_fn=lambda: ...)` wrapping the OpenAI call

## Consequences

### Positive
- No fragile proxy that breaks on SDK version changes
- No new dependency on the OpenAI SDK
- Bulwark stays provider-agnostic at its core

### Negative
- OpenAI users don't get the one-liner `protect()` experience
- Slightly more boilerplate compared to Anthropic integration
