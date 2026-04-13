# ADR-005: Proxy Pattern for protect()

**Status:** Accepted
**Date:** 2026-04-14

## Context

`protect()` wraps an Anthropic client to auto-sanitize messages. Three patterns were considered:

1. **Subclass** `anthropic.Anthropic` — requires the SDK at import time (breaks zero-dep core)
2. **Monkey-patch** `.messages.create` — mutates the original client (breaks shared clients, surprises callers)
3. **Proxy** — wrap the client, intercept `.messages`, delegate everything else

Additional constraint: Anthropic's client uses `functools.cached_property` for `.messages`. A naive `__getattr__` proxy will never intercept `.messages` because `cached_property` stores in the instance `__dict__` on first access, and `__getattr__` is only called when normal lookup fails.

## Decision

Proxy pattern with an explicit `@property` for `.messages`. The proxy class defines `messages` as a regular Python property (not relying on `__getattr__`), returning a `_ProtectedMessages` wrapper. All other attribute access delegates via `__getattr__` to the wrapped client.

The proxy also sanitizes `tool_result` content blocks, not just user-role text. Tool results contain untrusted external data (web scrapes, API responses).

## Consequences

### Positive
- Original client is never mutated — `.unwrap()` returns it unchanged
- Works with any Anthropic client version without pinning to internal API
- Handles `cached_property` correctly

### Negative
- `isinstance(client, anthropic.Anthropic)` fails on the proxy
- IDE autocomplete may not work for `.messages.create()`
- Each new Anthropic feature (beta, batch) passes through unprotected via `__getattr__`
