# ADR-002: Two-Phase Execution Architecture

**Status:** Superseded by ADR-031 (2026-04-23)
**Date:** 2026-04-14

## Context

LLMs that process untrusted content (emails, web scrapes, user input) and also have tool access are vulnerable to prompt injection. If an attacker embeds instructions in the untrusted content, the LLM may follow them and trigger unintended tool calls.

Detection (classifying input as safe/unsafe) is an arms race — every detector can be bypassed with enough effort. Architectural separation is more durable.

## Decision

Split LLM processing into two phases:

- **Phase 1 (Analyze):** LLM reads untrusted content but has NO tools. Even if injection succeeds, nothing can happen.
- **Bridge:** Sanitizes Phase 1 output, checks for injection patterns (AnalysisGuard), checks for canary token leaks.
- **Phase 2 (Execute):** LLM has full tool access but NEVER sees raw untrusted content — only the sanitized summary from Phase 1.

## Consequences

### Positive
- Architectural guarantee: the LLM that can act never sees the attack
- Each layer works independently — defense in depth
- Detection tools plug into the bridge as additional (not sole) defense

### Negative
- Requires two LLM calls instead of one (cost and latency)
- The bridge is a residual attack surface — sophisticated attacks could craft benign-looking Phase 1 output
- More complex to integrate than a single-call pattern

### Neutral
- Convenience APIs (clean, guard, protect) provide simpler entry points for users who don't need full two-phase
