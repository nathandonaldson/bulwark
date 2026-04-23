# ADR-003: Convenience API Tiers

**Status:** Superseded by ADR-031 (2026-04-23)
**Date:** 2026-04-14

## Context

Bulwark has many components (Sanitizer, TrustBoundary, AnalysisGuard, CanarySystem, TwoPhaseExecutor, Pipeline, MapReduceIsolator). New users face a steep learning curve before they can use any of it. Looking at our own reference implementation (Wintermute), 5 of 6 scripts only use Sanitizer + TrustBoundary — not the full Pipeline.

## Decision

Four tiers of API abstraction:

1. **`clean()` / `guard()`** — one-liners, zero config. Sanitize input, check output. Start here.
2. **`protect(client)`** — SDK wrapper. One-line change, auto-sanitizes all user messages.
3. **`Pipeline.default(analyze_fn, execute_fn)`** — full two-phase execution with bridge guards and canary tokens.
4. **Individual layers** — Sanitizer, TrustBoundary, AnalysisGuard, etc. for custom composition.

## Consequences

### Positive
- A developer can start with `clean()` in 30 seconds and graduate to Pipeline when needed
- Each tier serves a different adoption point — the library meets users where they are

### Negative
- More API surface to document and test
- Risk of false security: `clean()` provides only 2 of 5 layers but users may think they're fully protected

### Neutral
- README restructured to lead with Tier 1, graduating up through the tiers
