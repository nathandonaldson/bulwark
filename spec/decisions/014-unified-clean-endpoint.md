# 014: Unified /v1/clean Endpoint

## Status
Accepted

## Context
`/v1/clean` only sanitized and wrapped content. Detection models, LLM two-phase
execution, bridge guard, and canary checks only ran through `/v1/pipeline` — an
endpoint that no production consumer called. Wintermute and other integrations
used `/v1/clean`, getting weaker protection than what the dashboard test page
showed. The test page tested a code path that production didn't use.

This is misleading and dangerous. What we test should be what we ship.

## Decision
Make `/v1/clean` the single defense endpoint that runs the full stack:

1. Sanitizer (strip hidden chars) — if enabled
2. Trust boundary (wrap content) — if enabled
3. Detection models (ProtectAI, PromptGuard) — if active
4. Phase 1 LLM analyze (no tools) — if LLM configured
5. Bridge guard (check analysis for injection) — if enabled
6. Phase 2 LLM execute (acts on analysis) — if LLM configured
7. Canary check — if enabled

Remove `/v1/pipeline` and `/api/test`. The dashboard test page and red team
runner both call `/v1/clean` — testing the real production code path.

When injection is detected, `/v1/clean` returns 422 (not 200). The content
does not pass through. Callers must handle the block.

## Consequences
- Breaking change: `/v1/clean` response schema is larger (includes trace, blocked, analysis)
- Breaking change: `/v1/pipeline` is removed
- Test page and red team test exactly what production uses
- Single code path to maintain, audit, and secure
- Without an LLM configured, `/v1/clean` still runs sanitizer + detection + guard (fast path)
