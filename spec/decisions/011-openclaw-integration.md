# 011: OpenClaw Integration

## Status
Accepted (revised)

## Context
OpenClaw is the dominant open-source personal AI agent (~247k GitHub stars).
Its prompt injection story is its biggest weakness — multiple CVEs, public
exploits, and only basic boundary markers (`wrapExternalContent()`) for
external content. No actual sanitization of hidden characters, steganography,
encoding tricks, or canary tokens.

Existing security tools (ClawSec, SecureClaw, OpenClaw Shield, ClawDefender)
are either detection-based, audit-focused, or output-side. None do
deterministic input sanitization with trust boundary tagging.

### Why not skill-only?
The initial design used a skill (SKILL.md) to instruct the agent to call
Bulwark. Problem: skills are advisory. The agent can skip them, and a prompt
injection could tell the agent to skip sanitization. The enforcement point
was the agent itself — the thing we're trying to protect.

### Infrastructure-level hooks exist
OpenClaw's plugin system has 29 hooks. Three are relevant:
- `message:received` — fires before prompt construction, can modify content
- `tool_result_persist` — fires when any tool result (web, email, MCP, file)
  is written to the transcript, can modify the result
- `before_message_write` — fires before any message is written to history,
  can modify or block

These run at infrastructure level. The agent cannot bypass them.

## Decision
Ship a Docker sidecar + npm plugin as the primary integration:

- **Docker sidecar**: Bulwark runs alongside OpenClaw via compose overlay.
- **Plugin (npm package)**: Registers three hooks that call Bulwark HTTP API:
  1. `message:received` — sanitize inbound chat messages via `/v1/clean`
  2. `tool_result_persist` — sanitize all tool results via `/v1/clean`
  3. `before_message_write` — guard outbound content via `/v1/guard`
- **Skill (SKILL.md)**: Retained as documentation for the agent, but the
  plugin handles enforcement. The skill explains what Bulwark is doing.

This gives infrastructure-enforced defense. The agent literally cannot see
unsanitized external content because it's cleaned before it enters the
transcript.

## Consequences
- No new Bulwark HTTP endpoints — uses existing /v1/clean and /v1/guard
- Integration lives in integrations/openclaw/ directory
- Plugin is an npm package (integrations/openclaw/plugin/)
- Sidecar runs on port 8100 to avoid conflicts with OpenClaw defaults
- Known limitation: `message:received` doesn't fire for queued messages
  (OpenClaw #64525) — `tool_result_persist` and `before_message_write`
  provide defense-in-depth coverage
