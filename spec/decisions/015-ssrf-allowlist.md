# ADR-015: Opt-in SSRF allowlist for LAN model endpoints

**Status:** Accepted
**Date:** 2026-04-17

## Context

Bulwark's SSRF guard (`_validate_base_url` in `llm_factory.py`) blocks every
RFC1918 / link-local / loopback IP except `localhost`, `127.0.0.1`, `::1`, and
`host.docker.internal`. This was introduced in v1.0.0 (CHANGELOG "SSRF
validation on OpenAI-compatible execution paths") to prevent the dashboard
from being coerced into probing internal infrastructure.

Legitimate users running local inference servers on their LAN (LM Studio,
Ollama, vLLM on a workstation, etc.) cannot point Bulwark at
`http://192.168.x.x:PORT/v1` without hitting this block. A tunnel workaround
exists but is hostile to configure and fragile across reboots.

## Decision

Add an opt-in env var `BULWARK_ALLOWED_HOSTS` — a comma-separated list of
hostnames/IP literals that bypass the private-IP check in
`_validate_base_url`.

Rules:
- **Metadata hosts remain unconditionally blocked.** Even if a user lists
  `169.254.169.254` in the allowlist, the cloud-metadata block wins. This is
  defense-in-depth against typos and against compromised env-var injection.
- **Exact match only.** No wildcards, no CIDR. Each entry is compared to the
  parsed URL's `hostname` verbatim. Simple semantics, no accidental scope.
- **Env is read at validation time, not cached.** Keeps behavior consistent
  with `BULWARK_ALLOWED_HOSTS` changes across dashboard sessions.
- **No allowlist entry is required for already-allowed hosts** (`localhost`,
  `127.0.0.1`, `::1`, `host.docker.internal`). Those stay in the default
  allow-by-construction path.
- **Failure mode is still "blocked".** An empty or unset var is identical to
  the current behavior — no widening happens without explicit opt-in.

## Consequences

### Positive
- Users can point Bulwark at LAN inference servers without tunnels.
- Explicit env var makes the widened trust boundary auditable — a single
  `env | grep BULWARK_ALLOWED_HOSTS` reveals the exposure.
- Metadata-host block survives misconfiguration.

### Negative
- Widens the SSRF trust boundary in direct proportion to the user's
  allowlist. A shared dashboard with `BULWARK_ALLOWED_HOSTS=10.0.0.0/8`-style
  misuse (not supported here but users may request it) would re-open the
  door we closed in v1.0.0.
- No UI surfacing — users must inspect env to see which hosts are allowed.
  Follow-up work could expose the effective allowlist in `/api/config`.

### Neutral
- The existing `localhost` / `host.docker.internal` allows remain unchanged;
  this is purely additive.
