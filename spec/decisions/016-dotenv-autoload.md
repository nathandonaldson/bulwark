# ADR-016: Auto-load `.env` from cwd on dashboard startup

**Status:** Accepted
**Date:** 2026-04-17

## Context

Bulwark's dashboard reads configuration from `BULWARK_*` env vars
(G-ENV-001 … G-ENV-009). In Docker this works because users pass
`--env-file`. From source (`python -m bulwark.dashboard`) the Python
process does not read `.env` files automatically, so env-based config
silently fails to apply unless the user remembers to `source .env`
first.

The concrete failure seen in practice: user edited `.env`, restarted the
local server, saw `env_configured: false` (because `BULWARK_LLM_MODE` was
not in `os.environ`), and the pipeline fell back to
`https://api.openai.com/v1` with no key → 401 on every request. No
warning, no log line, no hint.

## Decision

`bulwark.dashboard.__main__.main()` auto-loads a `.env` file from the
current working directory before any config is constructed.

- **Zero dependency.** Hand-rolled 10-line parser — no `python-dotenv`.
  Supports `KEY=VALUE`, trims whitespace, strips single/double surrounding
  quotes, ignores blank lines and `#` comments.
- **Does not override existing env.** If `BULWARK_API_KEY` is already
  exported in the shell, that wins over `.env`. Standard dotenv semantics.
- **cwd-only.** No XDG search path, no `~/.bulwark/.env`. `.env` belongs
  to the project directory. Docker path is unaffected because
  `--env-file` still feeds `os.environ` before Python starts.
- **Startup log.** A single line lists which `BULWARK_*` keys were
  loaded (names only, never values) so the user can confirm the file
  was read.

## Consequences

### Positive
- Eliminates the silent 401 trap for local-source users.
- Keeps Docker behavior identical (env is already populated there).
- No new runtime dependency.

### Negative
- cwd-sensitive: running the dashboard from a different directory
  silently skips the file. Documented as the tradeoff for simplicity.
- Users who intentionally keep credentials out of `.env` but in the
  shell session still get the shell's values (by design — existing
  env wins).

### Neutral
- Startup log exposes key *names* only. Values are never printed.
