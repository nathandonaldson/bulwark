# Configuration

Bulwark v2 reads its configuration from `bulwark-config.yaml` at startup,
and from environment variables that override file values.

## Environment variables

```bash
# Auth — set this when exposing the dashboard outside loopback.
# Once set, /v1/clean from non-loopback callers requires Bearer auth
# regardless of judge state (ADR-041).
BULWARK_API_TOKEN=<random-string>

# Optional external alerting on BLOCKED events.
BULWARK_WEBHOOK_URL=https://hooks.slack.com/services/...

# SSRF allowlist — comma-separated hostnames that should be permitted
# as webhook + judge endpoints despite living in the private IP space.
BULWARK_ALLOWED_HOSTS=internal-router.example

# Byte cap on /v1/clean.content and /v1/guard.text (ADR-042).
# Default: 262144 (256 KiB). Over-cap requests get HTTP 413.
BULWARK_MAX_CONTENT_SIZE=262144

# Opt into sanitizer-only mode when zero ML detectors are loaded.
# Default behaviour is HTTP 503 from /v1/clean (ADR-040). With this set,
# /v1/clean returns 200 and the response carries mode: "degraded-explicit".
BULWARK_ALLOW_NO_DETECTORS=0

# Opt into a "degraded-explicit" /healthz when no detectors load (ADR-038).
# Default behaviour is /healthz reporting status=degraded.
BULWARK_ALLOW_SANITIZE_ONLY=0

# Enable base64 decode-rescan in /v1/clean (ADR-047). When set to 1,
# base64 spans inside the input are decoded and re-fed through the
# detector chain, catching base64-encoded injection payloads. ROT13
# rescan is always on (zero-FP cost). Default off — trades a small
# false-positive uptick for coverage.
BULWARK_DECODE_BASE64=0
```

The canonical list lives in `spec/contracts/env_config.yaml`. There is no
`BULWARK_LLM_*` env var in v2 — Bulwark never invokes a generative LLM
(ADR-031).

## bulwark-config.yaml

The file is auto-loaded from the working directory at startup. Editable
through `PUT /api/config` (dashboard does this on every toggle).

```yaml
# --- Pipeline layers ---
sanitizer_enabled: true
trust_boundary_enabled: true
canary_enabled: true              # output-side; checked by /v1/guard
encoding_resistant: true
strip_emoji_smuggling: true
strip_bidi: true
normalize_unicode: false

# --- Output checks (used by /v1/guard) ---
guard_patterns:
  - '(?i)\bignore\s+(all\s+)?previous\s+instructions?\b'
  # ... (full default list ships in src/bulwark/dashboard/config.py)
guard_max_length: 5000

canary_tokens:
  prod_admin_url: "https://admin-xxx.infra.internal/v1/keys/abc123"
  aws_key:        "AKIAEXAMPLEAAAABBBBCC"
canary_file: ""

# --- External alerting (ADR-026) ---
webhook_url: ""

# --- Optional detectors (mandatory DeBERTa is loaded automatically) ---
integrations:
  protectai:
    enabled: true
  promptguard:
    enabled: false        # opt-in; requires HuggingFace approval

# --- LLM judge (opt-in, ADR-033) ---
judge_backend:
  enabled: false
  mode: openai_compatible   # or "anthropic"
  base_url: ""              # e.g. http://192.168.1.78:1234/v1
  api_key: ""               # optional for local LM Studio / Ollama
  model: ""                 # e.g. prompt-injection-judge-8b
  threshold: 0.85           # confidence ≥ threshold → block
  fail_open: true           # network/parse error → log + pass
  timeout_s: 30
```

## Docker

```yaml
# docker-compose.yml
services:
  bulwark:
    image: nathandonaldson/bulwark:latest
    ports:
      - "3001:3000"
    env_file: .env
    volumes:
      - ./bulwark-config.yaml:/app/bulwark-config.yaml
      - ./reports:/app/reports
```

`.env`:

```
BULWARK_API_TOKEN=...
BULWARK_WEBHOOK_URL=...
```

## Reading the live config

```bash
curl http://localhost:3001/api/config | jq
```

`PUT /api/config` accepts a partial body with the same shape. The dashboard
uses this for every toggle.

## Resets

Wipe the dashboard event database (does not touch config):

```bash
rm bulwark-dashboard.db
```

Reset config to defaults:

```bash
mv bulwark-config.yaml bulwark-config.yaml.bak
# Restart Bulwark — it'll create a fresh default config on first save.
```
