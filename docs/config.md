# Configuration

## Docker (recommended)

Set environment variables in your `docker-compose.yml` or `.env` file:

```yaml
environment:
  - BULWARK_LLM_MODE=anthropic
  - BULWARK_API_KEY=sk-ant-...
  - BULWARK_ANALYZE_MODEL=claude-haiku-4-5-20251001
  - BULWARK_EXECUTE_MODEL=claude-sonnet-4-6
```

Or with a `.env` file (keeps secrets out of version control):

```bash
BULWARK_LLM_MODE=anthropic
BULWARK_API_KEY=sk-ant-your-key
BULWARK_API_TOKEN=$(openssl rand -hex 32)
```

## Dashboard authentication

Set `BULWARK_API_TOKEN` to protect the dashboard with bearer token auth:

```bash
# Generate a secure random token
openssl rand -hex 32
# Add it to your .env
echo "BULWARK_API_TOKEN=your-generated-token" >> .env
```

When set:
- The dashboard shows a login screen — enter the token to access
- Management endpoints (`/api/config`, `/api/redteam/*`, etc.) require `Authorization: Bearer <token>`
- Core API (`/v1/clean`, `/v1/guard`) remains public — no token needed
- The token is also accepted via `bulwark_token` HttpOnly cookie (set automatically on login)

When not set: all endpoints are open (fine for localhost development).

Env vars override the config file and are the persistent config mechanism for Docker. Dashboard UI changes are session-only unless backed by env vars.

## YAML config

For non-Docker installs, load pipeline settings from a YAML file:

```python
pipeline = Pipeline.from_config("bulwark-config.yaml", analyze_fn=my_fn)
```

Example `bulwark-config.yaml`:

```yaml
sanitizer:
  enabled: true
  max_length: 3000
  strip_html: true
  strip_css_hidden: true

trust_boundary:
  enabled: true
  format: xml

executor:
  guard_bridge: true
  sanitize_bridge: true
  require_json: false

canary:
  enabled: true

canary_tokens:
  prod_db_url: "mongodb+srv://svc_admin:Xk93mNpQ7vR@cluster0.prod.mongodb.net/main"
  prod_aws_key: "AKIA7Z9XK2P4QW8T3NFG"
  # ... add more via `bulwark canary add <label> --shape <shape>`
  #     or via the dashboard Configure → Canary panel (ADR-025)
```

## Canary management

Three ways to manage canary tokens; all three write to `canary_tokens` in the same config file:

1. **Dashboard UI** — Configure → Canary panel has an Add form with a shape picker and per-entry Remove button.
2. **CLI** — `bulwark canary {list, add, remove, generate}` — see [cli.md](cli.md).
3. **HTTP API** — `GET/POST /api/canaries`, `DELETE /api/canaries/{label}` — see [api-reference.md](api-reference.md#canary-management-adr-025).

Editing `canary_tokens` by hand still works, but requires restarting the container to pick up changes. The API / UI / CLI routes all persist immediately.

## Dashboard toggles

The dashboard's Configure page writes to the same config format. Changes take effect on the next pipeline run. In Docker, these changes persist when the config file is bind-mounted from the host (see [Persistence](#persistence) below).

## Persistence across container recreation

By default, `bulwark-config.yaml` lives inside the container's writable layer — it survives `docker restart` but not `docker rm`. To make canaries, guard patterns, and UI edits persist across rebuilds, bind-mount the config file from the host:

```yaml
# docker-compose.yml (see repo root for the full version)
services:
  bulwark:
    image: nathandonaldson/bulwark
    volumes:
      - ${HOME}/.config/bulwark/bulwark-config.yaml:/app/bulwark-config.yaml
```

Tighten file permissions: `chmod 600 ~/.config/bulwark/bulwark-config.yaml`. Canaries are by design non-sensitive (a leaked canary grants an attacker nothing), but there's no reason for other local processes to read the file.

## Webhook alerting on BLOCKED events (ADR-026)

Set `BULWARK_WEBHOOK_URL` (env) or `webhook_url` (YAML) to have Bulwark POST every BLOCKED event — prompt-injection blocks, canary leaks, guard-pattern hits, detection-model blocks — to an external URL.

```bash
# .env
BULWARK_WEBHOOK_URL=https://hooks.slack.com/services/T0.../B0.../xxx
```

Payload shape:

```json
{
  "events": [
    {
      "timestamp": 1744905823.412,
      "layer": "canary",
      "verdict": "blocked",
      "source_id": "api:clean:email",
      "detail": "Blocked: Canary token leaked from: prod_db_url",
      "duration_ms": 1420.3,
      "metadata": {}
    }
  ]
}
```

Delivery is fire-and-forget — a slow or unreachable webhook never delays `/v1/clean`. No retries, no auth headers (URL is the secret). Only `verdict == "blocked"` fires; PASSED / MODIFIED events are internal-only. See [spec/contracts/webhooks.yaml](../spec/contracts/webhooks.yaml) for the full contract.

## Runtime changes

```python
from bulwark.dashboard.config import BulwarkConfig

config = BulwarkConfig.load()
config.update_from_dict({"sanitizer": {"max_length": 5000}})
config.save()
```
