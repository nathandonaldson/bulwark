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
```

Env vars are the persistent config mechanism for Docker. Dashboard UI changes override them for the current session but reset on container restart.

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
```

## Dashboard toggles

The dashboard's Configure page writes to the same config format. Changes take effect on the next pipeline run. In Docker, these changes are session-only unless backed by env vars.

## Runtime changes

```python
from bulwark.dashboard.config import BulwarkConfig

config = BulwarkConfig.load()
config.update_from_dict({"sanitizer": {"max_length": 5000}})
config.save()
```
