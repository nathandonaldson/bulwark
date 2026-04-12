# Configuration

## YAML config

Load pipeline settings from a YAML file:

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

The dashboard's Configure page writes to the same config format. Changes take effect on the next pipeline run.

## Runtime changes

```python
from dashboard.config import BulwarkConfig

config = BulwarkConfig.load()
config.update_from_dict({"sanitizer": {"max_length": 5000}})
config.save()
```
