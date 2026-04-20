# CLI Reference

All commands require the `[cli]` extra: `pip install bulwark-shield[cli]`

## bulwark test

Run attack patterns against the default pipeline.

```bash
bulwark test                         # 8 preset attacks
bulwark test --full                  # All 77 attacks
bulwark test -c steganography        # Filter by category
bulwark test -c encoding -c steganography  # Multiple categories
bulwark test -v                      # Verbose (per-attack details)
bulwark test --garak                 # Run Garak probes
bulwark test --garak-import r.jsonl  # Import Garak results
```

Exit code 0 if all attacks caught, 1 if any exposed.

## bulwark sanitize

Sanitize untrusted text from stdin.

```bash
echo "Hello<script>evil()</script>" | bulwark sanitize
echo "text with\u200bhidden\u200bchars" | bulwark sanitize --no-html
```

Options: `--max-length`, `--no-html`, `--no-css`, `--no-zero-width`

## bulwark wrap

Wrap stdin content in trust boundary tags.

```bash
echo "untrusted content" | bulwark wrap --source email
echo "content" | bulwark wrap --source web --format markdown
```

Options: `--source`, `--label`, `--format` (xml/markdown/delimiter)

## bulwark canary (subgroup)

Manage canaries on a running dashboard via the [canary management API](api-reference.md#canary-management-adr-025). Requires the `[bench]` extra (the subgroup uses `httpx`): `pip install bulwark-shield[bench]`. If the dashboard has auth enabled, set `BULWARK_API_TOKEN` in the environment and the CLI will attach it.

```bash
# List configured canaries
bulwark canary list

# Add a generated canary matching a credential shape
bulwark canary add prod_db_url --shape mongo
bulwark canary add prod_aws_key --shape aws

# Add a literal canary (bring your own string, min 8 chars)
bulwark canary add legacy --token "INTERNAL-SECRET-VALUE-HERE"

# Rotate (same label → new token, no grace period)
bulwark canary add prod_db_url --shape mongo

# Remove
bulwark canary remove prod_db_url

# Preview a canary without saving (no network call)
bulwark canary generate --shape bearer
```

Shapes: `aws`, `bearer`, `password`, `url`, `mongo`. Each emits a shape-matching, UUID-tailed string — every call is guaranteed unique.

Dashboard URL defaults to `http://localhost:3000`; override with `--url http://elsewhere`.

## bulwark canary-generate (legacy)

Pre-ADR-025 command — generates a YAML/JSON canary file for offline use (no dashboard required). Kept for scripted pipelines that pre-date the HTTP API.

```bash
bulwark canary-generate user_data config api_keys
bulwark canary-generate user_data --output canaries.yaml --prefix MY-APP
```

## bulwark canary-check

Check for canary token leaks in stdin.

```bash
echo "output text" | bulwark canary-check --tokens canaries.yaml
```

Exit code 1 if tokens found. Useful in CI for post-run verification when the dashboard isn't in the loop.

## bulwark_bench

Sibling CLI for LLM bake-offs — sweeps Garak probes across multiple models and prints efficacy × latency × cost.

```bash
bulwark_bench --models claude-haiku-4-5,gpt-4o-mini --tier llm-quick
bulwark_bench --models claude-sonnet-4-6,claude-haiku-4-5 --tier llm-suite
bulwark_bench --models ollama/llama3 --tier llm-quick --bypass-detectors
```

Reads pricing from `src/bulwark_bench/pricing.py`. Use `--bypass-detectors` to guarantee every probe reaches the analyze LLM (recommended when comparing model defense quality). See also the `/bulwark-bench` Claude Code skill for an interactive picker.
