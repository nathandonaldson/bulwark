# CLI Reference

Bulwark is distributed as a Docker image (`nathandonaldson/bulwark`); the CLI ships in the same source tree. To run the CLI on a host, install from a checkout:

```bash
git clone https://github.com/nathandonaldson/bulwark.git
cd bulwark
pip install -e ".[cli]"
```

(See ADR-051: Docker is canonical; the package is not published to PyPI.)

After install, the entry-point scripts are `bulwark`, `bulwark-bench`,
and `bulwark-falsepos` (hyphens). The same commands also run via
`python -m bulwark`, `python -m bulwark_bench`, and
`python -m bulwark_falsepos` (underscores).

## bulwark test

Run attack patterns against the default pipeline.

```bash
bulwark test                         # 8 preset attacks
bulwark test --full                  # the full attack suite
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
printf 'text with​hidden​chars' | bulwark sanitize
```

Use `printf` (not `echo`) when you need shell-level interpretation of
`\u…` escapes — default `echo` in zsh/bash leaves the literal backslash
sequence in place.

Options: `--max-length`, `--no-html`, `--no-css`, `--no-zero-width`

## bulwark wrap

Wrap stdin content in trust boundary tags.

```bash
echo "untrusted content" | bulwark wrap --source email
echo "content" | bulwark wrap --source web --format markdown
```

Options: `--source`, `--label`, `--format` (xml/markdown/delimiter)

## bulwark canary (subgroup)

Manage canaries on a running dashboard via the [canary management API](api-reference.md#endpoints). Requires the `[bench]` extra (the subgroup uses `httpx`); install from source: `git clone https://github.com/nathandonaldson/bulwark.git && cd bulwark && pip install -e ".[bench]"`. If the dashboard has auth enabled, set `BULWARK_API_TOKEN` in the environment and the CLI will attach it.

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

## bulwark canary-generate (legacy, pre-ADR-025)

Pre-ADR-025 command — generates a JSON canary file for offline use (no
dashboard required). Kept for scripted pipelines that pre-date the HTTP
API.

```bash
bulwark canary-generate user_data config api_keys
bulwark canary-generate user_data --output canaries.json --prefix MY-APP
```

## bulwark canary-check (legacy, pre-ADR-025)

Check for canary token leaks in stdin against a JSON token file emitted
by `bulwark canary-generate`.

```bash
echo "output text" | bulwark canary-check --tokens canaries.json
```

The `--tokens` file is read with `json.loads` — it must be JSON, not
YAML. Exit code 1 if tokens found. Useful in CI for post-run
verification when the dashboard isn't in the loop.

## bulwark_bench

Sibling CLI for **detector-config** bake-offs (ADR-034). Sweeps Garak probes across detector configurations and prints defense rate × latency.

```bash
# Compare detector configs against the standard tier:
PYTHONPATH=src python3 -m bulwark_bench \
  --configs deberta-only,deberta+promptguard,deberta+llm-judge \
  --judge-base-url http://192.168.1.78:1234/v1 \
  --judge-model prompt-injection-judge-8b
```

`--tier` defaults to `standard`. `--url` defaults to
`http://localhost:3000`. Available presets: `deberta-only`,
`deberta+promptguard`, `deberta+llm-judge`, `all`. DeBERTa is mandatory
in v2 — every preset includes it. The judge presets require
`--judge-model` (and `--judge-base-url` for openai_compatible mode).

## bulwark_falsepos

Sibling CLI for false-positive measurement (ADR-036). Sweeps the same detector configs against a curated benign corpus.

```bash
PYTHONPATH=src python3 -m bulwark_falsepos \
  --configs deberta-only,deberta+promptguard,deberta+llm-judge \
  --max-fp-rate 0.05      # CI gate: exit 1 if any config exceeds 5%
```

Corpus lives at `spec/falsepos_corpus.jsonl` — drop more JSONL lines and the harness picks them up. Same scan also surfaces in the dashboard as the "False Positives" red-team tier.
