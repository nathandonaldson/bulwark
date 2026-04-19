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

## bulwark canary-generate

Generate canary tokens for data sources.

```bash
bulwark canary-generate user_data config api_keys
bulwark canary-generate user_data --output canaries.json --prefix MY-APP
```

## bulwark canary-check

Check for canary token leaks in stdin.

```bash
echo "output text" | bulwark canary-check --tokens canaries.json
```

Exit code 1 if tokens found.

## bulwark_bench

Sibling CLI for LLM bake-offs — sweeps Garak probes across multiple models and prints efficacy × latency × cost.

```bash
bulwark_bench --models claude-haiku-4-5,gpt-4o-mini --tier llm-quick
bulwark_bench --models claude-sonnet-4-6,claude-haiku-4-5 --tier llm-suite
bulwark_bench --models ollama/llama3 --tier llm-quick --bypass-detectors
```

Reads pricing from `src/bulwark_bench/pricing.py`. Use `--bypass-detectors` to guarantee every probe reaches the analyze LLM (recommended when comparing model defense quality). See also the `/bulwark-bench` Claude Code skill for an interactive picker.
