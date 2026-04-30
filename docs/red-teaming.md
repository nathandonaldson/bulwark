# Red Teaming

Prove your defenses work. Run attacks, not just tests.

## Built-in attacks

Curated attack catalog across 10 categories. No LLM calls needed, runs
locally in seconds. The exact count moves as the catalog grows; the
categories are stable.

| Category              | Count | What it tests                                        |
|-----------------------|-------|------------------------------------------------------|
| instruction_override  | 9     | Direct override, role switch, completion hijack      |
| social_engineering    | 11    | Urgency, authority, context switching                |
| encoding              | 10    | Base64, hex, ROT13, Unicode escapes                  |
| steganography         | 10    | Zero-width, invisible HTML, emoji smuggling          |
| data_exfiltration     | 8     | Canary extraction, credential leaks                  |
| cross_contamination   | 6     | Cross-item injection, multi-email poisoning          |
| delimiter_escape      | 6     | XML tag injection, boundary escapes                  |
| tool_manipulation     | 6     | Tool parameter injection, unauthorized calls         |
| multi_turn            | 5     | Multi-message injection chains                       |
| boundary_escape       | 6     | Structured-payload trust-boundary escape patterns    |

An 11th category — `split_evasion` — is generated on demand by
`AttackSuite.generate_split_evasion_samples()` rather than registered
in the static catalog. It exercises the long-range dilution gap
documented in ADR-046 (see "Known non-guarantees" below).

```bash
bulwark test                  # 8 preset attacks, 2 seconds
bulwark test --full           # the full attack suite with details
bulwark test --full -v        # Verbose per-attack breakdown
bulwark test -c steganography # Filter by category
```

## Production red team

The dashboard's Test tab includes a production red-team runner. Not a simulation — it sends Garak's attack payloads through your actual `/v1/clean` pipeline (Sanitizer → DeBERTa → optional PromptGuard / LLM Judge → Trust Boundary) and records what each layer did.

Four tiers (probe counts pulled dynamically from your installed garak version):

- **Smoke Test** (10 probes) — quick check that the pipeline is working
- **Standard Scan** — all active garak probes across injection,
  encoding, exfiltration, jailbreaks, content safety. The exact probe
  count is computed at runtime from `garak.probes.<family>`
  introspection and shown on the tier card.
- **Full Sweep** — every probe including extended payload variants
- **False Positives** — sends the curated benign corpus from `spec/falsepos_corpus.jsonl` through `/v1/clean` and inverts the metric so the displayed "defense" rate captures benign-pass rate (ADR-036)

Note: `llm-quick` and `llm-suite` LLM-facing tiers were removed in
v2.1.0 (ADR-035); v2's detection-only architecture has no LLM behind
the detectors to test.

For detector-config comparisons (DeBERTa vs DeBERTa+PromptGuard vs DeBERTa+LLM-Judge), run `bulwark_bench` — a sibling CLI that sweeps the named presets and prints a markdown comparison table (ADR-034).

Reports are automatically saved to `reports/` as JSON and downloadable from the dashboard for gap analysis. The dashboard exposes saved reports via `GET /api/redteam/reports` and `GET /api/redteam/reports/{filename}`, and `POST /api/redteam/retest` re-runs only the previously failed probes.

The report shows:
- Overall defense rate (format failures counted as defended, hijacks counted separately)
- Which layer caught each attack (sanitizer, trust boundary, detection models, LLM judgment)
- Per-probe-family breakdown with defended/hijacked/format_failure counts
- Specific vulnerabilities with recommendations
- **Retest failures** button to re-run only the failed probes from a previous report

Rate limiting is smart — only probes that reach the LLM are delayed (200ms). Probes blocked by detection models or the sanitizer run at full speed.

Requires `pip install garak` for the probe payloads (included in the Docker image).

## Known non-guarantees

- **Long-range split-evasion** (`NG-DETECTOR-WINDOW-EVASION-001`,
  ADR-046) — ≥~50 tokens of benign filler between trigger and
  instruction is documented as out of scope for the per-window
  classifier. Curated split-evasion pairs live at
  `src/bulwark/attacks.py`; on-demand corpus generation is via
  `AttackSuite.generate_split_evasion_samples()`. Defense for that
  regime relies on the LLM Judge (ADR-033) — enable the judge if
  dilution-style attacks are in scope for your threat model.

## Programmatic validation

```python
from bulwark import PipelineValidator, Sanitizer, TrustBoundary, CanarySystem

validator = PipelineValidator(
    sanitizer=Sanitizer(),
    trust_boundary=TrustBoundary(),
    canary=CanarySystem(),
)

report = validator.validate()
print(f"Score: {report.score}/100")
print(f"Blocked: {report.blocked}/{report.total}")
print(f"Exposed: {report.exposed}/{report.total}")
```

## Production red team (programmatic)

```python
from bulwark.integrations.redteam import ProductionRedTeam

runner = ProductionRedTeam(
    project_dir="/path/to/your/project",
    max_probes=10,        # 0 for all probes (count depends on garak version + tier)
    delay_ms=200,
)
# Route probes through /v1/clean to exercise the production detector
# chain (DeBERTa + optional PromptGuard / Judge). Without this the
# runner falls back to a sanitize+boundary-only path that won't
# exercise ADR-031's chain.
runner.pipeline_url = "http://localhost:3000"

summary = runner.run()
print(f"Defense rate: {summary.defense_rate:.0%}")
print(f"By layer: {summary.by_layer}")
```

## External tools

- [Garak](https://github.com/leondz/garak) — LLM vulnerability scanner (probe payloads used by the production red team)
- [Promptfoo](https://github.com/promptfoo/promptfoo) — red-team evaluation framework
- [PromptBench](https://github.com/microsoft/promptbench) — benchmark for prompt robustness
