# ADR-036: False-positive harness

**Status:** Accepted
**Date:** 2026-04-23

## Context

The red-team scan answers "what fraction of attacks does Bulwark
block?" The complementary question — "what fraction of *benign* traffic
does Bulwark block?" — has no harness today. The detectors (DeBERTa,
PromptGuard, the optional LLM judge) are statistical classifiers; each
has a false-positive rate that needs to be measured per detector
configuration so operators can pick a sane combination.

A red-team-only metric is misleading. A detector that blocks 100% of
attacks AND 30% of legitimate emails is useless in production.

## Decision

Add `bulwark_falsepos` — a sibling CLI alongside `bulwark_bench` that
runs a curated benign corpus through `/v1/clean` and reports the
false-positive rate per detector configuration.

### Corpus

A versioned JSONL file `spec/falsepos_corpus.jsonl` ships with the
project. Each entry:

```json
{
  "id": "email-001",
  "category": "everyday",
  "subject": "Meeting moved to Thursday",
  "body": "Hey team — heads up that the design review is now Thursday at 2pm…"
}
```

Categories represent realistic input shapes the detectors have been
seen to over-block on:

- `everyday`           — ordinary office email
- `customer_support`   — refund requests, complaints
- `marketing`          — newsletter snippets, product launches
- `technical`          — code review, bug reports, RFCs
- `meta`               — emails *about* prompt injection (security
                        advisories, blog drafts) — high false-positive risk
- `repetitive`         — list emails, status updates with similar lines
                        (DeBERTa over-blocks repetitive prose)
- `non_english`        — Spanish, French, Mandarin, Arabic snippets
- `code_blocks`        — emails with embedded snippets, JSON, HTML
- `quoted_attacks`     — emails *quoting* attacker payloads in context
                        ("a phishing email said: 'ignore previous
                        instructions'") — these MUST pass

Initial seed: ~50 entries across categories. The corpus is meant to
grow over time as users contribute false positives they encounter.

### CLI

```
bulwark_falsepos \
  --configs deberta-only,deberta+promptguard \
  --bulwark http://localhost:3001 \
  --corpus spec/falsepos_corpus.jsonl \
  --output benchmarks/falsepos-2026-04-23
```

Same per-config sweep mechanic as `bulwark_bench`: apply config, run
the corpus through `/v1/clean`, persist per-config results, sort, write
report.json + report.md.

### Reported metrics

Per configuration:
- `total` — corpus size
- `blocked` — count of `/v1/clean` 422s
- `false_positive_rate` — blocked / total
- `blocked_by_category` — breakdown
- `blocked_emails` — list of `(id, blocking_layer, reason)` so operators
  can inspect individual misclassifications

Markdown report sorts by `false_positive_rate ASC` (fewer FPs is
better). When run in conjunction with a red-team report, the two
metrics together let operators pick a config: "DeBERTa+PromptGuard
gives 100% defense and 4% FP rate; DeBERTa alone gives 100% / 1%."

### Pass / fail thresholds

Default: no hard threshold. The harness is informational. CI users can
add `--max-fp-rate 0.05` to fail the build when a config exceeds 5%.

## Consequences

### Positive
- Operators can finally measure both halves of detector quality.
- Corpus is plain JSONL — easy to extend, easy to diff.
- `quoted_attacks` category specifically tests the false-positive
  surface our users keep hitting (security blog posts, post-mortems,
  documentation).

### Negative
- Curated corpus is biased by who wrote it. Mitigated by (a) inviting
  contributions and (b) categorizing entries so over-fit is visible.
- /v1/clean cost: detector latency × corpus size per config. A 50-entry
  corpus × 3 configs is ~minutes; not a CI cost concern.

### Neutral
- Harness lives alongside `bulwark_bench` (same dashboard-API shape,
  same restore-on-finally pattern). Sharing the bench's config presets
  means new presets land in both at once.
- Initial corpus is intentionally small. The threshold to "trust the
  number" is corpus size; this gets called out in the markdown report.
