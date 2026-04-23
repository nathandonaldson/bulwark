# ADR-032: Chunk long inputs across the detector's token window

**Status:** Accepted
**Date:** 2026-04-23

## Context

The DeBERTa classifier (`protectai/deberta-v3-base-prompt-injection-v2`) has
a 512-token input limit. The HuggingFace `text-classification` pipeline
silently truncates inputs over that limit, so every byte past ~2 KB of
English text is invisible to the detector. `/v1/clean` accepts up to 1 MB
per `CleanRequest.content`, so a 16 KB payload passes through the detector
with only its first few paragraphs classified — a clear gap between what
Bulwark appears to check and what it actually checks.

## Decision

Chunk the sanitized input into overlapping 512-token windows, classify each
window independently, and block if **any** window is flagged as injection
above the configured threshold. Concretely:

- Use the detector's own tokenizer so the window matches what the model
  would have seen had the input fit. No character-length heuristic.
- Window size: the tokenizer's `model_max_length` (512 for DeBERTa),
  minus 2 for the special `[CLS]`/`[SEP]` tokens → 510 content tokens.
- Stride: 64 tokens of overlap between windows so an injection phrase that
  straddles a window boundary still lands wholly inside one neighbour.
- Classification is run in a single batched call per input to avoid
  per-window Python overhead (DeBERTa on MPS batches ~16 windows in the
  same wall-clock as one).
- Inputs short enough to fit in one window behave exactly as before — no
  regression for the common case.

## Consequences

### Positive
- The detector actually looks at the whole payload instead of the first
  ~2 KB. Closes the quiet false-negative surface.
- One trace entry per `/v1/clean` still; chunk count is stored in the
  trace `detail` for observability.
- Deterministic: same bytes in → same verdict out, regardless of batch
  ordering (we OR the per-chunk verdicts).

### Negative
- Latency scales with payload size. A 16 KB input needs ~8 windows
  (depending on tokenization density); batched DeBERTa inference on MPS
  stays under ~200 ms in practice but this is no longer O(1).
- Memory: batched inference holds all windows in VRAM/MPS at once. The
  1 MB `CleanRequest` ceiling translates to ~500 windows worst-case. We
  cap the batch at 32 and iterate — documented in the contract.

### Neutral
- Threshold semantics unchanged. The response `detector.score` is the
  **max** score across windows; `detector.label` is SAFE iff every
  window passed, INJECTION otherwise.
- No change to the PromptGuard opt-in path — the same chunking wrapper
  is applied uniformly to any transformers text-classification pipeline.
