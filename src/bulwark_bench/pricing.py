"""Pricing table and cost calculation.

G-BENCH-006 / G-BENCH-009 / NG-BENCH-002.

USD per 1M tokens, prompt (input) and completion (output).
Local inference defaults to $0. Unknown models also resolve to $0 with a warning.

Sources cited in comments; when provider rates change, edit this file and bump
`PRICING_TABLE_VERSION`.
"""
from __future__ import annotations

import sys
from dataclasses import dataclass


PRICING_TABLE_VERSION = "2026-04-17"


@dataclass(frozen=True)
class Pricing:
    input_per_mtok: float
    output_per_mtok: float

    @property
    def is_free(self) -> bool:
        return self.input_per_mtok == 0 and self.output_per_mtok == 0


# Case-insensitive model id → Pricing. Keys are lowercased at lookup time.
_TABLE: dict[str, Pricing] = {
    # Anthropic — public pricing
    "claude-haiku-4-5": Pricing(0.80, 4.00),
    "claude-haiku-4-5-20251001": Pricing(0.80, 4.00),
    "claude-sonnet-4-6": Pricing(3.00, 15.00),
    "claude-opus-4-6": Pricing(15.00, 75.00),
    "claude-opus-4-7": Pricing(15.00, 75.00),

    # OpenAI — representative current rates
    "gpt-4o": Pricing(2.50, 10.00),
    "gpt-4o-mini": Pricing(0.15, 0.60),
    "gpt-5": Pricing(5.00, 20.00),

    # Local inference — all free.
    "google/gemma-4-26b-a4b": Pricing(0, 0),
    "google/gemma-4-31b": Pricing(0, 0),
    "google/gemma-4-e4b": Pricing(0, 0),
    "unsloth/gemma-4-31b-it": Pricing(0, 0),
    "unsloth/gemma-4-26b-a4b-it": Pricing(0, 0),
    "qwen3.5-4b": Pricing(0, 0),
    "qwen3.5-27b": Pricing(0, 0),
    "qwen3.5-35b-a3b": Pricing(0, 0),
    "qwen2.5-vl-7b-instruct": Pricing(0, 0),
    "gpt-oss-120b": Pricing(0, 0),
}

# Prefixes that mark a local-backend model. Used when we don't have an exact hit.
_LOCAL_PREFIXES = (
    "google/gemma",
    "unsloth/",
    "qwen",
    "llama",
    "mistral",
    "phi-",
    "deepseek",
    "gpt-oss",
    "local/",
)


def lookup(model: str) -> Pricing:
    """Return pricing for a model id. $0 + warning if unknown."""
    key = model.strip().lower()
    hit = _TABLE.get(key)
    if hit is not None:
        return hit
    # Heuristic: anything that looks like a local / open-weights model → free.
    if any(key.startswith(p) for p in _LOCAL_PREFIXES):
        return Pricing(0, 0)
    # Unknown — warn and zero.
    print(
        f"[bulwark_bench] WARN: no pricing entry for model '{model}'. "
        f"Using $0/Mtok. Edit src/bulwark_bench/pricing.py to add one.",
        file=sys.stderr,
        flush=True,
    )
    return Pricing(0, 0)


def compute_cost(pricing: Pricing, prompt_tokens: int, completion_tokens: int) -> float:
    """USD cost = (tokens_in * $/Mtok_in + tokens_out * $/Mtok_out) / 1e6."""
    return (
        (prompt_tokens * pricing.input_per_mtok)
        + (completion_tokens * pricing.output_per_mtok)
    ) / 1_000_000
