"""Detector-configuration presets for bulwark_bench (ADR-034).

Each preset names which optional detectors to layer on top of DeBERTa
(which is mandatory in v2). The runner applies the preset to the
dashboard via PUT /api/config + integrations endpoints.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class DetectorConfig:
    """A named detector configuration."""
    slug: str
    name: str
    deberta: bool = True            # Always True; mandatory in v2.
    promptguard: bool = False
    llm_judge: bool = False

    def description(self) -> str:
        bits = ["DeBERTa"]
        if self.promptguard: bits.append("PromptGuard")
        if self.llm_judge:   bits.append("LLM judge")
        return " + ".join(bits)


PRESETS: dict[str, DetectorConfig] = {
    "deberta-only": DetectorConfig(
        slug="deberta-only",
        name="DeBERTa only",
    ),
    "deberta+promptguard": DetectorConfig(
        slug="deberta+promptguard",
        name="DeBERTa + PromptGuard",
        promptguard=True,
    ),
    "deberta+llm-judge": DetectorConfig(
        slug="deberta+llm-judge",
        name="DeBERTa + LLM judge",
        llm_judge=True,
    ),
    "all": DetectorConfig(
        slug="all",
        name="DeBERTa + PromptGuard + LLM judge",
        promptguard=True,
        llm_judge=True,
    ),
}


def parse_configs(arg: str) -> list[DetectorConfig]:
    """Parse a comma-separated list of preset slugs.

    Raises ValueError on unknown slugs so the CLI can surface a clean error.
    """
    out: list[DetectorConfig] = []
    seen: set[str] = set()
    for slug in (s.strip() for s in arg.split(",") if s.strip()):
        if slug not in PRESETS:
            raise ValueError(
                f"unknown preset {slug!r}. Available: {', '.join(sorted(PRESETS))}"
            )
        if slug in seen:
            continue
        seen.add(slug)
        out.append(PRESETS[slug])
    if not out:
        raise ValueError("no presets specified")
    return out
