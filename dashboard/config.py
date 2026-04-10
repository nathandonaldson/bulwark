"""Runtime configuration for Bulwark Dashboard."""
from __future__ import annotations
import json
import yaml
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Optional

CONFIG_PATH = Path("bulwark-config.yaml")

# Default AnalysisGuard patterns (must match executor.py defaults)
DEFAULT_PATTERNS = [
    r'(?i)\bignore\s+(all\s+)?previous\s+instructions?\b',
    r'(?i)\bdisregard\b.*\binstructions?\b',
    r'(?i)\bnew\s+(system\s+)?instructions?\b',
    r'(?i)\byou\s+are\s+now\b',
    r'(?i)\badmin\s+mode\b',
    r'</analysis_output>',
    r'</?system',
    r'</?trusted',
    r'(?i)\btool_use\b',
    r'(?i)\bfunction_call\b',
    r'(?i)\btool_calls?\b',
]

AVAILABLE_INTEGRATIONS = {
    "promptguard": {
        "name": "PromptGuard-86M",
        "type": "detection",
        "description": "Meta's fine-tuned mDeBERTa classifier for prompt injection detection",
        "model": "meta-llama/Prompt-Guard-86M",
        "latency_ms": 50,
        "size_mb": 184,
    },
    "piguard": {
        "name": "PIGuard",
        "type": "detection",
        "description": "Lower false-positive rate prompt injection detector",
        "model": "piguard/piguard",
        "latency_ms": 45,
        "size_mb": 184,
    },
    "llm_guard": {
        "name": "LLM Guard",
        "type": "detection",
        "description": "Input/output scanners for PII, toxicity, and prompt injection",
        "package": "llm-guard",
        "latency_ms": 120,
        "size_mb": None,
    },
    "nemo": {
        "name": "NeMo Guardrails",
        "type": "detection",
        "description": "NVIDIA's programmable rails for conversation flow control",
        "package": "nemoguardrails",
        "latency_ms": 200,
        "size_mb": None,
    },
    "garak": {
        "name": "Garak",
        "type": "testing",
        "description": "LLM vulnerability scanner with hundreds of attack probes",
        "package": "garak",
        "latency_ms": None,
        "size_mb": None,
    },
    "promptfoo": {
        "name": "Promptfoo",
        "type": "testing",
        "description": "LLM testing and red-teaming framework",
        "package": "promptfoo",
        "latency_ms": None,
        "size_mb": None,
    },
}


@dataclass
class IntegrationConfig:
    enabled: bool = False
    installed: bool = False
    last_used: Optional[float] = None


@dataclass
class BulwarkConfig:
    # Layer toggles
    sanitizer_enabled: bool = True
    trust_boundary_enabled: bool = True
    guard_bridge_enabled: bool = True
    sanitize_bridge_enabled: bool = True
    require_json: bool = False
    canary_enabled: bool = True
    encoding_resistant: bool = True
    normalize_unicode: bool = False
    strip_emoji_smuggling: bool = True
    strip_bidi: bool = True

    # AnalysisGuard
    guard_patterns: list[str] = field(default_factory=lambda: list(DEFAULT_PATTERNS))
    guard_max_length: int = 5000

    # Canary tokens
    canary_tokens: dict[str, str] = field(default_factory=dict)
    canary_file: str = ""

    # Integrations
    integrations: dict[str, IntegrationConfig] = field(default_factory=dict)

    def to_dict(self) -> dict:
        d = asdict(self)
        return d

    def save(self, path: str = None):
        p = Path(path) if path else CONFIG_PATH
        # Convert to plain dict for yaml serialization
        d = self.to_dict()
        p.write_text(yaml.dump(d, default_flow_style=False, sort_keys=False))

    @classmethod
    def load(cls, path: str = None) -> "BulwarkConfig":
        p = Path(path) if path else CONFIG_PATH
        if not p.exists():
            return cls()
        try:
            data = yaml.safe_load(p.read_text()) or {}
            # Reconstruct IntegrationConfig objects
            integrations = {}
            for k, v in data.pop("integrations", {}).items():
                if isinstance(v, dict):
                    integrations[k] = IntegrationConfig(**v)
                else:
                    integrations[k] = IntegrationConfig()
            return cls(integrations=integrations, **{k: v for k, v in data.items() if k in cls.__dataclass_fields__})
        except Exception:
            return cls()

    def update_from_dict(self, data: dict):
        """Update config fields from a dictionary (partial update)."""
        for key, value in data.items():
            if key == "integrations":
                for int_name, int_data in value.items():
                    if isinstance(int_data, dict):
                        if int_name not in self.integrations:
                            self.integrations[int_name] = IntegrationConfig()
                        for k, v in int_data.items():
                            if hasattr(self.integrations[int_name], k):
                                setattr(self.integrations[int_name], k, v)
            elif hasattr(self, key):
                setattr(self, key, value)
