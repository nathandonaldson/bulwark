"""Runtime configuration for Bulwark Dashboard.

v2.0.0 (ADR-031): LLM backend removed. Bulwark returns safe content or an
error; it never calls an LLM.
"""
from __future__ import annotations
import os
import yaml
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Optional

CONFIG_PATH = Path("bulwark-config.yaml")

# Default PatternGuard patterns (must match guard.py defaults)
DEFAULT_PATTERNS = [
    r'(?i)\bignore\s+(all\s+)?previous\s+instructions?\b',
    r'(?i)\bdisregard\b.{0,100}\binstructions?\b',
    r'(?i)\bnew\s+(system\s+)?instructions?\b',
    r'(?i)\byou\s+are\s+now\b',
    r'(?i)\badmin\s+mode\b',
    r'(?i)</untrusted_',
    r'(?i)</?system',
    r'(?i)</?trusted',
    r'(?i)^SYSTEM\s*:', r'(?i)\nSYSTEM\s*:',
    r'(?i)\btool_use\b',
    r'(?i)\bfunction_call\b',
    r'(?i)\btool_calls?\b',
    r'忽略.{0,100}指令', r'تجاهل.{0,100}تعليمات',
    r'(?i)\bforward\s+all\b.{0,100}\b(email|data|contact)',
    r'(?i)\bsend\s+all\b.{0,100}\b(data|email|contact)',
]

AVAILABLE_INTEGRATIONS = {
    "protectai": {
        "name": "ProtectAI DeBERTa",
        "type": "detection",
        "description": "Prompt injection classifier. Ungated, works immediately. Mandatory in v2.",
        "model": "protectai/deberta-v3-base-prompt-injection-v2",
        "latency_ms": 30,
        "size_mb": 180,
    },
    "promptguard": {
        "name": "PromptGuard-86M",
        "type": "detection",
        "description": "Meta's mDeBERTa classifier for prompt injection. Optional second-opinion detector. Requires HuggingFace approval.",
        "model": "meta-llama/Prompt-Guard-86M",
        "latency_ms": 50,
        "size_mb": 184,
        "gated": True,
    },
    "garak": {
        "name": "Garak",
        "type": "testing",
        "description": "LLM vulnerability scanner with hundreds of attack probes",
        "package": "garak",
        "latency_ms": None,
        "size_mb": None,
    },
}


def get_api_token() -> str:
    """Read BULWARK_API_TOKEN from environment. Returns empty string if not set."""
    return os.environ.get("BULWARK_API_TOKEN", "")


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
    canary_enabled: bool = True
    encoding_resistant: bool = True
    normalize_unicode: bool = False
    strip_emoji_smuggling: bool = True
    strip_bidi: bool = True

    # PatternGuard (regex patterns used by /v1/guard, not on input)
    guard_patterns: list[str] = field(default_factory=lambda: list(DEFAULT_PATTERNS))
    guard_max_length: int = 5000

    # Canary tokens (output-side only — checked by /v1/guard)
    canary_tokens: dict[str, str] = field(default_factory=dict)
    canary_file: str = ""

    # External webhook for BLOCKED-event alerting (ADR-026).
    webhook_url: str = ""

    # Integrations
    integrations: dict[str, IntegrationConfig] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)

    def save(self, path: str = None):
        p = Path(path) if path else CONFIG_PATH
        d = asdict(self)
        # G-WEBHOOK-006: env-shadowing for webhook_url
        if os.environ.get("BULWARK_WEBHOOK_URL") and "webhook_url" in d:
            d["webhook_url"] = ""
        p.write_text(yaml.dump(d, default_flow_style=False, sort_keys=False))

    @classmethod
    def _apply_env_vars(cls, cfg: "BulwarkConfig") -> None:
        """Apply BULWARK_* env vars to config."""
        webhook = os.environ.get("BULWARK_WEBHOOK_URL")
        if webhook is not None:
            cfg.webhook_url = webhook

    @classmethod
    def load(cls, path: str = None) -> "BulwarkConfig":
        p = Path(path) if path else CONFIG_PATH
        if not p.exists():
            cfg = cls()
            cls._apply_env_vars(cfg)
            return cfg
        try:
            data = yaml.safe_load(p.read_text()) or {}
            # Drop legacy v1 llm_backend field if present
            data.pop("llm_backend", None)
            # Drop legacy bridge fields
            data.pop("guard_bridge_enabled", None)
            data.pop("sanitize_bridge_enabled", None)
            data.pop("require_json", None)
            integrations = {}
            for k, v in data.pop("integrations", {}).items():
                if isinstance(v, dict):
                    integrations[k] = IntegrationConfig(**v)
                else:
                    integrations[k] = IntegrationConfig()
            cfg = cls(integrations=integrations, **{k: v for k, v in data.items() if k in cls.__dataclass_fields__})
            cls._apply_env_vars(cfg)
            return cfg
        except Exception:
            cfg = cls()
            cls._apply_env_vars(cfg)
            return cfg

    def update_from_dict(self, data: dict) -> str | None:
        """Update config fields from a dictionary (partial update).

        Returns an error string if the update is rejected, None on success.
        """
        # Reject updates that disable sanitizer AND trust boundary
        core_layers = ("sanitizer_enabled", "trust_boundary_enabled")
        proposed = {k: data.get(k, getattr(self, k)) for k in core_layers}
        if not any(proposed.values()):
            return "Cannot disable all core defense layers simultaneously. At least one of sanitizer or trust boundary must stay enabled."

        # G-WEBHOOK-007: reject private-host webhook URLs
        if "webhook_url" in data and data["webhook_url"]:
            from bulwark.dashboard.url_validator import validate_external_url
            err = validate_external_url(data["webhook_url"])
            if err:
                return f"webhook_url rejected: {err}"

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
        return None
