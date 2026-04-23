"""Runtime configuration for Bulwark Dashboard."""
from __future__ import annotations
import json
import os
import yaml
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import ClassVar, Optional

# Relative path — resolves against CWD. In Docker with WORKDIR /app, this is /app/bulwark-config.yaml.
CONFIG_PATH = Path("bulwark-config.yaml")

# Default AnalysisGuard patterns (must match executor.py defaults)
DEFAULT_PATTERNS = [
    r'(?i)\bignore\s+(all\s+)?previous\s+instructions?\b',
    r'(?i)\bdisregard\b.{0,100}\binstructions?\b',
    r'(?i)\bnew\s+(system\s+)?instructions?\b',
    r'(?i)\byou\s+are\s+now\b',
    r'(?i)\badmin\s+mode\b',
    r'</analysis_output>',
    r'</untrusted_',
    r'</?system',
    r'</?trusted',
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
        "description": "Prompt injection classifier. Ungated, works immediately. Recommended default.",
        "model": "protectai/deberta-v3-base-prompt-injection-v2",
        "latency_ms": 30,
        "size_mb": 180,
    },
    "promptguard": {
        "name": "PromptGuard-86M",
        "type": "detection",
        "description": "Meta's mDeBERTa classifier for prompt injection. Requires HuggingFace approval.",
        "model": "meta-llama/Prompt-Guard-86M",
        "latency_ms": 50,
        "size_mb": 184,
        "gated": True,
    },
    "llm_guard": {
        "name": "LLM Guard",
        "type": "detection",
        "description": "Input/output scanners for PII, toxicity, and prompt injection. Coming soon.",
        "package": "llm-guard",
        "latency_ms": 120,
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
}


def get_api_token() -> str:
    """Read BULWARK_API_TOKEN from environment. Returns empty string if not set.

    Read on every call (not cached) so token rotation doesn't need a restart.
    """
    return os.environ.get("BULWARK_API_TOKEN", "")


@dataclass
class LLMBackendConfig:
    """LLM backend configuration for two-phase pipeline execution."""
    mode: str = "none"  # none, anthropic, openai_compatible
    api_key: str = ""
    base_url: str = ""  # For openai_compatible mode (e.g., http://localhost:8080/v1)
    analyze_model: str = ""  # Phase 1 model (cheap/fast)
    execute_model: str = ""  # Phase 2 model (smart), optional — falls back to analyze_model


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

    # External webhook for BLOCKED-event alerting (ADR-026, G-WEBHOOK-001..006).
    # Empty = no external POST; set to an https://… URL to fan out blocked
    # events (prompt-injection blocks, canary leaks, guard-pattern hits) to
    # Slack / PagerDuty / an internal alert router.
    webhook_url: str = ""

    # LLM Backend
    llm_backend: LLMBackendConfig = field(default_factory=LLMBackendConfig)

    # Integrations
    integrations: dict[str, IntegrationConfig] = field(default_factory=dict)

    @staticmethod
    def _mask_key(key: str) -> str:
        """Mask an API key for display: show first 7 + last 4 chars."""
        if not key or len(key) <= 12:
            return "***" if key else ""
        return key[:7] + "..." + key[-4:]

    def to_dict(self) -> dict:
        d = asdict(self)
        # Mask API key in responses — never expose the full key
        if d.get("llm_backend", {}).get("api_key"):
            d["llm_backend"]["api_key"] = self._mask_key(d["llm_backend"]["api_key"])
        return d

    # Fields in llm_backend that can be populated from env vars. Shared by
    # save() (G-ENV-013) and update_from_dict() (G-ENV-012).
    _ENV_SHADOWED_LLM_FIELDS: ClassVar[dict[str, str]] = {
        "mode": "BULWARK_LLM_MODE",
        "api_key": "BULWARK_API_KEY",
        "base_url": "BULWARK_BASE_URL",
        "analyze_model": "BULWARK_ANALYZE_MODEL",
        "execute_model": "BULWARK_EXECUTE_MODEL",
    }

    def save(self, path: str = None):
        import os
        p = Path(path) if path else CONFIG_PATH
        d = asdict(self)
        # G-ENV-013: never persist env-provided credentials to disk. Blank
        # env-shadowed fields; _apply_env_vars() refills them on next load.
        llm = d.get("llm_backend", {})
        for field, env_var in self._ENV_SHADOWED_LLM_FIELDS.items():
            if os.environ.get(env_var) and field in llm:
                llm[field] = ""
        # G-WEBHOOK-006: same env-shadowing pattern for top-level webhook_url.
        if os.environ.get("BULWARK_WEBHOOK_URL") and "webhook_url" in d:
            d["webhook_url"] = ""
        p.write_text(yaml.dump(d, default_flow_style=False, sort_keys=False))

    @classmethod
    def _apply_env_vars(cls, cfg: "BulwarkConfig") -> None:
        """Apply BULWARK_* env vars to config. Only sets fields that have an env var present."""
        import os
        env_map = {
            "BULWARK_LLM_MODE": "mode",
            "BULWARK_API_KEY": "api_key",
            "BULWARK_BASE_URL": "base_url",
            "BULWARK_ANALYZE_MODEL": "analyze_model",
            "BULWARK_EXECUTE_MODEL": "execute_model",
        }
        for env_key, field_name in env_map.items():
            val = os.environ.get(env_key)
            if val is not None:
                setattr(cfg.llm_backend, field_name, val)
        # G-WEBHOOK-006: webhook URL env-shadowing.
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
            # Reconstruct LLMBackendConfig
            llm_data = data.pop("llm_backend", {})
            llm_backend = LLMBackendConfig(**llm_data) if isinstance(llm_data, dict) else LLMBackendConfig()
            # Reconstruct IntegrationConfig objects
            integrations = {}
            for k, v in data.pop("integrations", {}).items():
                if isinstance(v, dict):
                    integrations[k] = IntegrationConfig(**v)
                else:
                    integrations[k] = IntegrationConfig()
            cfg = cls(llm_backend=llm_backend, integrations=integrations, **{k: v for k, v in data.items() if k in cls.__dataclass_fields__})
            # Env vars override config file values (so Docker .env always wins)
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
        # Reject updates that disable all core defense layers
        core_layers = ("sanitizer_enabled", "trust_boundary_enabled", "guard_bridge_enabled")
        proposed = {k: data.get(k, getattr(self, k)) for k in core_layers}
        if not any(proposed.values()):
            return "Cannot disable all core defense layers simultaneously. At least one of sanitizer, trust boundary, or guard bridge must stay enabled."

        # G-WEBHOOK-007 / ADR-030: reject webhook_url pointing at private or
        # metadata hosts at config-write time. Prevents the Codex SSRF finding
        # where an attacker who can PUT /api/config (e.g. via a compromised
        # token) points webhook_url at 169.254.169.254 and then triggers a
        # BLOCKED event to exfiltrate cloud metadata. Same validator as the
        # LLM base_url check for consistency.
        if "webhook_url" in data and data["webhook_url"]:
            from bulwark.dashboard.llm_factory import _validate_base_url
            err = _validate_base_url(data["webhook_url"])
            if err:
                return f"webhook_url rejected: {err}"

        import os
        for key, value in data.items():
            if key == "llm_backend" and isinstance(value, dict):
                for k, v in value.items():
                    if hasattr(self.llm_backend, k):
                        # Don't overwrite real key with masked value
                        if k == "api_key" and isinstance(v, str) and "..." in v:
                            continue
                        # G-ENV-012: ignore empty-string updates to env-shadowed fields.
                        # The dashboard UI renders these read-only and getLLMFormData()
                        # returns "" when the input is absent — without this guard, a
                        # Save click would clobber the env-provided value in memory.
                        env_var = self._ENV_SHADOWED_LLM_FIELDS.get(k)
                        if env_var and os.environ.get(env_var) and v == "":
                            continue
                        setattr(self.llm_backend, k, v)
            elif key == "integrations":
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
