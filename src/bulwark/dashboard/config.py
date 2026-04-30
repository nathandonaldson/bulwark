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


# ADR-040: shared truthy-env parser. Matches the convention used by both
# BULWARK_ALLOW_NO_DETECTORS and BULWARK_ALLOW_SANITIZE_ONLY (ADR-038).
_TRUTHY_ENV_VALUES = frozenset({"1", "true", "yes"})


def env_truthy(name: str) -> bool:
    """Return True if the named env var is set to a truthy value.

    Truthy values: 1/true/yes (case-insensitive, whitespace-tolerant).
    Anything else (including unset, "", "0", "false", "no", arbitrary
    strings) returns False — the fail-closed default.
    """
    return os.environ.get(name, "").strip().lower() in _TRUTHY_ENV_VALUES


@dataclass
class IntegrationConfig:
    enabled: bool = False
    installed: bool = False
    last_used: Optional[float] = None


# ADR-033: opt-in third detector. Default OFF. When enabled, /v1/clean
# sends sanitized input to the configured endpoint with a fixed classifier
# prompt. The judge is detection-only — its raw output never reaches the
# /v1/clean response. See spec/contracts/llm_judge.yaml.
@dataclass
class JudgeBackendConfig:
    enabled: bool = False
    mode: str = "openai_compatible"   # or "anthropic"
    base_url: str = ""
    api_key: str = ""
    model: str = ""
    threshold: float = 0.85           # confidence ≥ threshold → INJECTION block
    fail_open: bool = True            # network/parse error → log + pass
    timeout_s: float = 30.0


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

    # ADR-047 / Phase H: opt-in base64 decode-rescan in /v1/clean.
    # ROT13 is always-on (zero-FP cost — rotated normal English is gibberish
    # detectors classify SAFE) and not a config field. Env override:
    # BULWARK_DECODE_BASE64=1 routed through env_truthy() in _apply_env_vars.
    decode_base64: bool = False

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

    # ADR-033: opt-in LLM judge as a third detector.
    judge_backend: JudgeBackendConfig = field(default_factory=JudgeBackendConfig)

    def to_dict(self) -> dict:
        d = asdict(self)
        # Mask the judge API key in /api/config responses.
        jb = d.get("judge_backend") or {}
        if jb.get("api_key"):
            jb["api_key"] = self._mask(jb["api_key"])
        return d

    @staticmethod
    def _mask(key: str) -> str:
        if not key or len(key) <= 12:
            return "***" if key else ""
        return key[:7] + "..." + key[-4:]

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
        # ADR-047: BULWARK_DECODE_BASE64 opts into base64 decode-rescan.
        # Uses the same env_truthy() helper as ADR-040's
        # BULWARK_ALLOW_NO_DETECTORS so truthy-value parsing stays consistent.
        if env_truthy("BULWARK_DECODE_BASE64"):
            cfg.decode_base64 = True

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
            judge_data = data.pop("judge_backend", {}) or {}
            judge_backend = JudgeBackendConfig(**judge_data) if isinstance(judge_data, dict) else JudgeBackendConfig()
            cfg = cls(integrations=integrations, judge_backend=judge_backend,
                      **{k: v for k, v in data.items() if k in cls.__dataclass_fields__})
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

        # G-JUDGE-006: reject private-host judge URLs (same allowlist).
        if "judge_backend" in data and isinstance(data["judge_backend"], dict):
            new_url = data["judge_backend"].get("base_url", "")
            if new_url:
                from bulwark.dashboard.url_validator import validate_external_url
                err = validate_external_url(new_url)
                if err:
                    return f"judge_backend.base_url rejected: {err}"

        for key, value in data.items():
            if key == "judge_backend" and isinstance(value, dict):
                for k, v in value.items():
                    if hasattr(self.judge_backend, k):
                        # Don't overwrite a real key with a masked one.
                        if k == "api_key" and isinstance(v, str) and "..." in v:
                            continue
                        setattr(self.judge_backend, k, v)
                continue
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
