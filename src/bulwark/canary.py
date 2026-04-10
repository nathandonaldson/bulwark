"""Canary token system for detecting data exfiltration."""
from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import secrets
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


@dataclass
class CanaryCheckResult:
    """Result of checking text for canary token leaks."""
    leaked: bool
    found_tokens: list[str] = field(default_factory=list)
    sources: list[str] = field(default_factory=list)


class CanaryLeakError(Exception):
    """Raised when a canary token is detected in output."""
    def __init__(self, result: CanaryCheckResult):
        self.result = result
        sources = ", ".join(result.sources)
        super().__init__(f"Canary token leaked from: {sources}")


@dataclass
class CanarySystem:
    """Embed, detect, and alert on canary token leaks.

    Canary tokens are unique strings placed in sensitive data stores.
    If an LLM's output contains a canary token, it indicates the model
    was manipulated into exfiltrating protected content.
    """
    tokens: dict[str, str] = field(default_factory=dict)  # source_name -> token
    prefix: str = "BLWK-CANARY"
    encoding_resistant: bool = True

    def generate(self, source_name: str) -> str:
        """Generate and store a new canary token for a source.

        Args:
            source_name: Identifier for what this token protects (e.g., "user_data", "config")

        Returns:
            The generated token string
        """
        suffix = secrets.token_hex(3)  # 6 hex chars
        tag = source_name.upper().replace(" ", "-").replace("_", "-")[:10]
        token = f"{self.prefix}-{tag}-{suffix}"
        self.tokens[source_name] = token
        return token

    def get(self, source_name: str) -> Optional[str]:
        """Get the token for a source, or None if not set."""
        return self.tokens.get(source_name)

    def check(self, text: str) -> CanaryCheckResult:
        """Check text for any canary token leaks.

        Args:
            text: The LLM output or outbound message to check

        Returns:
            CanaryCheckResult with leaked=True if any tokens found
        """
        if not text or not self.tokens:
            return CanaryCheckResult(leaked=False)

        found_tokens = []
        sources = []
        for source_name, token in self.tokens.items():
            if token in text:
                found_tokens.append(token)
                sources.append(source_name)
            elif self.encoding_resistant and self._check_encoded(text, token):
                found_tokens.append(token)
                sources.append(source_name)

        return CanaryCheckResult(
            leaked=bool(found_tokens),
            found_tokens=found_tokens,
            sources=sources,
        )

    def _check_encoded(self, text: str, token: str) -> bool:
        """Check for encoded variants of a canary token.

        Detects base64, hex, reversed, case-insensitive, and spaced-out encodings.
        """
        # Case-insensitive
        if token.lower() in text.lower():
            return True
        # Base64
        try:
            b64 = base64.b64encode(token.encode()).decode()
            if b64 in text:
                return True
        except Exception:
            pass
        # Hex
        hex_token = token.encode().hex()
        if hex_token in text.lower():
            return True
        # Reversed
        if token[::-1] in text:
            return True
        # Spaced out (with common separators)
        spaced_pattern = re.compile(
            r'[\s.\-_]'.join(re.escape(c) for c in token)
        )
        if spaced_pattern.search(text):
            return True
        return False

    def guard(self, func):
        """Decorator that checks function's first string argument for canary leaks.

        Raises CanaryLeakError if any canary tokens are detected.
        """
        def wrapper(*args, **kwargs):
            # Check all string arguments
            for arg in args:
                if isinstance(arg, str):
                    result = self.check(arg)
                    if result.leaked:
                        raise CanaryLeakError(result)
            for val in kwargs.values():
                if isinstance(val, str):
                    result = self.check(val)
                    if result.leaked:
                        raise CanaryLeakError(result)
            return func(*args, **kwargs)
        return wrapper

    def embed_comment(self, source_name: str, format: str = "html") -> str:
        """Generate an embeddable comment containing the canary token.

        Args:
            source_name: Which source this protects
            format: "html" for <!-- -->, "markdown" for [//]: #, "yaml" for # comment

        Returns:
            Formatted comment string ready to embed in a file
        """
        token = self.tokens.get(source_name)
        if not token:
            token = self.generate(source_name)

        if format == "html":
            return f"<!-- {token} -->"
        elif format == "markdown":
            return f"[//]: # ({token})"
        elif format == "yaml":
            return f"# {token}"
        else:
            return token

    def save(self, path: str) -> None:
        """Save tokens to a JSON file."""
        Path(path).write_text(json.dumps(self.tokens, indent=2))

    @classmethod
    def from_file(cls, path: str, prefix: str = "BLWK-CANARY") -> "CanarySystem":
        """Load tokens from a JSON file."""
        tokens = json.loads(Path(path).read_text())
        return cls(tokens=tokens, prefix=prefix)

    @classmethod
    def from_dict(cls, tokens: dict[str, str], prefix: str = "BLWK-CANARY") -> "CanarySystem":
        """Create from a dictionary of source_name -> token mappings."""
        return cls(tokens=dict(tokens), prefix=prefix)
