"""Anthropic SDK integration for Bulwark — SDK client-side protection.

v2.0.0 (ADR-031): Bulwark no longer orchestrates LLM calls. This module
now provides a single helper — ``protect()`` — which wraps an Anthropic
client so user-role message content is automatically sanitized and
trust-boundary-tagged before reaching the API.

Usage::

    import anthropic
    from bulwark.integrations.anthropic import protect

    client = protect(anthropic.Anthropic())
    response = client.messages.create(
        model="claude-sonnet-4-5",
        max_tokens=1024,
        messages=[{"role": "user", "content": untrusted_input}],
    )
"""
from __future__ import annotations

from typing import Any, Optional

from bulwark.sanitizer import Sanitizer
from bulwark.trust_boundary import TrustBoundary


def protect(
    client: Any,
    *,
    source: str = "user_input",
    sanitize: bool = True,
    tag: bool = True,
    max_length: Optional[int] = None,
) -> "ProtectedAnthropicClient":
    """Wrap an Anthropic client so untrusted message content is auto-sanitized."""
    return ProtectedAnthropicClient(
        client, source=source, sanitize=sanitize, tag=tag, max_length=max_length,
    )


class _ProtectedMessages:
    """Proxy for client.messages that intercepts create() calls."""

    def __init__(self, messages: Any, source: str, sanitize: bool, tag: bool,
                 max_length: Optional[int]):
        self._messages = messages
        self._source = source
        self._sanitizer = Sanitizer(max_length=max_length) if sanitize else None
        self._boundary = TrustBoundary() if tag else None

    def create(self, **kwargs: Any) -> Any:
        kwargs = self._process_kwargs(kwargs)
        return self._messages.create(**kwargs)

    def _process_kwargs(self, kwargs: dict) -> dict:
        kwargs = dict(kwargs)
        if "messages" in kwargs:
            kwargs["messages"] = [self._process_message(m) for m in kwargs["messages"]]
        return kwargs

    def _process_message(self, message: dict) -> dict:
        if message.get("role") != "user":
            return message
        message = dict(message)
        content = message.get("content", "")
        if isinstance(content, str):
            message["content"] = self._clean_content(content)
        elif isinstance(content, list):
            message["content"] = [self._process_content_block(b) for b in content]
        return message

    def _process_content_block(self, block: Any) -> Any:
        if not isinstance(block, dict):
            return block
        block_type = block.get("type")
        if block_type == "text":
            block = dict(block)
            block["text"] = self._clean_content(block.get("text", ""))
            return block
        if block_type == "tool_result":
            block = dict(block)
            content = block.get("content", "")
            if isinstance(content, str):
                block["content"] = self._clean_content(content)
            elif isinstance(content, list):
                block["content"] = [self._process_content_block(b) for b in content]
            return block
        return block

    def _clean_content(self, text: str) -> str:
        if self._sanitizer:
            text = self._sanitizer.clean(text)
        if self._boundary:
            text = self._boundary.wrap(text, source=self._source)
        return text

    def __getattr__(self, name: str) -> Any:
        return getattr(self._messages, name)


class ProtectedAnthropicClient:
    """Proxy for an Anthropic client that auto-sanitizes untrusted message content."""

    def __init__(self, client: Any, *, source: str, sanitize: bool, tag: bool,
                 max_length: Optional[int]):
        self._client = client
        self._source = source
        self._sanitize = sanitize
        self._tag = tag
        self._max_length = max_length

    @property
    def messages(self) -> _ProtectedMessages:
        return _ProtectedMessages(
            self._client.messages,
            source=self._source,
            sanitize=self._sanitize,
            tag=self._tag,
            max_length=self._max_length,
        )

    def unwrap(self) -> Any:
        return self._client

    def __getattr__(self, name: str) -> Any:
        return getattr(self._client, name)
