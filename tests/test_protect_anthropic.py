"""Tests for protect() Anthropic wrapper. Uses mock client — no API calls."""
import pytest
from unittest.mock import MagicMock
from dataclasses import dataclass


# ---------------------------------------------------------------------------
# Mock Anthropic response structure (matches test_anthropic_integration.py)
# ---------------------------------------------------------------------------

@dataclass
class MockContentBlock:
    text: str
    type: str = "text"


@dataclass
class MockMessage:
    content: list
    role: str = "assistant"


def make_mock_client(response_text="mock response"):
    """Create a mock Anthropic client that returns the given text."""
    client = MagicMock()
    client.messages.create.return_value = MockMessage(
        content=[MockContentBlock(text=response_text)]
    )
    return client


# ---------------------------------------------------------------------------
# TestProtect
# ---------------------------------------------------------------------------

class TestProtect:
    def test_returns_proxy(self):
        """protect() returns a ProtectedAnthropicClient."""
        from bulwark.integrations.anthropic import protect, ProtectedAnthropicClient
        client = make_mock_client()
        protected = protect(client)
        assert isinstance(protected, ProtectedAnthropicClient)

    def test_messages_create_works(self):
        """Protected client.messages.create() calls through to real client."""
        from bulwark.integrations.anthropic import protect
        client = make_mock_client("response")
        protected = protect(client)
        result = protected.messages.create(
            model="claude-sonnet-4-5",
            max_tokens=100,
            messages=[{"role": "user", "content": "hello"}],
        )
        assert client.messages.create.called
        assert result.content[0].text == "response"

    def test_sanitizes_user_content(self):
        """User message content is sanitized (zero-width chars removed)."""
        from bulwark.integrations.anthropic import protect
        client = make_mock_client()
        protected = protect(client)
        protected.messages.create(
            model="claude-sonnet-4-5",
            max_tokens=100,
            messages=[{"role": "user", "content": "hello\u200bworld"}],
        )
        call_kwargs = client.messages.create.call_args.kwargs
        user_content = call_kwargs["messages"][0]["content"]
        assert "\u200b" not in user_content

    def test_adds_trust_boundary_tags(self):
        """User message content is wrapped in trust boundary tags."""
        from bulwark.integrations.anthropic import protect
        client = make_mock_client()
        protected = protect(client)
        protected.messages.create(
            model="claude-sonnet-4-5",
            max_tokens=100,
            messages=[{"role": "user", "content": "hello"}],
        )
        call_kwargs = client.messages.create.call_args.kwargs
        user_content = call_kwargs["messages"][0]["content"]
        assert "<untrusted_user_input" in user_content
        assert "</untrusted_user_input>" in user_content

    def test_assistant_messages_untouched(self):
        """Assistant-role messages are not modified."""
        from bulwark.integrations.anthropic import protect
        client = make_mock_client()
        protected = protect(client)
        protected.messages.create(
            model="claude-sonnet-4-5",
            max_tokens=100,
            messages=[
                {"role": "user", "content": "question"},
                {"role": "assistant", "content": "answer"},
            ],
        )
        call_kwargs = client.messages.create.call_args.kwargs
        assistant_msg = call_kwargs["messages"][1]
        assert assistant_msg["content"] == "answer"

    def test_custom_source(self):
        """Custom source appears in trust boundary tag."""
        from bulwark.integrations.anthropic import protect
        client = make_mock_client()
        protected = protect(client, source="email")
        protected.messages.create(
            model="claude-sonnet-4-5",
            max_tokens=100,
            messages=[{"role": "user", "content": "hello"}],
        )
        call_kwargs = client.messages.create.call_args.kwargs
        user_content = call_kwargs["messages"][0]["content"]
        assert "untrusted_email" in user_content

    def test_sanitize_disabled(self):
        """sanitize=False skips sanitization but still tags."""
        from bulwark.integrations.anthropic import protect
        client = make_mock_client()
        protected = protect(client, sanitize=False)
        protected.messages.create(
            model="claude-sonnet-4-5",
            max_tokens=100,
            messages=[{"role": "user", "content": "hello\u200bworld"}],
        )
        call_kwargs = client.messages.create.call_args.kwargs
        user_content = call_kwargs["messages"][0]["content"]
        # Trust boundary tags should be present
        assert "<untrusted_" in user_content
        # Zero-width char should still be there since sanitize is off
        assert "\u200b" in user_content

    def test_tag_disabled(self):
        """tag=False skips trust boundary wrapping but still sanitizes."""
        from bulwark.integrations.anthropic import protect
        client = make_mock_client()
        protected = protect(client, tag=False)
        protected.messages.create(
            model="claude-sonnet-4-5",
            max_tokens=100,
            messages=[{"role": "user", "content": "hello\u200bworld"}],
        )
        call_kwargs = client.messages.create.call_args.kwargs
        user_content = call_kwargs["messages"][0]["content"]
        assert "<untrusted_" not in user_content
        # But zero-width chars should be stripped
        assert "\u200b" not in user_content

    def test_unwrap_returns_original(self):
        """unwrap() returns the original client."""
        from bulwark.integrations.anthropic import protect
        client = make_mock_client()
        protected = protect(client)
        assert protected.unwrap() is client

    def test_non_messages_attrs_delegated(self):
        """Non-messages attributes are delegated to the wrapped client."""
        from bulwark.integrations.anthropic import protect
        client = make_mock_client()
        client.api_key = "test-key"
        protected = protect(client)
        assert protected.api_key == "test-key"

    def test_multipart_text_content_sanitized(self):
        """Multi-part content blocks with type='text' are sanitized."""
        from bulwark.integrations.anthropic import protect
        client = make_mock_client()
        protected = protect(client)
        protected.messages.create(
            model="claude-sonnet-4-5",
            max_tokens=100,
            messages=[{
                "role": "user",
                "content": [
                    {"type": "text", "text": "hello\u200bworld"},
                    {"type": "image", "source": {"data": "base64..."}},
                ],
            }],
        )
        call_kwargs = client.messages.create.call_args.kwargs
        text_block = call_kwargs["messages"][0]["content"][0]
        assert "\u200b" not in text_block["text"]
        assert "<untrusted_" in text_block["text"]
        # Image block should be untouched
        image_block = call_kwargs["messages"][0]["content"][1]
        assert image_block["type"] == "image"

    def test_tool_result_content_sanitized(self):
        """tool_result content blocks are sanitized (untrusted external data)."""
        from bulwark.integrations.anthropic import protect
        client = make_mock_client()
        protected = protect(client)
        protected.messages.create(
            model="claude-sonnet-4-5",
            max_tokens=100,
            messages=[{
                "role": "user",
                "content": [
                    {"type": "tool_result", "tool_use_id": "abc",
                     "content": "scraped <script>evil()</script> page"},
                ],
            }],
        )
        call_kwargs = client.messages.create.call_args.kwargs
        tool_block = call_kwargs["messages"][0]["content"][0]
        assert "<script>" not in tool_block["content"]
        assert "<untrusted_" in tool_block["content"]

    def test_tool_result_nested_content_sanitized(self):
        """tool_result with list content blocks are recursively sanitized."""
        from bulwark.integrations.anthropic import protect
        client = make_mock_client()
        protected = protect(client)
        protected.messages.create(
            model="claude-sonnet-4-5",
            max_tokens=100,
            messages=[{
                "role": "user",
                "content": [
                    {"type": "tool_result", "tool_use_id": "abc",
                     "content": [
                         {"type": "text", "text": "nested\u200btext"},
                     ]},
                ],
            }],
        )
        call_kwargs = client.messages.create.call_args.kwargs
        tool_block = call_kwargs["messages"][0]["content"][0]
        nested_text = tool_block["content"][0]
        assert "\u200b" not in nested_text["text"]
        assert "<untrusted_" in nested_text["text"]

    def test_streaming_passes_through(self):
        """stream=True kwarg is passed through unchanged."""
        from bulwark.integrations.anthropic import protect
        client = make_mock_client()
        protected = protect(client)
        protected.messages.create(
            model="claude-sonnet-4-5",
            max_tokens=100,
            stream=True,
            messages=[{"role": "user", "content": "hello"}],
        )
        call_kwargs = client.messages.create.call_args.kwargs
        assert call_kwargs["stream"] is True
        # User content should still be sanitized
        assert "<untrusted_" in call_kwargs["messages"][0]["content"]
