"""Auto-protect an Anthropic client with one line.

protect() wraps your client so every messages.create() call auto-sanitizes
user message content and tool_result content blocks.

Requires: pip install bulwark-shield[anthropic]
"""
import anthropic
from bulwark.integrations.anthropic import protect

# One line: wrap your existing client
client = protect(anthropic.Anthropic())

# Use it exactly like before — user content is auto-sanitized
response = client.messages.create(
    model="claude-sonnet-4-5",
    max_tokens=1024,
    messages=[
        {"role": "user", "content": "Summarize this email: <untrusted content here>"},
    ],
)
print(response.content[0].text)

# The original client is accessible via unwrap()
original = client.unwrap()
