"""Quickstart: Bulwark + OpenAI SDK.

Wrap any OpenAI call in a lambda to create an analyze_fn.
Pipeline handles sanitization, trust boundaries, and output guards.

Requirements: pip install openai bulwark
"""
from openai import OpenAI
from bulwark import Pipeline

client = OpenAI()  # uses OPENAI_API_KEY env var

# Lambda wraps the OpenAI call into a simple (str) -> str function
pipeline = Pipeline.default(
    analyze_fn=lambda prompt: client.chat.completions.create(
        model="gpt-4o",
        messages=[{"role": "user", "content": prompt}],
    ).choices[0].message.content
)

# Run untrusted content through all defense layers
result = pipeline.run(
    "Hi Nathan, board meeting moved to Thursday at 2pm.",
    source="email",
)

if result.blocked:
    print(f"BLOCKED: {result.block_reason}")
else:
    print(f"Analysis: {result.analysis}")
    for step in result.trace:
        print(f"  [{step['layer']}] {step['verdict']}: {step['detail']}")
