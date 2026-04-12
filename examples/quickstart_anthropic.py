"""Quickstart: Bulwark + Anthropic SDK.

Protects untrusted content before it reaches your Claude-powered agent.
Pipeline sanitizes input, wraps trust boundaries, guards Phase 1 output,
and only then passes to Phase 2 for execution.

Requirements: pip install anthropic bulwark
"""
import anthropic
from bulwark.integrations.anthropic import make_pipeline

# One line to create a fully-defended pipeline
pipeline = make_pipeline(anthropic.Anthropic())  # uses ANTHROPIC_API_KEY env var

# Run untrusted content through all defense layers
result = pipeline.run(
    "Hi Nathan, board meeting moved to Thursday at 2pm.",
    source="email",
)

if result.blocked:
    print(f"BLOCKED: {result.block_reason}")
else:
    print(f"Analysis: {result.analysis}")
    print(f"Execution: {result.execution}")
    for step in result.trace:
        print(f"  [{step['layer']}] {step['verdict']}: {step['detail']}")
