"""Quickstart: Bulwark with any LLM.

Any function with signature (str) -> str works as an analyze_fn.
Use this pattern for local models, custom APIs, or testing.

Requirements: pip install bulwark
"""
from bulwark import Pipeline


def my_llm_call(prompt: str) -> str:
    """Replace this with your actual LLM call."""
    return '{"classification": "safe", "summary": "Meeting reschedule"}'


pipeline = Pipeline.default(analyze_fn=my_llm_call)
result = pipeline.run("Board meeting moved to Thursday.", source="document")

if result.blocked:
    print(f"BLOCKED: {result.block_reason}")
else:
    print(f"Analysis: {result.analysis}")
    for step in result.trace:
        print(f"  [{step['layer']}] {step['verdict']}: {step['detail']}")
