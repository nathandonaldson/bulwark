"""Bulwark integrations with LLM providers and testing tools.

Each integration is a separate module with its own SDK dependency.
Import directly from the submodule:

    from bulwark.integrations.anthropic import protect, make_pipeline
    from bulwark.integrations.anthropic import make_analyze_fn, make_execute_fn
    from bulwark.integrations.garak import GarakAdapter, import_garak_results
"""
