# Bulwark Roadmap

## Current State (v0.2.1)

14 source modules, 617 tests, production red team validated (315/315 probes defended).

### Shipped
- 5 defense layers: Sanitizer, TrustBoundary, TwoPhaseExecutor, CanarySystem, MapReduceIsolator
- Pipeline orchestrator with async support
- 77 attack patterns across 10 categories
- Production red team runner (Garak probes through real Bulwark+Claude pipeline)
- ProtectAI DeBERTa detection integration (ungated, 99.99% accuracy)
- PromptGuard-86M support (pending HuggingFace approval)
- Anthropic SDK integration
- Interactive dashboard with shield visualization, event stream, config management, red teaming
- `bulwark test` CLI with color output
- GitHub Actions CI (Python 3.11, 3.12, 3.13)
- PyPI publish workflow (tag-triggered)
- Security audited, eng reviewed, benchmarked (<1ms deterministic layers)

### v0.3.0 (next)
- **LLM Guard integration** — broader scanner coverage (PII, toxicity, prompt injection)
- **Dashboard auth** — bearer token for non-localhost deployments
- **Dashboard sync automation** — run from repo or auto-sync on commit (stop manual file copying)
- **Python 3.13 test fix** — Unicode handling edge case in isolator integration test

### Future
- **Promptfoo CI eval pipeline** — assertion-based regression testing for defenses
- **MCP/universal proxy** — Bulwark as infrastructure you deploy in front of your tools
- **LangChain integration** — first-class module if adoption warrants
- **CaMeL-style capability tracking** — fine-grained information flow control
- **More attack patterns** — expand from 77+ with community contributions

## Design Context

Extracted from production defenses in the Wintermute personal AI agent. The Wintermute agent processes email, calendar, and Slack data daily through Bulwark's pipeline. The production red team (315 Garak probes through Claude Haiku) achieved 100% defense rate.

## Running Tests

```bash
cd bulwark-ai
PYTHONPATH=src python3 -m pytest tests/ -v
```
