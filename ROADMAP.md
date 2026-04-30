# Bulwark Roadmap

See [`VERSION`](VERSION) for the current shipped version and
[`CHANGELOG.md`](CHANGELOG.md) for the full release history.

## Current state (v2.5.x)

Detection-only architecture (ADR-031). The pipeline runs sanitizer →
DeBERTa (mandatory) → optional PromptGuard → optional LLM Judge → trust
boundary. Docker distribution. FastAPI dashboard + React/Babel JSX UI
compiled in-browser. Spec-driven development enforced in CI via
`tests/test_spec_compliance.py`.

### Shipped

See [`CHANGELOG.md`](CHANGELOG.md).

### Next

- **Long-range dilution mitigation** — follow-up to ADR-046's documented
  non-guarantee. Approach not yet decided; tracking as an open design
  question rather than a planned ADR.
- **Punycode / additional encoding decoders** — Phase H follow-ups on
  top of ADR-047 (base64 + ROT13 already shipped) and ADR-048 (shared
  chain helper). Punycode is the only sub-item from the original Phase
  H still outstanding.
- **Promptfoo CI eval pipeline** — assertion-based regression testing
  layered on top of the e2e detector lane (ADR-045).
