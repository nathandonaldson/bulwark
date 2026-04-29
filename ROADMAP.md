# Bulwark Roadmap

See [`VERSION`](VERSION) for the current shipped version and
[`CHANGELOG.md`](CHANGELOG.md) for the full release history.

## Current state (v2.5.x)

Detection-only architecture (ADR-031). Five-stage pipeline: Sanitizer →
DeBERTa (mandatory) → PromptGuard (optional) → LLM Judge (optional) →
Trust Boundary. 960+ tests. Docker distribution. FastAPI dashboard +
React/Babel JSX UI compiled in-browser. Spec-driven development enforced
in CI via `tests/test_spec_compliance.py`.

### Shipped highlights

- **Five-stage detection pipeline** — sanitizer + DeBERTa + optional
  PromptGuard + optional LLM Judge + trust boundary (ADR-031, ADR-032,
  ADR-033).
- **Library/dashboard parity** — `Pipeline.from_config()` reads the same
  YAML the dashboard reads and composes the same detector chain
  (ADR-044, `G-PIPELINE-PARITY-001`).
- **Fail-closed semantics** — `/v1/clean` returns HTTP 503 +
  `error.code = "no_detectors_loaded"` when zero detectors are loaded
  and the judge is disabled (ADR-040). Operators opt into sanitizer-only
  via `BULWARK_ALLOW_NO_DETECTORS=1`.
- **Byte-count content cap** — `/v1/clean.content` and `/v1/guard.text`
  are capped in bytes, not chars (ADR-042). Tunable via
  `BULWARK_MAX_CONTENT_SIZE`.
- **Auth gate decoupled from judge** — `BULWARK_API_TOKEN` enables
  Bearer auth on `/v1/clean` from non-loopback callers regardless of
  judge state (ADR-041).
- **HTTP API** — `/v1/clean`, `/v1/guard`, `/healthz`, dashboard `/api/*`.
  Source of truth: `spec/openapi.yaml`.
- **Sister CLIs** — `bulwark_bench` for detector-config bake-offs
  (ADR-034), `bulwark_falsepos` for false-positive measurement
  (ADR-036). False-positive harness surfaced as the 4th tier card on
  the dashboard's Test page.
- **Real-detector e2e CI lane** — nightly cron + per-PR job exercises
  the canonical injections against real ProtectAI DeBERTa weights
  (ADR-045).
- **Split-evasion test coverage** — short-range gap is a guarantee
  (`G-DETECTOR-WINDOW-EVASION-001`); long-range dilution is documented
  as a non-guarantee (`NG-DETECTOR-WINDOW-EVASION-001`, ADR-046).
- **Docker hardening** — multi-stage build, non-root user, no build
  tools in final image (ADR-019).
- **OpenClaw integration** — Docker sidecar + npm plugin with
  infrastructure-level hooks (ADR-011).
- **Wintermute integration** — personal-agent integration via the
  Docker HTTP API (`docs/integrations/wintermute.md`).
- **Spec-driven development** — every endpoint/feature has an OpenAPI
  spec entry, a contract YAML with guarantee IDs, and an ADR (ADR-001).

### Next

- **Semantic encoding detection (Phase H, deferred)** — base64 / ROT13 /
  punycode decoding pre-pass at `/v1/clean`. Deliberately punted from
  the Codex efficacy hardening series pending its own brainstorming
  session — see Phase H in
  [`docs/superpowers/plans/2026-04-29-codex-efficacy-hardening.md`](docs/superpowers/plans/2026-04-29-codex-efficacy-hardening.md).
- **Content fingerprinting pre-pass** — strip benign filler before
  classification to mitigate the long-range dilution gap documented by
  ADR-046 (planned ADR-047).
- **Promptfoo CI eval pipeline** — assertion-based regression testing
  layered on top of the e2e detector lane.

### Future

- **Transparent proxy mode** — Bulwark as a reverse proxy between your
  app and the LLM provider. Zero-code integration.
- **CaMeL-style capability tracking** — fine-grained information flow
  control.
- **Community attack catalog growth** — expand the curated catalog
  beyond the current 77 patterns × 10 categories with contributions.
- **OpenClaw TypeScript plugin** — deeper integration via
  `before_agent_reply` hooks (version-dependent).
