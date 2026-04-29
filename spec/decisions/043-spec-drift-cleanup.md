# ADR-043: Spec / preset / compose drift cleanup

**Status:** Accepted
**Date:** 2026-04-29
**Related:** ADR-031 (pipeline simplification), ADR-021 (presets source of truth)

## Context

The Codex efficacy hardening review (Phase D) caught two pieces of stale
documentation that contradict the shipped implementation:

1. **`spec/presets.yaml` — XML boundary escape preset.** The preset
   description claimed:

   > Trust Boundary layer re-escapes the payload before wrapping.

   This is false. `tests/test_trust_boundary.py` proves the trust boundary
   wraps untrusted content in `<untrusted_*>` tags but does **not** escape
   XML characters in the payload — it's intentional, the wrapped content is
   for LLM consumption, not XML-parser consumption. The relevant tests:

   - `test_content_with_xml_like_characters_preserved` —
     `<script>alert("xss")</script>` round-trips unchanged inside the wrap.
   - `test_content_containing_tag_name_handled` — even
     `</untrusted_email>` inside the payload is preserved as-is, with
     a real closing tag still appended at the end.

   A user reading the preset description would expect `&lt;` / `&gt;` /
   `&amp;` substitution that the implementation never performs. This is
   pure docs drift — the preset's *intent* (test that boundary mid-content
   close-tag injection is handled) is correct, but the description's
   *mechanism* claim is wrong.

2. **`docker-compose.yml` env_file comment.** Lines 27–29 documented the
   `.env` file as providing five env vars that ADR-031 removed in v2.0.0:
   `BULWARK_LLM_MODE`, `BULWARK_API_KEY`, `BULWARK_BASE_URL`,
   `BULWARK_ANALYZE_MODEL`, `BULWARK_EXECUTE_MODEL`. v2 is detection-only;
   Bulwark never calls an LLM, and `spec/contracts/env_config.yaml` has
   already encoded these as `NG-ENV-LLM-REMOVED`. The compose comment is
   the last surviving reference and would mislead a fresh operator.

Both items contributed noise during the Codex review. Neither is a
behavioural defect — the code is right, the documentation lies.

## Decision

This is a **documentation alignment**, not a behaviour change.

### 1. Correct the preset description

`spec/presets.yaml` — `xml` preset description rewritten to describe what
the trust boundary actually does:

> Attempts to close the trust boundary tag mid-content and inject a
> forged system turn. Trust boundary wraps the entire payload (close tag
> and all) inside an outer `<untrusted_email>` block; the LLM sees the
> attacker's fake `</untrusted>` as opaque text inside the real
> boundary, not as a structural close. No XML escaping is performed —
> the wrap, plus the security instruction, plus the real outer close
> tag, is the defense.

`spec/contracts/presets.yaml` mirrors no implementation detail of the
description text, so no contract change is needed. (Verified: preset
contract guarantees describe the *load-and-serve* mechanism, not preset
description content.)

### 2. Drop deleted env vars from `docker-compose.yml`

The `env_file` comment block is rewritten to list only the env vars that
still exist post-ADR-031: `BULWARK_API_TOKEN`, `BULWARK_ALLOWED_HOSTS`,
`BULWARK_WEBHOOK_URL`, `HF_TOKEN`. Cross-references
`spec/contracts/env_config.yaml` as the canonical list.

### 3. Add a regression-prevention spec compliance test

`tests/test_spec_compliance.py::TestPresetTrustBoundaryDrift::test_no_preset_claims_xml_escaping`
fails if any preset description in `spec/presets.yaml` contains a phrase
from a curated forbidden list (`re-escape`, `reescape`, `escape payload`,
`escapes the payload`, `escapes payload`, `xml-escape`, `xml escape`).
This locks in the truth that trust-boundary tests already prove: wrap,
not escape. New phrases get appended to the list as similar drift is
discovered.

New guarantee:

- **`G-SPEC-PRESETS-NO-XML-ESCAPE-001`** — Preset descriptions in
  `spec/presets.yaml` MUST NOT claim XML escaping or payload re-escaping
  behaviour, because `tests/test_trust_boundary.py` proves the trust
  boundary wraps without escaping. Enforced by
  `TestPresetTrustBoundaryDrift::test_no_preset_claims_xml_escaping`.

The guarantee is added to `spec/contracts/presets.yaml` as
`G-PRESETS-008`-aligned drift-prevention; the human-readable ID
`G-SPEC-PRESETS-NO-XML-ESCAPE-001` is used in the test docstring so the
guarantee's purpose is self-evident at the failure site. (Bulwark's
contracts use both `G-AREA-NNN` numeric IDs and longer slug-style IDs;
the slug variant is preferred here because the assertion message reads
better in CI logs.)

## Consequences

### Positive

- Preset description no longer lies to operators about trust-boundary
  behaviour.
- `docker-compose.yml` matches the shipped env-var surface; new operators
  no longer chase phantom LLM config.
- Spec compliance test catches future occurrences of the same drift —
  copy-paste from older docs would fail CI.

### Negative

- None. Pure documentation alignment.

### Neutral

- No behaviour change: `/v1/clean`, the trust boundary, and the preset
  payload library all behave identically before and after this ADR.
- v2.4.1 → v2.4.2 patch bump. Single commit, no tag.
