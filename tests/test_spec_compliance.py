"""Meta-tests that enforce spec/implementation agreement.

These tests ensure:
1. Every path in spec/openapi.yaml exists in the running FastAPI app
2. Every guarantee ID in spec/contracts/*.yaml has a corresponding test
3. Every non-guarantee ID has a corresponding test
4. Operator-facing setup files don't reference env vars that ADR-031 removed
5. Preset descriptions don't claim trust-boundary behaviour the boundary
   does not actually perform
"""
import os
import re
from pathlib import Path

import pytest
import yaml

try:
    from fastapi.testclient import TestClient
    HAS_FASTAPI = True
except ImportError:
    HAS_FASTAPI = False


REPO_ROOT = Path(__file__).parent.parent
SPEC_DIR = REPO_ROOT / "spec"
CONTRACTS_DIR = SPEC_DIR / "contracts"
TESTS_DIR = REPO_ROOT / "tests"


# Paths the app serves that are NOT part of the public spec. These power the
# bundled dashboard UI and redteam/integrations UX. Adding a new app path to
# this allowlist should be a conscious decision — if the path is something
# external callers will hit, put it in spec/openapi.yaml instead.
INTERNAL_PATHS: frozenset[str] = frozenset({
    "/",                              # dashboard HTML root
    "/api/auth/login",                # dashboard auth gate
    "/api/config",                    # dashboard config read/write
    "/api/events",                    # event log feed
    "/api/stream",                    # SSE stream for live dashboard updates
    "/api/metrics",                   # dashboard metrics tiles
    "/api/timeseries",                # dashboard sparklines
    "/api/pipeline-status",           # dashboard pipeline flow
    "/api/integrations",              # integrations list
    "/api/integrations/active-checks",
    "/api/integrations/detect",
    "/api/integrations/{name}",
    "/api/integrations/{name}/activate",
    "/api/garak/run",                 # red-team runner
    "/api/garak/status",
    "/api/redteam/run",
    "/api/redteam/status",
    "/api/redteam/stop",
})


def _load_yaml(path: Path) -> dict:
    """Load a YAML file."""
    with open(path) as f:
        return yaml.safe_load(f)


def _collect_guarantee_ids() -> list[str]:
    """Collect all guarantee and non-guarantee IDs from contract YAMLs."""
    ids = []
    for f in sorted(CONTRACTS_DIR.glob("*.yaml")):
        data = _load_yaml(f)
        for g in data.get("guarantees", []):
            ids.append(g["id"])
        for ng in data.get("non_guarantees", []):
            ids.append(ng["id"])
    return ids


def _find_id_in_tests(guarantee_id: str) -> bool:
    """Check if a guarantee ID appears in any test file docstring."""
    for test_file in TESTS_DIR.glob("test_*.py"):
        content = test_file.read_text()
        if guarantee_id in content:
            return True
    return False


# ---------------------------------------------------------------------------
# OpenAPI spec compliance
# ---------------------------------------------------------------------------

@pytest.mark.skipif(not HAS_FASTAPI, reason="FastAPI not installed")
class TestOpenAPICompliance:
    def test_openapi_spec_exists(self):
        """The OpenAPI spec file exists."""
        assert (SPEC_DIR / "openapi.yaml").exists()

    def test_openapi_spec_is_valid_yaml(self):
        """The OpenAPI spec is valid YAML."""
        spec = _load_yaml(SPEC_DIR / "openapi.yaml")
        assert "openapi" in spec
        assert "paths" in spec

    def test_spec_paths_exist_in_app(self):
        """Every path in spec/openapi.yaml exists in the running app."""
        from fastapi.testclient import TestClient
        from bulwark.dashboard.app import app

        spec = _load_yaml(SPEC_DIR / "openapi.yaml")
        client = TestClient(app)
        app_schema = client.get("/openapi.json").json()
        app_paths = set(app_schema.get("paths", {}).keys())

        for path in spec.get("paths", {}):
            assert path in app_paths, f"Spec path {path} not found in app. App has: {app_paths}"

    def test_app_paths_are_documented_or_allowlisted(self):
        """Every path the app serves is either in spec/openapi.yaml or on INTERNAL_PATHS.

        Closes the reverse-direction gap in the spec-compliance meta-tests. Previously
        an endpoint could ship without a spec entry and no test would fail. Public
        /v1/* endpoints belong in openapi.yaml. Dashboard-internal /api/* endpoints
        are allowlisted below because they serve the bundled UI and are not a
        stable public contract — adding a new one requires explicitly extending
        this list (forcing a conscious public/internal decision).
        """
        from fastapi.testclient import TestClient
        from bulwark.dashboard.app import app

        spec = _load_yaml(SPEC_DIR / "openapi.yaml")
        client = TestClient(app)
        app_paths = set(client.get("/openapi.json").json().get("paths", {}).keys())
        spec_paths = set(spec.get("paths", {}).keys())

        undocumented = sorted(app_paths - spec_paths - INTERNAL_PATHS)
        assert not undocumented, (
            f"App paths neither documented in spec/openapi.yaml nor explicitly "
            f"marked internal: {undocumented}. Either add them to openapi.yaml "
            f"(public contract) or to INTERNAL_PATHS in tests/test_spec_compliance.py "
            f"(dashboard-internal, not a stable contract)."
        )

        # Also flag dead allowlist entries — if an internal path disappears, the
        # allowlist should shrink with it rather than accumulate ghosts.
        dead = sorted(INTERNAL_PATHS - app_paths)
        assert not dead, (
            f"INTERNAL_PATHS contains paths the app no longer serves: {dead}. "
            f"Remove them from tests/test_spec_compliance.py."
        )

    def test_spec_request_fields_match_app(self):
        """Request body fields in spec match the app's Pydantic models."""
        from fastapi.testclient import TestClient
        from bulwark.dashboard.app import app

        spec = _load_yaml(SPEC_DIR / "openapi.yaml")
        client = TestClient(app)
        app_schema = client.get("/openapi.json").json()

        for path, methods in spec.get("paths", {}).items():
            for method, details in methods.items():
                if method == "post" and "requestBody" in details:
                    spec_schema = details["requestBody"]["content"]["application/json"]["schema"]
                    # Resolve $ref if present
                    if "$ref" in spec_schema:
                        ref_name = spec_schema["$ref"].split("/")[-1]
                        spec_props = spec.get("components", {}).get("schemas", {}).get(ref_name, {}).get("properties", {})
                    else:
                        spec_props = spec_schema.get("properties", {})

                    # Get app's schema for this endpoint
                    app_path = app_schema.get("paths", {}).get(path, {})
                    app_method = app_path.get(method, {})
                    app_body = app_method.get("requestBody", {})
                    app_content = app_body.get("content", {}).get("application/json", {})
                    app_schema_ref = app_content.get("schema", {})

                    if "$ref" in app_schema_ref:
                        ref_name = app_schema_ref["$ref"].split("/")[-1]
                        app_props = app_schema.get("components", {}).get("schemas", {}).get(ref_name, {}).get("properties", {})
                    else:
                        app_props = app_schema_ref.get("properties", {})

                    for field_name in spec_props:
                        assert field_name in app_props, (
                            f"Spec field '{field_name}' for {method.upper()} {path} "
                            f"not found in app model. App has: {list(app_props.keys())}"
                        )


# ---------------------------------------------------------------------------
# Contract guarantee coverage
# ---------------------------------------------------------------------------

class TestGuaranteeCoverage:
    def test_all_contracts_exist(self):
        """Contract YAML files exist for clean, guard, http_clean, http_guard."""
        assert (CONTRACTS_DIR / "clean.yaml").exists()
        assert (CONTRACTS_DIR / "guard.yaml").exists()
        assert (CONTRACTS_DIR / "http_clean.yaml").exists()
        assert (CONTRACTS_DIR / "http_guard.yaml").exists()

    def test_contracts_are_valid_yaml(self):
        """All contract files are valid YAML with required keys."""
        for f in CONTRACTS_DIR.glob("*.yaml"):
            data = _load_yaml(f)
            assert "guarantees" in data, f"{f.name} missing 'guarantees' key"
            assert "non_guarantees" in data, f"{f.name} missing 'non_guarantees' key"
            for g in data["guarantees"]:
                assert "id" in g, f"{f.name}: guarantee missing 'id'"
                assert "summary" in g, f"{f.name}: guarantee missing 'summary'"
            for ng in data["non_guarantees"]:
                assert "id" in ng, f"{f.name}: non_guarantee missing 'id'"
                assert "summary" in ng, f"{f.name}: non_guarantee missing 'summary'"

    def test_no_duplicate_ids(self):
        """No duplicate guarantee IDs across all contracts."""
        all_ids = _collect_guarantee_ids()
        seen = set()
        for gid in all_ids:
            assert gid not in seen, f"Duplicate guarantee ID: {gid}"
            seen.add(gid)

    def test_every_guarantee_has_test(self):
        """Every guarantee and non-guarantee ID has at least one test referencing it."""
        all_ids = _collect_guarantee_ids()
        missing = []
        for gid in all_ids:
            if not _find_id_in_tests(gid):
                missing.append(gid)
        assert not missing, f"Guarantee IDs without tests: {missing}"


# ---------------------------------------------------------------------------
# Preset description / trust-boundary behaviour drift
# ---------------------------------------------------------------------------

class TestPresetTrustBoundaryDrift:
    """G-SPEC-PRESETS-NO-XML-ESCAPE-001 — Phase D / ADR-043.

    Trust-boundary tests (tests/test_trust_boundary.py — see
    test_content_with_xml_like_characters_preserved and
    test_content_containing_tag_name_handled) prove the boundary WRAPS
    untrusted content but does NOT escape XML-like characters in the
    payload. Any preset description that claims XML re-escaping or payload
    escaping contradicts that behaviour and should fail this test before
    drift can ship.

    NOTE: this is still a phrase-level test — it catches drift in
    description copy. For true behavioural verification of what the trust
    boundary does (and does not) do, see tests/test_trust_boundary.py.
    """

    # Regex patterns that, if matched against any preset description, would
    # contradict what tests/test_trust_boundary.py proves. Each pattern is
    # case-insensitive (compiled with re.IGNORECASE) and intentionally broad
    # so common variants (escape/escapes/escaping, escape payload/escape
    # the boundary, encode/sanitize/substitute the payload) all trip.
    # Add new patterns here as similar drift surfaces.
    _FORBIDDEN_PATTERNS: tuple[re.Pattern[str], ...] = (
        # "re-escape", "reescape", "re escape" + ing/ed/s suffixes
        re.compile(r"re-?\s?escap(?:e|es|ed|ing)", re.IGNORECASE),
        # "xml-escape", "xml escape", "xml escapes/escaping/escaped"
        re.compile(r"xml[\s-]?escap(?:e|es|ed|ing)", re.IGNORECASE),
        # verb (escape/encode/sanitize/substitute) + optional words +
        # (payload | xml | (trust)?boundary). Catches "escapes the payload",
        # "encodes the boundary", "sanitizes payload", etc.
        re.compile(
            r"\b(?:escape|encode|sanitize|substitute)s?\s+"
            r"(?:\w+\s+){0,3}"
            r"(?:payload|xml|(?:trust\s+)?boundary)\b",
            re.IGNORECASE,
        ),
    )

    # Negation tokens that, when they appear within ~25 chars before a
    # forbidden-pattern match, mean the description is correctly
    # disclaiming the behaviour rather than claiming it. e.g.
    # "No XML escaping is performed" or "does not escape the payload".
    _NEGATION_RE: re.Pattern[str] = re.compile(
        r"\b(?:no|not|never|without|n't|none)\b",
        re.IGNORECASE,
    )
    _NEGATION_LOOKBACK_CHARS: int = 25

    def _is_negated(self, text: str, match_start: int) -> bool:
        """True if a negation word appears in the lookback window before
        match_start. Lets descriptions correctly say "no XML escaping is
        performed" without tripping the drift test."""
        window_start = max(0, match_start - self._NEGATION_LOOKBACK_CHARS)
        return bool(self._NEGATION_RE.search(text[window_start:match_start]))

    def test_no_preset_claims_xml_escaping(self):
        """G-SPEC-PRESETS-NO-XML-ESCAPE-001 — preset descriptions must not
        claim trust-boundary XML escaping behaviour that does not exist."""
        presets_doc = _load_yaml(SPEC_DIR / "presets.yaml")
        offenders: list[str] = []
        for preset in presets_doc.get("presets", []):
            desc = preset.get("description") or ""
            for pattern in self._FORBIDDEN_PATTERNS:
                for m in pattern.finditer(desc):
                    if self._is_negated(desc, m.start()):
                        continue
                    offenders.append(
                        f"preset '{preset.get('id')}' description contains "
                        f"forbidden phrase {m.group(0)!r} (pattern "
                        f"{pattern.pattern!r}) — trust boundary wraps but "
                        f"does not escape XML; see "
                        f"tests/test_trust_boundary.py::"
                        f"test_content_with_xml_like_characters_preserved"
                    )
                    break
                else:
                    continue
                break
        assert not offenders, (
            "Preset descriptions contradicted by trust-boundary tests:\n  "
            + "\n  ".join(offenders)
        )


# ---------------------------------------------------------------------------
# Operator-facing setup-file env-var drift
# ---------------------------------------------------------------------------

class TestEnvFileDrift:
    """NG-ENV-LLM-REMOVED — Phase D follow-up / ADR-043.

    spec/contracts/env_config.yaml encodes the env vars that ADR-031
    removed in v2.0.0 (BULWARK_LLM_MODE, BULWARK_API_KEY, BULWARK_BASE_URL,
    BULWARK_ANALYZE_MODEL, BULWARK_EXECUTE_MODEL). Operator-facing setup
    files (.env.example, docker-compose.yml) must not reference any of
    them — a fresh operator copies these files verbatim and ends up with
    env vars set that have no effect.

    CHANGELOG.md is intentionally exempt: it is append-only history, and
    the v2.0.0 / v2.4.2 / v2.4.3 entries legitimately record the removal.
    """

    @staticmethod
    def _removed_envvars_from_contract() -> list[str]:
        """Pull the canonical removed-env-var list from the env_config
        contract (NG-ENV-LLM-REMOVED summary)."""
        env_contract = _load_yaml(CONTRACTS_DIR / "env_config.yaml")
        for ng in env_contract.get("non_guarantees", []):
            if ng.get("id") == "NG-ENV-LLM-REMOVED":
                summary = ng.get("summary", "")
                # Extract every BULWARK_* identifier from the summary text.
                names = re.findall(r"\bBULWARK_[A-Z_]+\b", summary)
                # De-dupe while preserving order.
                seen: set[str] = set()
                unique: list[str] = []
                for n in names:
                    if n not in seen:
                        seen.add(n)
                        unique.append(n)
                return unique
        return []

    def test_removed_envvars_resolve_from_contract(self):
        """The contract still encodes the canonical removed-env-var list,
        so this test has something to enforce."""
        removed = self._removed_envvars_from_contract()
        # Five env vars were removed by ADR-031; if the contract changes,
        # so should this assertion.
        assert removed, (
            "Could not extract removed env var names from "
            "spec/contracts/env_config.yaml NG-ENV-LLM-REMOVED summary."
        )
        for expected in (
            "BULWARK_LLM_MODE",
            "BULWARK_API_KEY",
            "BULWARK_BASE_URL",
            "BULWARK_ANALYZE_MODEL",
            "BULWARK_EXECUTE_MODEL",
        ):
            assert expected in removed, (
                f"Expected {expected} in NG-ENV-LLM-REMOVED summary, got "
                f"{removed!r}"
            )

    def test_no_setup_file_references_removed_llm_envvars(self):
        """NG-ENV-LLM-REMOVED — operator setup files must not invite
        operators to set env vars ADR-031 deleted.

        Catches: actual `VAR=value` assignments, commented-out
        `# VAR=value` template lines, and `- VAR` / `VAR:` references in
        YAML environment blocks. These are the high-impact drift cases —
        a fresh operator copies .env.example to .env, sees a VAR=...
        line, fills in a value, and ends up with five env vars set that
        have no effect.

        Allows: narrative prose that names the removed vars to explain
        the removal (e.g. "ADR-031 removed BULWARK_LLM_MODE..."). That
        kind of historical reference helps operators upgrading from v1
        and is not a copy-paste hazard.
        """
        removed = self._removed_envvars_from_contract()
        # Operator-facing setup files only. CHANGELOG.md and ADRs are
        # append-only history and document the removal — exempt.
        targets = [
            REPO_ROOT / ".env.example",
            REPO_ROOT / "docker-compose.yml",
        ]
        offenders: list[str] = []
        for target in targets:
            if not target.exists():
                continue
            text = target.read_text()
            for var in removed:
                escaped = re.escape(var)
                # An "assignment" in either dotenv (.env / .env.example)
                # form (`VAR=value`, optionally commented out with `#`)
                # or compose `environment:` form (`- VAR=value` or
                # `VAR: value`). Anchored to start-of-line plus optional
                # leading whitespace, comment marker, and YAML list dash.
                assignment_re = re.compile(
                    rf"^[\s#\-]*{escaped}\s*[:=]",
                    re.MULTILINE,
                )
                if assignment_re.search(text):
                    offenders.append(
                        f"{target.relative_to(REPO_ROOT)} contains an "
                        f"assignment line for removed env var {var!r} — "
                        f"ADR-031 deleted it in v2.0.0; see "
                        f"spec/contracts/env_config.yaml "
                        f"NG-ENV-LLM-REMOVED"
                    )
        assert not offenders, (
            "Operator setup files invite use of env vars removed by "
            "ADR-031:\n  " + "\n  ".join(offenders)
        )
