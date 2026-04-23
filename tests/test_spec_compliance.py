"""Meta-tests that enforce spec/implementation agreement.

These tests ensure:
1. Every path in spec/openapi.yaml exists in the running FastAPI app
2. Every guarantee ID in spec/contracts/*.yaml has a corresponding test
3. Every non-guarantee ID has a corresponding test
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
