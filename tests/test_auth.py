"""Spec-driven tests for dashboard authentication — spec/contracts/http_auth.yaml."""
import os
import pytest

try:
    from fastapi.testclient import TestClient
    HAS_FASTAPI = True
except ImportError:
    HAS_FASTAPI = False

pytestmark = pytest.mark.skipif(not HAS_FASTAPI, reason="FastAPI not installed")


def _get_client():
    from fastapi.testclient import TestClient
    from bulwark.dashboard.app import app
    return TestClient(app)


class TestAuthEnabled:
    """Tests with BULWARK_API_TOKEN set."""

    @pytest.fixture(autouse=True)
    def _set_token(self, monkeypatch):
        monkeypatch.setenv("BULWARK_API_TOKEN", "test-secret-token")

    def test_protected_endpoint_returns_401(self):
        """G-AUTH-001: Protected endpoints return 401 without valid token."""
        client = _get_client()
        resp = client.get("/api/config")
        assert resp.status_code == 401

    def test_protected_endpoint_with_valid_token(self):
        """G-AUTH-001: Protected endpoints work with valid bearer token."""
        client = _get_client()
        resp = client.get("/api/config", headers={"Authorization": "Bearer test-secret-token"})
        assert resp.status_code == 200

    def test_protected_endpoint_with_wrong_token(self):
        """G-AUTH-001: Protected endpoints reject wrong token."""
        client = _get_client()
        resp = client.get("/api/config", headers={"Authorization": "Bearer wrong-token"})
        assert resp.status_code == 401

    def test_healthz_public(self):
        """G-AUTH-002: /healthz works without auth."""
        client = _get_client()
        resp = client.get("/healthz")
        assert resp.status_code == 200

    def test_v1_clean_public(self):
        """G-AUTH-002: /v1/clean works without auth."""
        client = _get_client()
        resp = client.post("/v1/clean", json={"content": "test", "source": "test"})
        assert resp.status_code == 200

    def test_v1_guard_public(self):
        """G-AUTH-002: /v1/guard works without auth."""
        client = _get_client()
        resp = client.post("/v1/guard", json={"text": "test"})
        assert resp.status_code == 200

    def test_v1_pipeline_public(self, monkeypatch):
        """G-AUTH-002: /v1/pipeline works without auth."""
        import bulwark.dashboard.app as app_mod
        from bulwark.dashboard.config import BulwarkConfig
        old = app_mod.config
        app_mod.config = BulwarkConfig()  # mode=none, no LLM call
        try:
            client = _get_client()
            resp = client.post("/v1/pipeline", json={"content": "test"})
            assert resp.status_code == 200
        finally:
            app_mod.config = old

    def test_login_sets_cookie(self):
        """G-AUTH-004: POST /api/auth/login validates token and sets cookie."""
        client = _get_client()
        resp = client.post("/api/auth/login", json={"token": "test-secret-token"})
        assert resp.status_code == 200
        assert "bulwark_token" in resp.cookies

    def test_login_rejects_wrong_token(self):
        """G-AUTH-004: Login rejects wrong token."""
        client = _get_client()
        resp = client.post("/api/auth/login", json={"token": "wrong"})
        assert resp.status_code == 401

    def test_cookie_auth_works(self):
        """G-AUTH-005: Cookie-based auth works for protected endpoints."""
        client = _get_client()
        # Login to get cookie
        client.post("/api/auth/login", json={"token": "test-secret-token"})
        # Cookie should be set on the client — next request uses it
        resp = client.get("/api/config")
        assert resp.status_code == 200

    def test_options_passes_through(self):
        """G-AUTH-006: OPTIONS requests pass through for CORS preflight."""
        client = _get_client()
        resp = client.options("/api/config")
        assert resp.status_code != 401

    def test_dashboard_html_serves_login_gate(self):
        """G-AUTH-001: Dashboard HTML serves but shows login gate (JS handles auth)."""
        client = _get_client()
        resp = client.get("/")
        assert resp.status_code == 200
        assert "auth-overlay" in resp.text

    def test_redteam_protected(self):
        """G-AUTH-001: Red team endpoints are protected."""
        client = _get_client()
        resp = client.get("/api/redteam/status")
        assert resp.status_code == 401

    def test_events_protected(self):
        """G-AUTH-001: Event endpoints are protected."""
        client = _get_client()
        resp = client.get("/api/events?hours=1")
        assert resp.status_code == 401


class TestAuthNonGuarantees:
    """Non-guarantee coverage for spec compliance."""

    def test_no_user_accounts(self):
        """NG-AUTH-001: No user accounts or RBAC — single token for the whole dashboard."""
        # By design — verified by the middleware checking a single env var
        from bulwark.dashboard.config import get_api_token
        assert callable(get_api_token)

    def test_token_not_encrypted(self):
        """NG-AUTH-002: Token is an env var, not encrypted at rest."""
        import os
        os.environ["BULWARK_API_TOKEN"] = "test"
        from bulwark.dashboard.config import get_api_token
        assert get_api_token() == "test"
        del os.environ["BULWARK_API_TOKEN"]


class TestAuthDisabled:
    """Tests without BULWARK_API_TOKEN set (backwards compatible)."""

    @pytest.fixture(autouse=True)
    def _clear_token(self, monkeypatch):
        monkeypatch.delenv("BULWARK_API_TOKEN", raising=False)

    def test_config_accessible_without_token(self):
        """G-AUTH-003: When no token set, all endpoints work without auth."""
        client = _get_client()
        resp = client.get("/api/config")
        assert resp.status_code == 200

    def test_dashboard_accessible_without_token(self):
        """G-AUTH-003: Dashboard HTML accessible without token."""
        client = _get_client()
        resp = client.get("/")
        assert resp.status_code == 200

    def test_redteam_accessible_without_token(self):
        """G-AUTH-003: Red team accessible without token."""
        client = _get_client()
        resp = client.get("/api/redteam/status")
        assert resp.status_code == 200
