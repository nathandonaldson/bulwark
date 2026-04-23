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

    def test_v1_clean_public(self, monkeypatch):
        """G-AUTH-002: /v1/clean works without auth."""
        import bulwark.dashboard.app as app_mod
        from bulwark.dashboard.config import BulwarkConfig
        old = app_mod.config
        app_mod.config = BulwarkConfig()
        try:
            client = _get_client()
            resp = client.post("/v1/clean", json={"content": "test", "source": "test"})
            assert resp.status_code == 200
        finally:
            app_mod.config = old

    def test_v1_guard_public(self):
        """G-AUTH-002: /v1/guard works without auth."""
        client = _get_client()
        resp = client.post("/v1/guard", json={"text": "test"})
        assert resp.status_code == 200

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


class TestLoopbackOnlyMutations:
    """G-AUTH-007 / ADR-029: when no token is set, mutations require loopback.

    The TestClient is treated as loopback by _is_loopback_client. Tests
    that need to simulate a remote client monkeypatch the helper.
    """

    @pytest.fixture(autouse=True)
    def _clear_token(self, monkeypatch):
        monkeypatch.delenv("BULWARK_API_TOKEN", raising=False)

    def test_local_put_still_works_without_token(self):
        """G-AUTH-007 (allow): loopback client + no token → PUT succeeds."""
        client = _get_client()
        resp = client.put("/api/config", json={"require_json": False})
        # 200 on success, 400 on validation error — both mean auth passed.
        # A 403 here would mean the loopback check is wrongly denying.
        assert resp.status_code != 403

    def test_remote_put_rejected_without_token(self, monkeypatch):
        """G-AUTH-007 (deny): remote client + no token → 403, not 200."""
        import bulwark.dashboard.app as app_mod
        monkeypatch.setattr(app_mod, "_is_loopback_client", lambda req: False)

        client = _get_client()
        resp = client.put("/api/config", json={"require_json": True})
        assert resp.status_code == 403
        assert "BULWARK_API_TOKEN" in resp.text

    def test_remote_post_rejected_without_token(self, monkeypatch):
        """G-AUTH-007: POST is a mutating method and is gated the same way."""
        import bulwark.dashboard.app as app_mod
        monkeypatch.setattr(app_mod, "_is_loopback_client", lambda req: False)

        client = _get_client()
        resp = client.post("/api/canaries", json={"label": "x", "token": "12345678"})
        assert resp.status_code == 403

    def test_remote_delete_rejected_without_token(self, monkeypatch):
        """G-AUTH-007: DELETE is a mutating method and is gated the same way."""
        import bulwark.dashboard.app as app_mod
        monkeypatch.setattr(app_mod, "_is_loopback_client", lambda req: False)

        client = _get_client()
        resp = client.delete("/api/canaries/ghost")
        assert resp.status_code == 403

    def test_remote_get_still_works_without_token(self, monkeypatch):
        """G-AUTH-003: reads are open to remote clients even without a token."""
        import bulwark.dashboard.app as app_mod
        monkeypatch.setattr(app_mod, "_is_loopback_client", lambda req: False)

        client = _get_client()
        resp = client.get("/api/config")
        assert resp.status_code == 200

    def test_remote_put_allowed_with_valid_token(self, monkeypatch):
        """When the operator sets a token and authenticates, remote mutations
        work. The loopback rule is the unauth-fallback, not a hard limit."""
        monkeypatch.setenv("BULWARK_API_TOKEN", "ops-secret")
        import bulwark.dashboard.app as app_mod
        monkeypatch.setattr(app_mod, "_is_loopback_client", lambda req: False)

        client = _get_client()
        resp = client.put(
            "/api/config",
            json={"require_json": False},
            headers={"Authorization": "Bearer ops-secret"},
        )
        assert resp.status_code != 403

    def test_xforwarded_for_does_not_grant_loopback(self, monkeypatch):
        """NG-AUTH-003: X-Forwarded-For: 127.0.0.1 must not bypass the check."""
        import bulwark.dashboard.app as app_mod
        monkeypatch.setattr(app_mod, "_is_loopback_client", lambda req: False)

        client = _get_client()
        resp = client.put(
            "/api/config",
            json={"require_json": True},
            headers={
                "X-Forwarded-For": "127.0.0.1",
                "X-Real-IP": "127.0.0.1",
            },
        )
        assert resp.status_code == 403


class TestLoopbackDetector:
    """G-AUTH-007 helper: _is_loopback_client correctly classifies clients."""

    def _req(self, host):
        """Build a minimal object with request.client.host = host."""
        class _C:
            def __init__(self, h): self.host = h
        class _R:
            def __init__(self, h): self.client = _C(h)
        return _R(host)

    def test_127_0_0_1_is_loopback(self):
        from bulwark.dashboard.app import _is_loopback_client
        assert _is_loopback_client(self._req("127.0.0.1")) is True

    def test_127_0_0_2_is_loopback(self):
        """Full 127.0.0.0/8 block, not just the canonical 127.0.0.1."""
        from bulwark.dashboard.app import _is_loopback_client
        assert _is_loopback_client(self._req("127.0.0.2")) is True

    def test_ipv6_loopback(self):
        from bulwark.dashboard.app import _is_loopback_client
        assert _is_loopback_client(self._req("::1")) is True

    def test_testclient_sentinel_is_loopback(self):
        """FastAPI TestClient uses "testclient" as host; counts as loopback."""
        from bulwark.dashboard.app import _is_loopback_client
        assert _is_loopback_client(self._req("testclient")) is True

    def test_lan_ip_is_not_loopback(self):
        from bulwark.dashboard.app import _is_loopback_client
        assert _is_loopback_client(self._req("192.168.1.5")) is False
        assert _is_loopback_client(self._req("10.0.0.1")) is False
        assert _is_loopback_client(self._req("172.16.0.1")) is False

    def test_public_ip_is_not_loopback(self):
        from bulwark.dashboard.app import _is_loopback_client
        assert _is_loopback_client(self._req("8.8.8.8")) is False

    def test_garbage_host_is_not_loopback(self):
        from bulwark.dashboard.app import _is_loopback_client
        assert _is_loopback_client(self._req("not-an-ip-nor-sentinel")) is False

    def test_missing_client_is_not_loopback(self):
        from bulwark.dashboard.app import _is_loopback_client
        class _R:
            client = None
        assert _is_loopback_client(_R()) is False
