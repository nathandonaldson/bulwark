"""Tests for the PR-B hardening pass (ADR-039).

Covers:
  - G-SANITIZER-018, NG-SANITIZER-003 (encoding_resistant)
  - G-HTTP-CLEAN-011, G-HTTP-CLEAN-012 (trace observability + body cap)
  - G-WEBHOOK-008, NG-WEBHOOK-006 (hostname-resolving SSRF + TOCTOU NG)
  - G-REDTEAM-REPORTS-006 (locked snapshot)
"""
from __future__ import annotations

import socket
from unittest.mock import patch

import pytest


# ---------------------------------------------------------------------------
# B1 — encoding_resistant decode step
# ---------------------------------------------------------------------------


class TestEncodingResistantSanitizer:
    """G-SANITIZER-018: decode HTML entities + percent-encoding when enabled."""

    def test_html_entities_decoded(self):
        from bulwark.sanitizer import Sanitizer
        s = Sanitizer(decode_encodings=True)
        # `&lt;script&gt;` should decode to `<script>` and then be stripped.
        result = s.clean("hello &lt;script&gt;alert(1)&lt;/script&gt; world")
        # After decoding to <script>...</script>, the script stripper removes it.
        assert "alert" not in result
        assert "hello" in result and "world" in result

    def test_numeric_entities_decoded(self):
        from bulwark.sanitizer import Sanitizer
        s = Sanitizer(decode_encodings=True)
        result = s.clean("plain &#60;b&#62;text&#60;/b&#62; here")
        # &#60;b&#62; → <b>, then HTML strip removes <b> tags.
        assert "<b>" not in result
        assert "plain" in result and "text" in result and "here" in result

    def test_percent_encoding_decoded(self):
        from bulwark.sanitizer import Sanitizer
        s = Sanitizer(decode_encodings=True)
        result = s.clean("path %3Cscript%3E here")
        assert "<script>" not in result  # was decoded then stripped
        assert "path" in result and "here" in result

    def test_two_pass_handles_nested_encoding(self):
        """`&amp;lt;` → `&lt;` → `<` after the fixed-point loop (ADR-039 / B1)."""
        from bulwark.sanitizer import Sanitizer
        s = Sanitizer(decode_encodings=True)
        result = s.clean("a &amp;lt;script&amp;gt;x&amp;lt;/script&amp;gt; b")
        assert "x" not in result or "script" not in result.lower()
        assert "a" in result and "b" in result

    def test_triple_encoded_payload_decoded(self):
        """G-SANITIZER-018: fixed-point loop catches mixed-mode triple encoding."""
        from bulwark.sanitizer import Sanitizer
        s = Sanitizer(decode_encodings=True)
        # %2526lt%253B → %26lt%3B → &lt; → < (three rounds of decode)
        attack = "before %2526lt%253Bscript%2526gt%253B alert(1) %2526lt%253B/script%2526gt%253B after"
        result = s.clean(attack)
        # After decode loop, the script tag is plain text and the script
        # stripper removes it. "alert" must not survive.
        assert "alert" not in result
        assert "before" in result and "after" in result

    def test_disabled_by_default(self):
        """Default Sanitizer doesn't touch encoded payloads (backwards compat)."""
        from bulwark.sanitizer import Sanitizer
        s = Sanitizer()
        # Default constructor: decode_encodings is False.
        assert s.decode_encodings is False

    def test_off_state_preserves_encoded_text(self):
        """When decode_encodings=False, encoded payload survives (NG-SANITIZER-003)."""
        from bulwark.sanitizer import Sanitizer
        s = Sanitizer(decode_encodings=False)
        # Sanitizer with everything off except defaults — but no decode.
        # The literal entity bytes should be present in the output.
        result = s.clean("text &lt;b&gt; more")
        assert "&lt;" in result, "entities must survive when decode_encodings is off"

    def test_unencoded_payload_passes_unchanged(self):
        """A payload with no `%` or `&` percent/entity escapes is byte-stable."""
        from bulwark.sanitizer import Sanitizer
        s = Sanitizer(decode_encodings=True, strip_html=False, strip_scripts=False,
                      strip_zero_width=False, strip_control_chars=False,
                      strip_bidi=False, strip_emoji_smuggling=False,
                      strip_css_hidden=False, collapse_whitespace=False)
        original = "Just normal text. No special chars."
        assert s.clean(original) == original


# ---------------------------------------------------------------------------
# B2 — body size cap
# ---------------------------------------------------------------------------


class TestBodySizeCap:
    """G-HTTP-CLEAN-012: default 256 KB cap, tunable via BULWARK_MAX_CONTENT_SIZE."""

    def test_default_is_256kb(self):
        # The cap is computed at module-load time, so we read the constant.
        from bulwark.dashboard import models
        # Default 256 KB (262144 bytes) unless env overrides at import time.
        # We allow either: matches default OR matches whatever env set.
        import os
        expected = int(os.environ.get("BULWARK_MAX_CONTENT_SIZE", "262144"))
        assert models.MAX_CONTENT_SIZE == expected

    def test_env_override_function_returns_default_on_garbage(self):
        from bulwark.dashboard.models import _default_max_content_size
        # Direct call test — env-state restored after.
        import os
        prev = os.environ.get("BULWARK_MAX_CONTENT_SIZE")
        try:
            os.environ["BULWARK_MAX_CONTENT_SIZE"] = "not-a-number"
            assert _default_max_content_size() == 262144
            os.environ["BULWARK_MAX_CONTENT_SIZE"] = "0"
            assert _default_max_content_size() == 262144
            os.environ["BULWARK_MAX_CONTENT_SIZE"] = "-1"
            assert _default_max_content_size() == 262144
            os.environ["BULWARK_MAX_CONTENT_SIZE"] = "131072"
            assert _default_max_content_size() == 131072
        finally:
            if prev is None:
                os.environ.pop("BULWARK_MAX_CONTENT_SIZE", None)
            else:
                os.environ["BULWARK_MAX_CONTENT_SIZE"] = prev


# ---------------------------------------------------------------------------
# B3 — hostname-resolving SSRF
# ---------------------------------------------------------------------------


class TestHostnameSsrf:
    """G-WEBHOOK-008: resolve hostnames before allowing them past the SSRF check."""

    def setup_method(self):
        # Clear the resolution cache between tests to avoid cross-contamination.
        from bulwark.dashboard import url_validator
        url_validator._RESOLUTION_CACHE.clear()

    def test_hostname_resolving_to_loopback_blocked(self):
        from bulwark.dashboard.url_validator import validate_external_url
        with patch("socket.getaddrinfo") as gai:
            # evil.example.com → 127.0.0.1
            gai.return_value = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 0))]
            err = validate_external_url("https://evil.example.com/hook")
            assert err is not None
            assert "127.0.0.1" in err
            assert "evil.example.com" in err

    def test_hostname_resolving_to_metadata_blocked(self):
        from bulwark.dashboard.url_validator import validate_external_url
        with patch("socket.getaddrinfo") as gai:
            gai.return_value = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("169.254.169.254", 0))]
            err = validate_external_url("https://metadata.evil/")
            assert err is not None
            assert "169.254.169.254" in err

    def test_hostname_resolving_to_private_blocked(self):
        from bulwark.dashboard.url_validator import validate_external_url
        with patch("socket.getaddrinfo") as gai:
            gai.return_value = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.5", 0))]
            err = validate_external_url("https://internal-api.test/")
            assert err is not None
            assert "10.0.0.5" in err

    def test_hostname_resolving_to_public_passes(self):
        from bulwark.dashboard.url_validator import validate_external_url
        with patch("socket.getaddrinfo") as gai:
            gai.return_value = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 0))]
            err = validate_external_url("https://example.com/hook")
            assert err is None

    def test_unresolvable_hostname_rejected(self):
        from bulwark.dashboard.url_validator import validate_external_url
        with patch("socket.getaddrinfo", side_effect=socket.gaierror("nodename")):
            err = validate_external_url("https://does-not-exist.invalid/")
            assert err is not None
            assert "could not resolve" in err

    def test_hostname_with_mixed_resolution_blocks_on_first_private(self):
        """If ANY resolved IP is private, reject."""
        from bulwark.dashboard.url_validator import validate_external_url
        with patch("socket.getaddrinfo") as gai:
            gai.return_value = [
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", 0)),
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 0)),  # one bad apple
            ]
            err = validate_external_url("https://splitbrain.test/")
            assert err is not None

    def test_resolution_cached_60s(self):
        """G-WEBHOOK-008: getaddrinfo called once per host within the TTL."""
        from bulwark.dashboard import url_validator
        url_validator._RESOLUTION_CACHE.clear()
        with patch("socket.getaddrinfo") as gai:
            gai.return_value = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", 0))]
            url_validator.validate_external_url("https://example.com/")
            url_validator.validate_external_url("https://example.com/")
            url_validator.validate_external_url("https://example.com/")
            assert gai.call_count == 1, f"expected single getaddrinfo, got {gai.call_count}"

    def test_localhost_skips_resolution(self):
        """`localhost` and `host.docker.internal` always pass — Docker networking."""
        from bulwark.dashboard.url_validator import validate_external_url
        with patch("socket.getaddrinfo") as gai:
            assert validate_external_url("http://localhost:1234/") is None
            assert validate_external_url("http://host.docker.internal/") is None
            gai.assert_not_called()

    def test_literal_private_ip_still_blocked(self):
        """Don't regress on the original literal-IP path."""
        from bulwark.dashboard.url_validator import validate_external_url
        err = validate_external_url("http://10.0.0.1/")
        assert err is not None

    def test_does_not_pin_ip_at_fire_time(self):
        """NG-WEBHOOK-006: validation resolves the host but does NOT pass the
        IP to the eventual httpx call. Documented as a residual TOCTOU window
        bounded by _RESOLUTION_TTL. Operators in adversarial-DNS environments
        should front the receiver with a known-IP reverse proxy.

        This is a documentation-only test: it asserts the URL string is
        passed through untouched, which is the surface that makes the
        TOCTOU possible.
        """
        from bulwark.dashboard import url_validator
        # The validator returns None or an error string. It does NOT return
        # a rewritten URL with an embedded IP. That is the (intentional, but
        # documented) limit captured by NG-WEBHOOK-006.
        url_validator._RESOLUTION_CACHE.clear()
        with patch("socket.getaddrinfo") as gai:
            gai.return_value = [(socket.AF_INET, socket.SOCK_STREAM, 6, "",
                                 ("1.1.1.1", 0))]
            result = url_validator.validate_external_url("https://example.com/hook")
        assert result is None  # accepted, but URL not pinned to the resolved IP


# ---------------------------------------------------------------------------
# B4 — locked status snapshot
# ---------------------------------------------------------------------------


class TestRedteamStatusSnapshot:
    """G-REDTEAM-REPORTS-006: status read returns a coherent deep-copy snapshot."""

    def test_snapshot_is_deep_copy(self):
        import bulwark.dashboard.app as app_mod
        with app_mod._redteam_lock:
            app_mod._redteam_result.clear()
            app_mod._redteam_result.update({
                "status": "running", "completed": 5, "total": 10,
                "nested": {"foo": "bar"},
            })
        snap = app_mod._redteam_status_snapshot()
        assert snap == {"status": "running", "completed": 5, "total": 10, "nested": {"foo": "bar"}}
        # Mutate the snapshot — original must be unaffected.
        snap["completed"] = 999
        snap["nested"]["foo"] = "tampered"
        with app_mod._redteam_lock:
            assert app_mod._redteam_result["completed"] == 5
            assert app_mod._redteam_result["nested"]["foo"] == "bar"

    def test_snapshot_under_concurrent_writes(self):
        """Hammer the snapshot vs a writer thread — no torn reads or RuntimeErrors."""
        import threading
        import bulwark.dashboard.app as app_mod
        with app_mod._redteam_lock:
            app_mod._redteam_result.clear()
            app_mod._redteam_result.update({"status": "running", "completed": 0, "total": 100})
        stop = threading.Event()
        errors: list = []

        def writer():
            i = 0
            while not stop.is_set():
                with app_mod._redteam_lock:
                    app_mod._redteam_result["completed"] = i % 100
                i += 1

        def reader():
            try:
                while not stop.is_set():
                    snap = app_mod._redteam_status_snapshot()
                    # If we ever see status missing, that's a torn read.
                    assert "status" in snap and "total" in snap
            except Exception as e:
                errors.append(e)

        wt = threading.Thread(target=writer)
        rt = threading.Thread(target=reader)
        wt.start(); rt.start()
        # Run for a brief, deterministic time.
        import time as _t
        _t.sleep(0.05)
        stop.set()
        wt.join(timeout=2); rt.join(timeout=2)
        assert errors == [], f"snapshot races: {errors}"


# ---------------------------------------------------------------------------
# B5 — /v1/clean docstring (B5 is the FastAPI description, exposed via /openapi.json)
# ---------------------------------------------------------------------------


class TestCleanRouteDocstring:
    """B5 / ADR-039: route description reflects v2 reality (judge optional)."""

    def test_route_description_mentions_judge(self):
        try:
            from fastapi.testclient import TestClient
        except ImportError:
            pytest.skip("FastAPI not installed")
        from bulwark.dashboard.app import app
        spec = TestClient(app).get("/openapi.json").json()
        desc = spec["paths"]["/v1/clean"]["post"]["description"]
        assert "judge" in desc.lower()
        assert "no llm is invoked" not in desc.lower(), "stale docstring still present"


# ---------------------------------------------------------------------------
# B6 — trace observability
# ---------------------------------------------------------------------------


class TestTraceObservability:
    """G-HTTP-CLEAN-011: max_score and n_windows in trace entries."""

    def test_check_returns_dict_on_pass_safe(self):
        """promptguard.create_check returns dict on pass; max_score=0 when only SAFE labels."""
        from bulwark.integrations.promptguard import create_check

        class _FakePipe:
            class _FakeTokenizer:
                model_max_length = 512
                def encode(self, t, add_special_tokens=False, truncation=False):
                    return t.split()
                def decode(self, ids, skip_special_tokens=True):
                    return " ".join(ids)
            tokenizer = _FakeTokenizer()
            class model:
                name_or_path = "fake/path"
            def __call__(self, batch, truncation=False):
                if isinstance(batch, list):
                    return [{"label": "SAFE", "score": 0.12} for _ in batch]
                return [{"label": "SAFE", "score": 0.12}]

        check = create_check(_FakePipe(), threshold=0.9)
        result = check("hello world")
        assert isinstance(result, dict)
        assert "max_score" in result and "n_windows" in result
        # max_score reports INJECTION signal: SAFE-only inputs → 0.0
        assert result["max_score"] == 0.0
        assert result["top_label"] == "SAFE"
        assert result["n_windows"] == 1

    def test_clean_response_detector_label_reflects_top_label(self):
        """G-HTTP-CLEAN-007: detector.label is the model's actual top label,
        not a hardcoded "SAFE". Reviewer caught this on PR-B; previously the
        pass path returned {"label": "SAFE", ...} regardless of what
        PromptGuard ("BENIGN") or other models reported.
        """
        try:
            from fastapi.testclient import TestClient
        except ImportError:
            pytest.skip("FastAPI not installed")
        import bulwark.dashboard.app as app_mod

        # Stub a check function that mimics PromptGuard returning BENIGN.
        def _benign_check(text):
            return {"max_score": 0.0, "n_windows": 1, "top_label": "BENIGN"}

        saved_checks = dict(app_mod._detection_checks)
        try:
            app_mod._detection_checks.clear()
            app_mod._detection_checks["fakepg"] = _benign_check
            client = TestClient(app_mod.app)
            resp = client.post("/v1/clean", json={"content": "hello", "source": "t"})
            assert resp.status_code == 200
            body = resp.json()
            assert body["detector"]["label"] == "BENIGN"
            assert body["detector"]["score"] == 0.0
        finally:
            app_mod._detection_checks.clear()
            app_mod._detection_checks.update(saved_checks)

    def test_check_returns_max_inj_score_when_below_threshold(self):
        """Below-threshold INJECTION still surfaces in max_score for observability."""
        from bulwark.integrations.promptguard import create_check

        class _AlmostInjPipe:
            class _FakeTokenizer:
                model_max_length = 512
                def encode(self, t, add_special_tokens=False, truncation=False):
                    return t.split()
                def decode(self, ids, skip_special_tokens=True):
                    return " ".join(ids)
            tokenizer = _FakeTokenizer()
            class model:
                name_or_path = "fake/almost"
            def __call__(self, batch, truncation=False):
                # Below threshold of 0.9 — passes through.
                return [{"label": "INJECTION", "score": 0.78} for _ in batch]

        check = create_check(_AlmostInjPipe(), threshold=0.9)
        result = check("borderline text")
        assert result["max_score"] == 0.78
        assert result["top_label"] == "INJECTION"

    def test_block_exception_carries_score_and_window_attrs(self):
        from bulwark.guard import SuspiciousPatternError
        from bulwark.integrations.promptguard import create_check

        class _AttackPipe:
            class _FakeTokenizer:
                model_max_length = 8
                def encode(self, t, add_special_tokens=False, truncation=False):
                    return t.split()
                def decode(self, ids, skip_special_tokens=True):
                    return " ".join(ids)
            tokenizer = _FakeTokenizer()
            class model:
                name_or_path = "fake/attack"
            def __call__(self, batch, truncation=False):
                # Last window has a high-score INJECTION; others SAFE.
                out = []
                for i, _ in enumerate(batch):
                    if i == len(batch) - 1:
                        out.append({"label": "INJECTION", "score": 0.97})
                    else:
                        out.append({"label": "SAFE", "score": 0.10})
                return out

        check = create_check(_AttackPipe(), threshold=0.9)
        long = " ".join(f"tok{i}" for i in range(40))  # > window=8
        with pytest.raises(SuspiciousPatternError) as exc:
            check(long)
        err = exc.value
        assert getattr(err, "max_score", None) is not None
        assert err.max_score >= 0.9
        assert getattr(err, "n_windows", None) is not None
        assert err.n_windows > 1
        assert getattr(err, "window_index", None) is not None
        assert err.window_index == err.n_windows  # Last window was the trigger
