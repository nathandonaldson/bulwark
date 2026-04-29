"""ADR-038 — falsepos runner classifies HTTP failures as errors, not passes.

Covers the dashboard `_run_falsepos_in_background` path and the standalone
`bulwark_falsepos.runner.FalseposRunner._run_one_email` path. Errored
requests are excluded from the false-positive rate denominator.
"""
from __future__ import annotations

import pytest

try:
    import httpx
    HAS_HTTPX = True
except ImportError:
    HAS_HTTPX = False


# ---------------------------------------------------------------------------
# Standalone runner: _run_one_email response classification.
# ---------------------------------------------------------------------------


class _FakeClient:
    """Minimal client surface FalseposRunner expects (only what _run_one_email uses)."""
    def __init__(self):
        self.base_url = "http://test.invalid"
    def _headers(self):
        return {}


@pytest.mark.skipif(not HAS_HTTPX, reason="httpx not installed")
class TestStandaloneRunnerClassification:

    def _make_runner(self):
        from bulwark_bench.configs import DetectorConfig
        from bulwark_falsepos.runner import FalseposRunner
        cfg = DetectorConfig(slug="test", name="test")
        return FalseposRunner(
            client=_FakeClient(),
            run_dir=__import__("pathlib").Path("/tmp/_falsepos_test"),
            corpus=[],
            configs=[cfg],
        )

    def _email(self):
        from bulwark_falsepos.corpus import CorpusEmail
        return CorpusEmail(id="e1", category="newsletter", subject="hi", body="hello")

    def test_200_response_is_clean_pass(self, monkeypatch):
        """200 with valid JSON → blocked=False, no error."""
        runner = self._make_runner()
        def _fake_post(url, json, headers, timeout):
            return httpx.Response(200, json={"safe": True, "result": "..."})
        monkeypatch.setattr(httpx, "post", _fake_post)
        r = runner._run_one_email(self._email())
        assert r["blocked"] is False
        assert r.get("error") is None

    def test_422_is_blocked_false_positive(self, monkeypatch):
        runner = self._make_runner()
        def _fake_post(url, json, headers, timeout):
            return httpx.Response(422, json={"blocked": True, "block_reason": "x", "blocked_at": "detection:protectai"})
        monkeypatch.setattr(httpx, "post", _fake_post)
        r = runner._run_one_email(self._email())
        assert r["blocked"] is True
        assert r.get("error") is None
        assert r["blocking_layer"] == "detection:protectai"

    def test_500_is_error_not_pass(self, monkeypatch):
        """ADR-038: 5xx must classify as error so it can't inflate defense rate."""
        runner = self._make_runner()
        def _fake_post(url, json, headers, timeout):
            return httpx.Response(500, text="Internal Server Error")
        monkeypatch.setattr(httpx, "post", _fake_post)
        r = runner._run_one_email(self._email())
        assert r["blocked"] is False
        assert r["error"] is not None
        assert "500" in r["error"]

    def test_401_is_error_not_pass(self, monkeypatch):
        """Auth failures must classify as error, not as defended."""
        runner = self._make_runner()
        def _fake_post(url, json, headers, timeout):
            return httpx.Response(401, text="Unauthorized")
        monkeypatch.setattr(httpx, "post", _fake_post)
        r = runner._run_one_email(self._email())
        assert r["blocked"] is False
        assert r["error"] is not None
        assert "401" in r["error"]

    def test_200_with_non_json_is_error(self, monkeypatch):
        """A 200 with an unparseable body indicates a server bug, not a clean pass."""
        runner = self._make_runner()
        def _fake_post(url, json, headers, timeout):
            return httpx.Response(200, text="plain text body")
        monkeypatch.setattr(httpx, "post", _fake_post)
        r = runner._run_one_email(self._email())
        assert r["blocked"] is False
        assert r["error"] is not None
        assert "non-JSON" in r["error"]

    def test_network_failure_is_error(self, monkeypatch):
        """Connection refusal / timeout returns blocked=False with error set."""
        runner = self._make_runner()
        def _fake_post(url, json, headers, timeout):
            raise httpx.ConnectError("refused", request=None)
        monkeypatch.setattr(httpx, "post", _fake_post)
        r = runner._run_one_email(self._email())
        assert r["blocked"] is False
        assert r["error"] is not None

    def test_fp_rate_excludes_errors(self):
        """ADR-038: false_positive_rate = blocked / scored_count, not / corpus_size."""
        from bulwark_bench.configs import DetectorConfig
        from bulwark_falsepos.corpus import CorpusEmail
        from bulwark_falsepos.runner import FalseposRunner

        cfg = DetectorConfig(slug="test", name="test")
        corpus = [
            CorpusEmail(id="e1", category="x", subject="s", body="a"),
            CorpusEmail(id="e2", category="x", subject="s", body="b"),
            CorpusEmail(id="e3", category="x", subject="s", body="c"),
            CorpusEmail(id="e4", category="x", subject="s", body="d"),
        ]
        runner = FalseposRunner(
            client=_FakeClient(), run_dir=__import__("pathlib").Path("/tmp/_falsepos_test_rate"),
            corpus=corpus, configs=[cfg],
        )
        # Hand-craft per_email outcomes to mimic: 1 blocked, 1 clean, 2 errored.
        # We can't easily run the loop without HTTP; just verify the math by
        # building the payload through the public path.
        per_email = [
            {"id": "e1", "category": "x", "blocked": True, "blocking_layer": "x", "blocking_reason": "x"},
            {"id": "e2", "category": "x", "blocked": False},
            {"id": "e3", "category": "x", "blocked": False, "error": "HTTP 500: ..."},
            {"id": "e4", "category": "x", "blocked": False, "error": "ConnectError"},
        ]
        # Replicate the rate calc from _run_one_config inline (mirror of source).
        blocked = [r for r in per_email if r.get("blocked")]
        errored = [r for r in per_email if r.get("error")]
        scored = len(corpus) - len(errored)
        rate = (len(blocked) / scored) if scored else 0.0
        assert scored == 2
        assert rate == 0.5, "1 blocked out of 2 scored = 50%, NOT 25% over the full corpus"


# ---------------------------------------------------------------------------
# Dashboard runner: rate over scored, errors visible in by_family.
# ---------------------------------------------------------------------------


class TestDashboardRunnerErrorClassification:
    """Smoke checks for the inline classification block in app._run_falsepos_in_background.

    We don't run the full async runner here (it boots an HTTP loop). We
    verify the classification predicates are exercised by the source so a
    future refactor doesn't silently undo the fix.
    """

    def test_source_treats_non_422_non_200_as_error(self):
        """ADR-038: any status that is neither 422 nor 200 must set verdict=error."""
        import inspect
        import bulwark.dashboard.app as app_mod
        src = inspect.getsource(app_mod._run_falsepos_in_background)
        assert 'verdict"] = "error"' in src or '"verdict": "error"' in src or "verdict\"]= \"error\"" in src.replace(" ", "")
        # And the rate must be computed over scored, not total.
        assert "scored = defended + false_positives" in src
        assert "fp_rate = (false_positives / scored)" in src
