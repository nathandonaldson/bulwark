"""Phase C — byte-count limit on /v1/clean content and /v1/guard text.

Spec/contract reference:
  - spec/contracts/http_clean.yaml :: G-HTTP-CLEAN-CONTENT-BYTES-001
  - spec/contracts/http_guard.yaml :: G-HTTP-GUARD-CONTENT-BYTES-001
  - spec/decisions/042-content-byte-limit.md

Background: Pydantic's ``Field(..., max_length=N)`` measures ``len(str)`` —
i.e. character count, not bytes. ``MAX_CONTENT_SIZE`` was always named
as bytes (256 KiB == 262_144), so a payload of 65_536 four-byte UTF-8
characters (1 MiB on the wire) would sail past the cap. Phase C enforces
a true byte-count limit on the UTF-8 encoding of the field, returning
HTTP 413 ``content_too_large`` per RFC 9110 §15.5.14. The same cap
applies to ``/v1/guard``'s ``text`` field — closing the laundering route
where an attacker would otherwise route oversized payloads to the
output-side endpoint instead of ``/v1/clean``.
"""
from __future__ import annotations

import pytest

try:
    from fastapi.testclient import TestClient
    HAS_FASTAPI = True
except ImportError:
    HAS_FASTAPI = False

pytestmark = pytest.mark.skipif(not HAS_FASTAPI, reason="FastAPI not installed")


def _get_client():
    """TestClient for the dashboard app, isolated from local LLM config."""
    from fastapi.testclient import TestClient
    from bulwark.dashboard.app import app
    return TestClient(app)


@pytest.fixture(autouse=True)
def _force_no_llm(monkeypatch):
    """Force sanitize-only mode so we exercise body-cap independently of
    detection state. When Phase A (ADR-040) lands, ``BULWARK_ALLOW_NO_DETECTORS``
    will gate the 503-fail-closed path; setting it here is forward-compatible
    and a no-op until then.
    """
    import bulwark.dashboard.app as app_mod
    from bulwark.dashboard.config import BulwarkConfig
    monkeypatch.setenv("BULWARK_ALLOW_NO_DETECTORS", "1")
    old = app_mod.config
    app_mod.config = BulwarkConfig()
    yield
    app_mod.config = old


def _max_bytes() -> int:
    from bulwark.dashboard.models import MAX_CONTENT_SIZE
    return MAX_CONTENT_SIZE


class TestContentByteLimit:
    """G-HTTP-CLEAN-CONTENT-BYTES-001: byte-count cap, not character-count cap."""

    def test_clean_rejects_oversize_byte_payload(self):
        """G-HTTP-CLEAN-CONTENT-BYTES-001: a payload that fits under the
        char-count cap but exceeds the byte cap when UTF-8 encoded MUST
        be rejected with HTTP 413 and ``error.code == "content_too_large"``.

        Construction: 4-byte UTF-8 character (U+1D54F MATHEMATICAL DOUBLE-
        STRUCK CAPITAL X) repeated until the encoding crosses the byte cap.
        With ``MAX_CONTENT_SIZE`` == 262_144 the worst case is 65_537
        chars × 4 bytes == 262_148 bytes — 4 bytes over, well under the
        262_144 *char* count Pydantic's old check would have accepted.
        """
        client = _get_client()
        cap = _max_bytes()
        # 4-byte char × (cap // 4 + 1) → 4 bytes over the byte cap, but
        # still well under the previous char-count cap (cap chars).
        n_chars = (cap // 4) + 1
        payload = "\U0001D54F" * n_chars
        # Sanity: char count under cap, byte count over cap.
        assert len(payload) < cap
        assert len(payload.encode("utf-8")) > cap

        resp = client.post("/v1/clean", json={"content": payload, "source": "byte-cap"})
        assert resp.status_code == 413, (
            f"expected 413 content_too_large, got {resp.status_code}: {resp.text[:200]}"
        )
        body = resp.json()
        # Match the structured-error shape used by Phase A's 503 path.
        assert "error" in body, body
        assert body["error"].get("code") == "content_too_large", body

    def test_clean_accepts_ascii_at_limit(self):
        """G-HTTP-CLEAN-CONTENT-BYTES-001: ASCII payload at exactly the byte
        cap is NOT rejected for size. ASCII is 1-byte-per-char so char
        count equals byte count. The request may still be rejected by
        downstream validation/detection (422) or the no-detectors gate
        (503) — what matters is that 413 does NOT fire."""
        client = _get_client()
        cap = _max_bytes()
        payload = "a" * cap  # exactly cap bytes (ASCII)
        assert len(payload.encode("utf-8")) == cap

        resp = client.post("/v1/clean", json={"content": payload, "source": "ascii-at-limit"})
        assert resp.status_code != 413, (
            f"ASCII at the byte cap MUST NOT 413; got {resp.status_code}: {resp.text[:200]}"
        )

    def test_clean_accepts_unicode_under_limit(self):
        """G-HTTP-CLEAN-CONTENT-BYTES-001: a non-ASCII payload that stays
        under the byte cap when UTF-8 encoded is NOT rejected for size."""
        client = _get_client()
        cap = _max_bytes()
        # 4-byte char × n where 4n < cap, leaving headroom.
        n_chars = (cap // 4) - 8
        payload = "\U0001D54F" * n_chars
        assert len(payload.encode("utf-8")) < cap

        resp = client.post("/v1/clean", json={"content": payload, "source": "unicode-under"})
        assert resp.status_code != 413, (
            f"Unicode under the byte cap MUST NOT 413; got {resp.status_code}: {resp.text[:200]}"
        )


class TestGuardTextByteLimit:
    """G-HTTP-GUARD-CONTENT-BYTES-001: byte-count cap parity with /v1/clean.

    The output-side ``/v1/guard`` endpoint reuses the same
    ``MAX_CONTENT_SIZE`` constant via a ``field_validator`` on
    ``GuardRequest.text``. Without this guarantee, an attacker could
    submit oversized payloads to ``/v1/guard`` to evade ``/v1/clean``'s
    body cap — the worker-pinning surface (tokenizer + downstream
    detector cost) would be just as exposed.
    """

    def test_guard_rejects_oversize_byte_payload(self):
        """G-HTTP-GUARD-CONTENT-BYTES-001: a ``text`` payload that fits
        under the char-count cap but exceeds the byte cap when UTF-8
        encoded MUST be rejected with HTTP 413 and
        ``error.code == "content_too_large"``.

        Construction mirrors the ``/v1/clean`` case: 4-byte UTF-8
        character (U+1D54F MATHEMATICAL DOUBLE-STRUCK CAPITAL X) repeated
        until the encoding crosses the byte cap. With
        ``MAX_CONTENT_SIZE`` == 262_144 the worst case is 65_537 chars ×
        4 bytes == 262_148 bytes — 4 bytes over. This closes the
        laundering route where an attacker would route oversized inputs
        to the output-side endpoint to bypass ``/v1/clean``'s cap.
        """
        client = _get_client()
        cap = _max_bytes()
        n_chars = (cap // 4) + 1
        payload = "\U0001D54F" * n_chars
        # Sanity: char count under cap, byte count over cap.
        assert len(payload) < cap
        assert len(payload.encode("utf-8")) > cap

        resp = client.post("/v1/guard", json={"text": payload})
        assert resp.status_code == 413, (
            f"expected 413 content_too_large, got {resp.status_code}: {resp.text[:200]}"
        )
        body = resp.json()
        assert "error" in body, body
        assert body["error"].get("code") == "content_too_large", body

    def test_guard_accepts_unicode_under_limit(self):
        """G-HTTP-GUARD-CONTENT-BYTES-001: a non-ASCII ``text`` payload
        that stays under the byte cap when UTF-8 encoded is NOT rejected
        for size. Symmetry with
        ``test_clean_accepts_unicode_under_limit`` — under-cap unicode
        on either endpoint must never 413.
        """
        client = _get_client()
        cap = _max_bytes()
        n_chars = (cap // 4) - 8
        payload = "\U0001D54F" * n_chars
        assert len(payload.encode("utf-8")) < cap

        resp = client.post("/v1/guard", json={"text": payload})
        assert resp.status_code != 413, (
            f"Unicode under the byte cap MUST NOT 413 on /v1/guard; "
            f"got {resp.status_code}: {resp.text[:200]}"
        )
