"""Tests for the canary-shape generator — spec/contracts/canaries.yaml.

G-CANARY-006..008 covered here. HTTP/CLI/UI coverage lives in
test_http_api.py, test_cli.py, and the dashboard UI tests respectively.
"""
import re

import pytest

from bulwark.canary_shapes import (
    AVAILABLE_SHAPES,
    generate_canary,
)


class TestShapeFormats:
    """G-CANARY-006 — each shape produces output matching its documented regex."""

    def test_aws_shape_matches_akia_pattern(self):
        out = generate_canary("aws")
        assert re.fullmatch(r"AKIA[A-Z0-9]{16}", out), f"bad AWS shape: {out!r}"

    def test_bearer_shape_matches_tk_live_pattern(self):
        out = generate_canary("bearer")
        assert re.fullmatch(r"tk_live_[a-f0-9]{32}", out), f"bad bearer: {out!r}"

    def test_password_shape_is_18_plus_chars_mixed(self):
        out = generate_canary("password")
        assert len(out) >= 18
        assert any(c.isupper() for c in out), "missing uppercase"
        assert any(c.islower() for c in out), "missing lowercase"
        assert any(c.isdigit() for c in out), "missing digit"
        assert any(not c.isalnum() for c in out), "missing symbol"

    def test_url_shape_is_internal_https(self):
        out = generate_canary("url")
        assert out.startswith("https://")
        assert ".internal/" in out

    def test_mongo_shape_is_srv_connection_string(self):
        out = generate_canary("mongo")
        assert out.startswith("mongodb+srv://")
        assert "@" in out and ".mongodb.net/" in out


class TestUniqueness:
    """G-CANARY-007 — every invocation produces a unique value."""

    @pytest.mark.parametrize("shape", ["aws", "bearer", "password", "url", "mongo"])
    def test_ten_invocations_are_all_distinct(self, shape):
        values = {generate_canary(shape) for _ in range(10)}
        assert len(values) == 10, f"collision in {shape}: {values}"


class TestShapeValidation:
    """G-CANARY-008 — unknown shapes raise; AVAILABLE_SHAPES enumerates valid."""

    def test_unknown_shape_raises_value_error(self):
        with pytest.raises(ValueError, match="unknown shape"):
            generate_canary("base64")

    def test_available_shapes_contains_all_documented(self):
        expected = {"aws", "bearer", "password", "url", "mongo"}
        assert set(AVAILABLE_SHAPES) == expected

    def test_available_shapes_are_all_generatable(self):
        for shape in AVAILABLE_SHAPES:
            assert generate_canary(shape), f"shape {shape} generated empty"
