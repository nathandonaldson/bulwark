"""Unit tests for the shared env_truthy helper (ADR-040 follow-up).

This helper unifies the truthy-env parsing previously duplicated between
api_v1.py (BULWARK_ALLOW_NO_DETECTORS) and app.py (BULWARK_ALLOW_SANITIZE_ONLY).
Behaviour: 1 / true / yes (case-insensitive, whitespace-tolerant) → True.
Anything else, including unset, falls back to False (fail-closed).
"""
from __future__ import annotations

import pytest

from bulwark.dashboard.config import env_truthy


_VAR = "BULWARK_TEST_ENV_TRUTHY"


@pytest.mark.parametrize("value", ["1", "true", "TRUE", "True", "yes", "YES", "  1  ", "\ttrue\n", " yes "])
def test_env_truthy_truthy_values(monkeypatch, value):
    """Documented truthy strings (and whitespace-padded variants) opt in."""
    monkeypatch.setenv(_VAR, value)
    assert env_truthy(_VAR) is True


@pytest.mark.parametrize("value", ["", "0", "false", "FALSE", "no", "NO", "random", "off", "2", " ", "\t"])
def test_env_truthy_falsy_values(monkeypatch, value):
    """Anything that isn't 1/true/yes (after strip+lower) is fail-closed."""
    monkeypatch.setenv(_VAR, value)
    assert env_truthy(_VAR) is False


def test_env_truthy_unset(monkeypatch):
    """Missing env var is False — fail-closed default."""
    monkeypatch.delenv(_VAR, raising=False)
    assert env_truthy(_VAR) is False
