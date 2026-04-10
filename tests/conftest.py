"""Shared fixtures for bulwark tests."""
import pytest

from bulwark.canary import CanarySystem


@pytest.fixture
def canary():
    """Fresh CanarySystem instance."""
    return CanarySystem()


@pytest.fixture
def canary_with_tokens():
    """CanarySystem with two pre-generated tokens."""
    cs = CanarySystem()
    cs.generate("user_data")
    cs.generate("config")
    return cs
