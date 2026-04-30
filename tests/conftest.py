"""Shared fixtures for bulwark tests."""
import pytest

from bulwark.canary import CanarySystem


def _get_client():
    """Create a TestClient for the dashboard app.

    Hoisted from per-file copies in test_http_api.py / test_auth.py /
    test_dashboard_layers.py / test_content_byte_limit.py — single
    source of truth so an API-shape change updates one place.

    Imported lazily so tests gated on FastAPI availability still skip
    cleanly via their module-level pytestmark.
    """
    from fastapi.testclient import TestClient
    from bulwark.dashboard.app import app
    return TestClient(app)


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


# ---------------------------------------------------------------------------
# DX guard: friendly banner when test_e2e_real_detectors.py is invoked
# directly without `-m e2e_slow` — see ADR-045 / I-2 follow-up.
#
# Because pyproject.toml sets `addopts = "-m 'not e2e_slow'"`, running
# `pytest tests/test_e2e_real_detectors.py` silently deselects all 6
# tests. The top-of-file docstring names the marker, but a CLI banner
# is a stronger forcing function. The hook writes via the
# terminalreporter so the message survives pytest's stdout/stderr
# capture machinery. Scoped narrowly: only fires when the e2e file is
# named on the command line and the resolved -m expression is exactly
# the pyproject default (`not e2e_slow`). No behaviour change for any
# other marker, file, or invocation pattern.
# ---------------------------------------------------------------------------

_E2E_DETECTOR_MODULE = "tests/test_e2e_real_detectors.py"


def _e2e_invoked_without_marker(config) -> bool:
    """True iff `pytest tests/test_e2e_real_detectors.py` was invoked
    explicitly but the user didn't override the default `not e2e_slow`
    deselection. That's the silent-deselect footgun.

    We compare invocation_params.args (what the user typed on the CLI)
    against the resolved -m expression. The default markexpr is the
    pyproject addopts value (`not e2e_slow`); the user opts in by
    passing their own `-m` that mentions `e2e_slow` positively.
    """
    invocation_args = getattr(getattr(config, "invocation_params", None), "args", ()) or ()
    user_typed_e2e_file = any(_E2E_DETECTOR_MODULE in str(a) for a in invocation_args)
    if not user_typed_e2e_file:
        return False
    # Resolved markexpr — if it's exactly the default-deselect expression,
    # the user didn't override it. Anything containing positive `e2e_slow`
    # selection (or an explicit `-m ""`) is treated as opt-in.
    markexpr = (config.getoption("-m", default="") or "").strip()
    if not markexpr:
        return False
    if markexpr == "not e2e_slow":
        return True
    # User passed their own -m. Treat it as opt-in if it positively
    # mentions the marker; treat it as still-deselecting if it strengthens
    # the exclusion. Conservative: only fire the banner for the default.
    return False


def pytest_collection_finish(session):
    """Emit a DX banner via the terminal reporter when the e2e file is
    invoked without `-m e2e_slow`. The terminal-reporter `write_line`
    path bypasses pytest's stdout/stderr capture so the banner is
    reliably visible to the developer regardless of -s / -v flags.
    """
    if not _e2e_invoked_without_marker(session.config):
        return
    reporter = session.config.pluginmanager.get_plugin("terminalreporter")
    if reporter is None:
        return
    reporter.write_line("")
    reporter.write_line(
        "DX banner (ADR-045): tests/test_e2e_real_detectors.py invoked without "
        "`-m e2e_slow`.",
        yellow=True,
        bold=True,
    )
    reporter.write_line(
        "  pyproject addopts (`-m 'not e2e_slow'`) deselects this module by "
        "default, so 0 tests will run.",
        yellow=True,
    )
    reporter.write_line(
        "  Re-invoke with: pytest tests/test_e2e_real_detectors.py -m e2e_slow",
        yellow=True,
    )
    reporter.write_line("")
