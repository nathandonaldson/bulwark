"""Spec-driven tests for dashboard shell — spec/contracts/dashboard_ui.yaml."""
from pathlib import Path
import re

import pytest


SHELL_JS = Path(__file__).parent.parent / "src" / "bulwark" / "dashboard" / "static" / "src" / "shell.jsx"
DATA_JS = Path(__file__).parent.parent / "src" / "bulwark" / "dashboard" / "static" / "src" / "data.jsx"
INDEX_HTML = Path(__file__).parent.parent / "src" / "bulwark" / "dashboard" / "static" / "index.html"


# ---------------------------------------------------------------------------
# JS-driven behavior tests — run computeStatusPill inside a tiny Node/JS
# harness. We use `js2py` if available, otherwise fall back to a subprocess
# running `node -e`. Both are optional; tests skip cleanly on missing.
# ---------------------------------------------------------------------------


def _shell_source():
    return SHELL_JS.read_text(encoding="utf-8")


def _data_source():
    return DATA_JS.read_text(encoding="utf-8")


def _run_pill(store: dict) -> dict:
    """Execute computeStatusPill(store) via Node and return {kind, label}."""
    import json

    from tests._node_helpers import run_node_eval

    # Stub LAYERS array (7 entries — matches data.jsx). The pill only reads
    # l.id and the layerConfig keyed by that id.
    # v2 (ADR-031): four layers — sanitizer, detection, boundary, canary.
    layers_stub = "const LAYERS = " + json.dumps([
        {"id": "sanitizer"}, {"id": "detection"}, {"id": "boundary"}, {"id": "canary"},
    ]) + ";"

    # computeStatusPill delegates to activeLayerCount (defined in data.jsx).
    # Pull both into the harness so the Node eval has everything it needs.
    data_src = (Path(__file__).parent.parent / "src" / "bulwark" / "dashboard" / "static" / "src" / "data.jsx").read_text()
    active_src = re.search(
        r"function activeLayerCount\([^)]*\) \{.*?\n\}\n",
        data_src,
        flags=re.DOTALL,
    )
    assert active_src, "activeLayerCount not found in data.jsx"

    pill_src = re.search(
        r"function computeStatusPill\(store\) \{.*?\n\}\n",
        _shell_source(),
        flags=re.DOTALL,
    )
    assert pill_src, "computeStatusPill not found in shell.jsx"

    harness = (
        layers_stub + "\n"
        + active_src.group(0) + "\n"
        + pill_src.group(0) + "\n"
        + f"process.stdout.write(JSON.stringify(computeStatusPill({json.dumps(store)})));"
    )
    return run_node_eval(harness, skip_reason="node not on PATH — cannot exercise JSX status-pill logic")


def _store(**overrides):
    """v2 store fixture (ADR-031): no llm; detector status drives the pill."""
    base = {
        "layerConfig": {
            "sanitizer": True, "detection": True, "boundary": True, "canary": True,
        },
        "detectorStatus": {"protectai": {"status": "ready"}},
        "version": "9.9.9",
    }
    base.update(overrides)
    return base


class TestComputeStatusPill:
    """v2.5.12 (audit-05 R2 / F2/F13/F16): computeStatusPill is now a state
    machine returning {kind, label, detail?}. The state machine reads
    detectorStatus, integrations.promptguard, judge.enabled, and serviceMode
    (echoed from /v1/clean) so the dashboard's top-level signal honours the
    ADR-040 (fail-closed) + ADR-038 (degraded-explicit) modes."""

    def test_all_on_ready_returns_ok(self):
        """G-UI-STATUS-001: all layers on + detector ready → ok."""
        result = _run_pill(_store())
        assert result == {"kind": "ok", "label": "All layers active"}

    def test_one_off_returns_warn_with_count(self):
        """G-UI-STATUS-002: one layer off → warn + '3 of 4 layers active'."""
        s = _store()
        s["layerConfig"]["sanitizer"] = False
        result = _run_pill(s)
        assert result == {"kind": "warn", "label": "3 of 4 layers active"}

    def test_detector_error_with_no_alternates_returns_no_detectors_loaded(self):
        """ADR-040 / audit-05 F2: detector error + no PromptGuard + no judge →
        bad + 'No detectors loaded' (the fail-closed state /v1/clean is
        returning 503 for). The state machine surfaces the actual condition
        rather than the v2.5.11 'Detector unreachable' which understated it."""
        s = _store()
        s["detectorStatus"] = {"protectai": {"status": "error"}}
        result = _run_pill(s)
        assert result["kind"] == "bad"
        assert result["label"] == "No detectors loaded"
        assert "detail" in result

    def test_detector_error_with_promptguard_active_returns_unreachable(self):
        """G-UI-STATUS-003 (refined): detector error but PromptGuard is up →
        bad + 'Detector unreachable' (some detection is still running)."""
        s = _store()
        s["detectorStatus"] = {"protectai": {"status": "error"}}
        s["integrations"] = {"promptguard": "active"}
        result = _run_pill(s)
        assert result == {"kind": "bad", "label": "Detector unreachable"}

    def test_detector_error_with_judge_enabled_returns_unreachable(self):
        """ADR-041: judge state alone keeps the pill out of fail-closed."""
        s = _store()
        s["detectorStatus"] = {"protectai": {"status": "error"}}
        s["judge"] = {"enabled": True}
        result = _run_pill(s)
        assert result == {"kind": "bad", "label": "Detector unreachable"}

    def test_detector_loading_returns_warn(self):
        """G-UI-STATUS-004: detector status=loading → warn + 'Loading detector…'."""
        s = _store()
        s["detectorStatus"] = {"protectai": {"status": "loading"}}
        result = _run_pill(s)
        assert result == {"kind": "warn", "label": "Loading detector…"}

    def test_degraded_explicit_mode_returns_sanitize_only(self):
        """ADR-038 / audit-05 F2: when /v1/clean echoes mode='degraded-explicit'
        (operator opted into BULWARK_ALLOW_NO_DETECTORS=1) the pill surfaces
        'Sanitize-only mode' so the user knows detection is intentionally off."""
        s = _store()
        s["serviceMode"] = "degraded-explicit"
        result = _run_pill(s)
        assert result["kind"] == "warn"
        assert result["label"] == "Sanitize-only mode"
        assert "detail" in result


# ---------------------------------------------------------------------------
# Static-source guarantees that don't need a JS runtime.
# ---------------------------------------------------------------------------


class TestBrandAndVersion:
    def test_brand_reads_version_from_store_not_hardcoded(self):
        """G-UI-STATUS-005: Brand renders v{version} from prop, not hardcoded."""
        shell = _shell_source()
        # Brand signature takes version:
        assert re.search(r"function Brand\(\{\s*version\s*\}\)", shell), (
            "Brand must accept a `version` prop"
        )
        # Template renders v{version}:
        assert "v{version}" in shell
        # TopNav passes store.version to Brand:
        assert "<Brand version={store.version} />" in shell
        # No hardcoded v1.2.2 / v0.x.x / v9.9.9 etc. in shell.jsx:
        assert not re.search(r">v\d+\.\d+\.\d+<", shell), (
            "shell.jsx still has a hardcoded v{n.n.n} literal"
        )

    def test_store_pulls_version_from_healthz(self):
        """G-UI-STATUS-005: data.jsx fetches /healthz and stores .version."""
        data = _data_source()
        assert "'/healthz'" in data
        assert "state.version = healthzR.value.version" in data


class TestAccessibility:
    def test_reduced_motion_block_present(self):
        """G-UI-A11Y-001: @media (prefers-reduced-motion: reduce) caps motion."""
        html = INDEX_HTML.read_text(encoding="utf-8")
        assert "@media (prefers-reduced-motion: reduce)" in html
        assert "animation-duration: 0.01ms" in html
        assert "transition-duration: 0.01ms" in html

    def test_focus_visible_uses_accent_outline(self):
        """G-UI-A11Y-002: button:focus-visible uses 2px accent outline."""
        html = INDEX_HTML.read_text(encoding="utf-8")
        # The rule may be formatted on multiple lines — match loosely:
        assert re.search(
            r"button:focus-visible\s*\{[^}]*outline:\s*2px\s+solid\s+var\(--accent\)[^}]*outline-offset:\s*2px",
            html,
        ), "button:focus-visible rule missing or misconfigured"

    def test_status_pill_has_aria_live(self):
        """G-UI-STATUS-007: rendered pill is role='status' with aria-live='polite'."""
        shell = _shell_source()
        # StatusPill component carries role + aria-live:
        pill_body = re.search(
            r"function StatusPill.*?Object\.assign\(window", shell, flags=re.DOTALL
        )
        assert pill_body, "StatusPill function not found"
        assert 'role="status"' in pill_body.group(0)
        assert 'aria-live="polite"' in pill_body.group(0)


class TestNonGuarantees:
    def test_no_sidebar_component(self):
        """NG-UI-SHELL-002: sidebar navigation is not shipped."""
        shell = _shell_source()
        assert "function SideNav" not in shell
        assert "variant === 'sidebar'" not in shell

    def test_cmdk_is_stub(self):
        """NG-UI-SHELL-001: ⌘K command palette is a stub (no modal wired up)."""
        shell = _shell_source()
        # The search icon button has an onClick that is an empty function —
        # the stub that STATES.md §10 describes.
        assert "onClick={() => {}}" in shell
        assert "Search events (⌘K)" in shell
