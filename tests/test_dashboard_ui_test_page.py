"""Spec-driven tests for dashboard Test page — spec/contracts/dashboard_ui.yaml."""
import re
from pathlib import Path

import pytest


SRC = Path(__file__).parent.parent / "src" / "bulwark" / "dashboard" / "static" / "src"
PAGE_TEST = SRC / "page-test.jsx"
DATA_JSX = SRC / "data.jsx"
INDEX_HTML = Path(__file__).parent.parent / "src" / "bulwark" / "dashboard" / "static" / "index.html"


def _test_src():
    return PAGE_TEST.read_text()


def _data_src():
    return DATA_JSX.read_text()


# ---------------------------------------------------------------------------
# G-UI-PRESETS-001 — presets from the store, not inline
# ---------------------------------------------------------------------------


class TestPresetsSource:
    def test_page_test_uses_store_presets(self):
        """G-UI-PRESETS-001: Test page reads presets from store.presets."""
        src = _test_src()
        assert "store.presets" in src
        assert re.search(r"store\.presets\.filter\(p => p\.family === category\)", src)

    def test_no_inline_preset_list(self):
        """G-UI-PRESETS-001: no inline PRESETS array in page-test.jsx."""
        src = _test_src()
        assert "const PRESETS" not in src
        # Also confirm data.jsx no longer defines PRESETS as a module-level const:
        data = _data_src()
        assert "const PRESETS" not in data


# ---------------------------------------------------------------------------
# G-UI-TEST-RUN-001 / 002 — real pipeline call + honest status
# ---------------------------------------------------------------------------


class TestRunPipeline:
    def test_runpipeline_calls_store_runclean(self):
        """G-UI-TEST-RUN-001: runPipeline calls BulwarkStore.runClean."""
        src = _test_src()
        start = src.index("async function runPipeline()")
        end = src.index("\n  }\n", start)  # inner function body, 2-space indent
        body = src[start:end]
        assert "BulwarkStore.runClean(payload" in body
        # No Math.random() fakery and no hardcoded step latencies:
        assert "Math.random" not in body
        assert "willBlock" not in body
        assert "setTimeout(() => reveal" not in body

    def test_runclean_posts_v1_clean(self):
        """G-UI-TEST-RUN-001: runClean POSTs /v1/clean with {content, source}."""
        data = _data_src()
        start = data.index("async runClean(")
        end = data.index("\n    },\n", start)
        body = data[start:end]
        assert "/v1/clean" in body
        assert "method: 'POST'" in body
        assert "content" in body and "source" in body

    def test_trace_status_derives_from_response(self):
        """G-UI-TEST-RUN-002: status is honest — blocked iff backend says so."""
        src = _test_src()
        assert "res.blocked === true || res.httpStatus === 422" in src
        assert "res.error && !blocked ? 'error'" in src


# ---------------------------------------------------------------------------
# G-UI-TEST-REPLAY-001 — consume bulwark:goto payload from Events
# ---------------------------------------------------------------------------


class TestReplayPayload:
    def test_listens_for_bulwark_goto_with_payload(self):
        """G-UI-TEST-REPLAY-001: PageTest listens for bulwark:goto and sets payload."""
        src = _test_src()
        assert "window.addEventListener('bulwark:goto', onGoto)" in src
        # Handler extracts payload from event.detail:
        assert re.search(
            r"const p = e\.detail && e\.detail\.payload;\s*\n\s*if \(typeof p === 'string' && p\) setPayload\(p\);",
            src,
        )


# ---------------------------------------------------------------------------
# G-UI-TEST-TIERS-001 / 002 — tiers from backend
# ---------------------------------------------------------------------------


class TestRedTeamTiers:
    def test_tiers_fetched_from_store(self):
        """G-UI-TEST-TIERS-001: RedTeam fetches tiers via BulwarkStore.fetchRedteamTiers()."""
        src = _test_src()
        assert "BulwarkStore.fetchRedteamTiers()" in src
        # No hardcoded tier list:
        assert "{ id: 'smoke'" not in src
        assert "{ id: 'standard'" not in src.replace("tiers.find(t => t.id === tier)", "")
        # Actually simpler: no hardcoded probe counts:
        assert "4270" not in src
        assert "32745" not in src

    def test_fetch_tiers_hits_endpoint(self):
        """G-UI-TEST-TIERS-001: fetchRedteamTiers GETs /api/redteam/tiers."""
        data = _data_src()
        start = data.index("async fetchRedteamTiers()")
        end = data.index("\n    },\n", start)
        body = data[start:end]
        assert "/api/redteam/tiers" in body
        assert "state.redteamTiers = res" in body

    def test_run_disabled_when_garak_missing(self):
        """G-UI-TEST-TIERS-002: Run button disabled when garak is not installed."""
        src = _test_src()
        assert "tiersData.garak_installed" in src
        # The disabled attribute on the Run button considers garak_installed:
        assert "disabled={!tier || !tiersData.garak_installed}" in src


# ---------------------------------------------------------------------------
# G-UI-TEST-REPORTS-001..004 — past reports wiring
# ---------------------------------------------------------------------------


class TestReports:
    def test_reports_list_from_store(self):
        """G-UI-TEST-REPORTS-001: ReportsList reads store.redteamReports."""
        src = _test_src()
        assert "store.redteamReports" in src
        # No hardcoded report entries:
        assert "91m 20s" not in src
        assert "18/04/2026" not in src

    def test_fetch_reports_hits_endpoint(self):
        """G-UI-TEST-REPORTS-001: fetchRedteamReports GETs /api/redteam/reports."""
        data = _data_src()
        start = data.index("async fetchRedteamReports()")
        end = data.index("\n    },\n", start)
        body = data[start:end]
        assert "/api/redteam/reports" in body
        assert "state.redteamReports" in body

    def test_retest_posts_filename(self):
        """G-UI-TEST-REPORTS-002: retestReport POSTs /api/redteam/retest with filename."""
        data = _data_src()
        start = data.index("async retestReport(filename)")
        end = data.index("\n    },\n", start)
        body = data[start:end]
        assert "/api/redteam/retest" in body
        assert "method: 'POST'" in body
        assert "filename" in body

    def test_retest_button_calls_store_action(self):
        """G-UI-TEST-REPORTS-002: Retest button wires to BulwarkStore.retestReport."""
        src = _test_src()
        assert "BulwarkStore.retestReport(report.filename)" in src

    def test_json_button_opens_download_url(self):
        """G-UI-TEST-REPORTS-002: JSON button opens /api/redteam/reports/{filename}."""
        src = _test_src()
        assert 'window.open(`/api/redteam/reports/${encodeURIComponent(report.filename)}`' in src

    def test_score_caps_at_9999_when_hijacked(self):
        """G-UI-TEST-REPORTS-003: hijacked > 0 caps the displayed score at 99.99%."""
        src = _test_src()
        assert "hijacked > 0 && raw >= 100 ? 99.99" in src

    def test_reports_refetch_after_run_completes(self):
        """G-UI-TEST-REPORTS-004: reports list re-fetches when a run completes."""
        src = _test_src()
        # The effect runs on [store.running] and re-fetches when it transitions to null:
        assert "wasRunning.current && !store.running" in src
        assert "BulwarkStore.fetchRedteamReports()" in src


# ---------------------------------------------------------------------------
# G-UI-TOKENS-003 — no hex anywhere in JSX (global guard)
# ---------------------------------------------------------------------------


class TestGlobalTokens:
    def test_no_hex_colors_in_any_jsx(self):
        """G-UI-TOKENS-003: JSX files have no inline hex colors (non-SVG)."""
        offenders = []
        for jsx in SRC.glob("*.jsx"):
            for i, line in enumerate(jsx.read_text().splitlines(), 1):
                # Skip SVG path definitions which may legitimately contain # as fragments
                # (actually SVG paths don't use #, so any #xxx in JSX is suspicious):
                if re.search(r"#[0-9a-fA-F]{3,6}", line):
                    offenders.append(f"{jsx.name}:{i}: {line.strip()}")
        assert not offenders, "Hex color literals remain in JSX:\n" + "\n".join(offenders)


class TestNonGuarantees:
    def test_no_setTimeout_reveal_animation(self):
        """NG-UI-TEST-001: no fake per-step reveal animation."""
        src = _test_src()
        assert "setTimeout(() => reveal" not in src

    def test_curl_is_stub(self):
        """NG-UI-TEST-002: cURL button exists but does nothing."""
        src = _test_src()
        # cURL button is present but has no onClick handler:
        assert ">cURL<" in src
        # No export/copy helpers pretending to generate curl:
        assert "curl -X" not in src


# ---------------------------------------------------------------------------
# Store shape sanity
# ---------------------------------------------------------------------------


class TestDataStoreShape:
    def test_store_exposes_redteam_state(self):
        """State carries redteamTiers and redteamReports."""
        data = _data_src()
        assert "redteamTiers:" in data
        assert "redteamReports:" in data

    def test_store_exposes_runclean_action(self):
        """Store has runClean + fetchRedteamTiers + fetchRedteamReports + retestReport."""
        data = _data_src()
        for fn in ("runClean(", "fetchRedteamTiers()", "fetchRedteamReports()", "retestReport(filename)"):
            assert fn in data, f"data.jsx missing store action {fn}"
