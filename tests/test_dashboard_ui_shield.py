"""Spec-driven tests for dashboard Shield page — spec/contracts/dashboard_ui.yaml."""
import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest


SRC = Path(__file__).parent.parent / "src" / "bulwark" / "dashboard" / "static" / "src"
INDEX_HTML = Path(__file__).parent.parent / "src" / "bulwark" / "dashboard" / "static" / "index.html"
PAGE_SHIELD = SRC / "page-shield.jsx"


def _run_has_incident(events: list[dict], now_ms: int) -> bool:
    """Execute hasRecentIncident(events, now_ms) via Node."""
    node = shutil.which("node")
    if not node:
        pytest.skip("node not on PATH — cannot exercise hasRecentIncident")

    fn_src = re.search(
        r"function hasRecentIncident\(events, nowMs\) \{.*?\n\}\n",
        PAGE_SHIELD.read_text(),
        flags=re.DOTALL,
    )
    assert fn_src, "hasRecentIncident not found in page-shield.jsx"

    harness = (
        fn_src.group(0) + "\n"
        + f"process.stdout.write(JSON.stringify(hasRecentIncident({json.dumps(events)}, {now_ms})));"
    )
    out = subprocess.run(
        [node, "-e", harness],
        check=True, capture_output=True, text=True, timeout=5,
    )
    return json.loads(out.stdout)


# ---------------------------------------------------------------------------
# G-UI-INCIDENT-001 / 002 / 003 — banner trigger logic
# ---------------------------------------------------------------------------


class TestIncidentBanner:
    def test_blocked_within_30m_triggers_incident(self):
        """G-UI-INCIDENT-001: blocked event within the window → incident."""
        now = 10_000_000
        events = [{"verdict": "blocked", "ts": now - 5 * 60 * 1000}]
        assert _run_has_incident(events, now) is True

    def test_blocked_older_than_30m_does_not_trigger(self):
        """G-UI-INCIDENT-002: blocked event just over 30m old → no incident."""
        now = 10_000_000
        events = [{"verdict": "blocked", "ts": now - 31 * 60 * 1000}]
        assert _run_has_incident(events, now) is False

    def test_non_blocked_events_never_trigger(self):
        """G-UI-INCIDENT-001: only verdict='blocked' counts as an incident."""
        now = 10_000_000
        events = [
            {"verdict": "passed",   "ts": now - 1_000},
            {"verdict": "modified", "ts": now - 1_000},
            {"verdict": "clean",    "ts": now - 1_000},
        ]
        assert _run_has_incident(events, now) is False

    def test_empty_events_does_not_trigger(self):
        """G-UI-INCIDENT-002 edge case: empty event list → no incident."""
        assert _run_has_incident([], 10_000_000) is False

    def test_mixed_returns_true_when_any_recent_blocked(self):
        """G-UI-INCIDENT-001: any matching event in the window triggers."""
        now = 10_000_000
        events = [
            {"verdict": "blocked", "ts": now - 40 * 60 * 1000},  # outside
            {"verdict": "passed",  "ts": now - 1 * 60 * 1000},
            {"verdict": "blocked", "ts": now - 2 * 60 * 1000},   # inside
        ]
        assert _run_has_incident(events, now) is True

    def test_banner_carries_role_alert(self):
        """G-UI-INCIDENT-003: incident banner element has role='alert'."""
        src = PAGE_SHIELD.read_text()
        # HeroStatus starts the incident branch with an amber-soft panel. The
        # wrapper carries role="alert" so assistive tech announces new attacks.
        hero_start = src.index("function HeroStatus")
        # Find the next top-level function (StatTile or ShieldRadial) to bound
        # the HeroStatus body:
        next_fn_candidates = [
            src.index("function StatTile", hero_start),
            src.index("function ShieldRadial", hero_start),
        ]
        hero_body = src[hero_start:min(next_fn_candidates)]
        assert 'role="alert"' in hero_body
        # Banner uses the token, not the old fallback:
        assert "var(--amber-soft, " not in hero_body


# ---------------------------------------------------------------------------
# G-UI-TOKENS-001 / TOKENS-STAGES-001 — no hardcoded hex in ring colors
# ---------------------------------------------------------------------------


class TestTokens:
    def test_radial_shield_has_no_inline_hex(self):
        """G-UI-TOKENS-001: RadialShield rings reference tokens only."""
        src = PAGE_SHIELD.read_text()
        ring_block = re.search(
            r"const rings = \[.*?\];",
            src, flags=re.DOTALL,
        )
        assert ring_block, "rings array not found"
        body = ring_block.group(0)
        # No 3- or 6-digit hex literals anywhere in the rings block:
        assert not re.search(r"#[0-9a-fA-F]{3,6}", body), (
            "RadialShield ring block still contains hex colors: " + body
        )
        # Explicitly uses the per-stage tokens:
        for stage in ("sanitizer", "boundary", "detection", "bridge", "execute"):
            assert f"var(--stage-{stage})" in body, f"missing --stage-{stage} token"

    def test_root_defines_stage_tokens(self):
        """G-UI-TOKENS-STAGES-001: all 7 --stage-* tokens defined in :root."""
        html = INDEX_HTML.read_text()
        root_block = re.search(r":root\s*\{.*?\n\s*\}", html, flags=re.DOTALL)
        assert root_block, ":root block not found in index.html"
        body = root_block.group(0)
        for stage in ("sanitizer", "boundary", "detection", "analyze", "bridge", "canary", "execute"):
            assert f"--stage-{stage}:" in body, f":root missing --stage-{stage}"


# ---------------------------------------------------------------------------
# G-UI-SHIELD-001 / 002 / 003 — single variant, stats wired, layers visible
# ---------------------------------------------------------------------------


class TestShieldLayout:
    def test_only_radial_variant_ships(self):
        """G-UI-SHIELD-001: PageShield returns ShieldRadial unconditionally."""
        src = PAGE_SHIELD.read_text()
        assert "function ShieldData"   not in src
        assert "function ShieldHybrid" not in src
        assert "function BigSparkline" not in src
        # PageShield has no variant branching:
        page_body = re.search(
            r"function PageShield\(\{\s*store\s*\}\)\s*\{[^}]*\}",
            src, flags=re.DOTALL,
        )
        assert page_body, "PageShield signature changed unexpectedly"
        assert "variant" not in page_body.group(0), (
            "PageShield must not reference a layout variant prop"
        )

    def test_stat_tiles_read_from_store(self):
        """G-UI-SHIELD-002: stat tiles bind to store.stats24h fields."""
        src = PAGE_SHIELD.read_text()
        # All four stats come from s24 = store.stats24h:
        assert "const s24 = store.stats24h" in src
        for field in ("processed", "blocked", "canary", "bridge"):
            assert f"s24.{field}" in src, f"StatTile is not reading s24.{field}"

    def test_layer_rows_unconditional(self):
        """G-UI-SHIELD-003: LAYERS.map renders every layer; no filter by on/off."""
        src = PAGE_SHIELD.read_text()
        # The Shield page maps over LAYERS directly with no conditional filter:
        assert "LAYERS.map(layer =>" in src
        assert ".filter(" not in re.search(r"LAYERS[^;]*map", src).group(0)

    def test_no_alternate_layouts(self):
        """NG-UI-SHIELD-001: no alternate Shield layouts ship (data / hybrid)."""
        src = PAGE_SHIELD.read_text()
        for dropped in ("ShieldData", "ShieldHybrid", "BigSparkline"):
            assert dropped not in src
