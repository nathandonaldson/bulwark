"""Spec-driven tests for dashboard Events page — spec/contracts/dashboard_ui.yaml."""
import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest


SRC = Path(__file__).parent.parent / "src" / "bulwark" / "dashboard" / "static" / "src"
PAGE_EVENTS = SRC / "page-events.jsx"


def _extract_fn(source: str, name: str) -> str:
    """Pull a named top-level JS function out of a JSX file."""
    m = re.search(rf"function {name}\([^)]*\) \{{.*?\n\}}\n", source, flags=re.DOTALL)
    assert m, f"{name}() not found in page-events.jsx"
    return m.group(0)


from tests._node_helpers import run_node_eval


def _run_node(harness: str):
    return run_node_eval(harness, skip_reason="node not on PATH — cannot exercise page-events.jsx logic")


# ---------------------------------------------------------------------------
# G-UI-FILTER-001 — filterEvents narrows correctly
# ---------------------------------------------------------------------------

class TestFilterEvents:
    def _call(self, events, opts):
        src = PAGE_EVENTS.read_text()
        harness = (
            _extract_fn(src, "filterEvents") + "\n"
            + f"process.stdout.write(JSON.stringify(filterEvents({json.dumps(events)}, {json.dumps(opts)})));"
        )
        return _run_node(harness)

    def _events(self):
        return [
            {"id": "a", "verdict": "passed",   "layer": "sanitizer", "detail": "stripped 3 zero-width", "source": "api:clean:email"},
            {"id": "b", "verdict": "blocked",  "layer": "bridge",    "detail": "ignore previous",       "source": "api:clean:dashboard"},
            {"id": "c", "verdict": "modified", "layer": "sanitizer", "detail": "normalized emoji",      "source": "api:guard"},
            {"id": "d", "verdict": "passed",   "layer": "canary",    "detail": "12 tokens OK",           "source": "cli:test"},
        ]

    def test_all_filter_returns_all(self):
        """G-UI-FILTER-001: no filter narrows nothing."""
        out = self._call(self._events(), {"filter": "all", "layerFilter": "all", "search": ""})
        assert [e["id"] for e in out] == ["a", "b", "c", "d"]

    def test_verdict_filter_exact_match(self):
        """G-UI-FILTER-001: filter='blocked' keeps only blocked rows."""
        out = self._call(self._events(), {"filter": "blocked", "layerFilter": "all", "search": ""})
        assert [e["id"] for e in out] == ["b"]

    def test_layer_filter_exact_match(self):
        """G-UI-FILTER-001: layerFilter='sanitizer' keeps only sanitizer rows."""
        out = self._call(self._events(), {"filter": "all", "layerFilter": "sanitizer", "search": ""})
        assert [e["id"] for e in out] == ["a", "c"]

    def test_search_matches_detail(self):
        """G-UI-FILTER-001: search matches case-insensitive substring in detail."""
        out = self._call(self._events(), {"filter": "all", "layerFilter": "all", "search": "IGNORE"})
        assert [e["id"] for e in out] == ["b"]

    def test_search_matches_source(self):
        """G-UI-FILTER-001: search also matches substring in source field."""
        out = self._call(self._events(), {"filter": "all", "layerFilter": "all", "search": "cli:"})
        assert [e["id"] for e in out] == ["d"]

    def test_combined_filters(self):
        """G-UI-FILTER-001: filters compose (AND across verdict+layer+search)."""
        out = self._call(self._events(), {"filter": "passed", "layerFilter": "sanitizer", "search": "zero"})
        assert [e["id"] for e in out] == ["a"]


# ---------------------------------------------------------------------------
# G-UI-EMPTY-004 — isAnyFilterActive
# ---------------------------------------------------------------------------

class TestIsAnyFilterActive:
    def _call(self, filter_v, layer_v, search_v):
        src = PAGE_EVENTS.read_text()
        harness = (
            _extract_fn(src, "isAnyFilterActive") + "\n"
            + f"process.stdout.write(JSON.stringify(isAnyFilterActive({json.dumps(filter_v)}, {json.dumps(layer_v)}, {json.dumps(search_v)})));"
        )
        return _run_node(harness)

    def test_defaults_return_false(self):
        """G-UI-EMPTY-004: all defaults → no filter active."""
        assert self._call("all", "all", "") is False

    def test_verdict_filter_counts(self):
        """G-UI-EMPTY-004: any verdict filter counts."""
        assert self._call("blocked", "all", "") is True

    def test_layer_filter_counts(self):
        """G-UI-EMPTY-004: any layer filter counts."""
        assert self._call("all", "sanitizer", "") is True

    def test_whitespace_only_search_does_not_count(self):
        """G-UI-EMPTY-004: pure-whitespace search does NOT count as active."""
        assert self._call("all", "all", "   ") is False

    def test_real_search_counts(self):
        """G-UI-EMPTY-004: non-empty search counts."""
        assert self._call("all", "all", "injection") is True


# ---------------------------------------------------------------------------
# G-UI-EMPTY-001 / 002 / 003 — empty-state split + clear action
# ---------------------------------------------------------------------------


class TestEmptyState:
    def test_empty_state_component_split_by_state(self):
        """G-UI-EMPTY-001 + G-UI-EMPTY-002: EventsEmptyState branches on (hasAnyEvents, anyFilterActive)."""
        src = PAGE_EVENTS.read_text()
        # Component marks the branch via data-empty-state:
        assert 'data-empty-state={state}' in src
        # The 'no-events' branch fires only when !hasAnyEvents && !anyFilterActive:
        assert "(!hasAnyEvents && !anyFilterActive) ? 'no-events' : 'filter-miss'" in src
        # 'no-events' branch has a primary 'Run a test' CTA dispatching goto:
        assert "Run a test" in src
        # 'filter-miss' branch has a 'Clear filters' action:
        assert "Clear filters" in src

    def test_run_a_test_dispatches_goto(self):
        """G-UI-EMPTY-001: "Run a test" CTA dispatches bulwark:goto → test page."""
        src = PAGE_EVENTS.read_text()
        # The CTA handler dispatches a CustomEvent to navigate:
        m = re.search(
            r"Run a test.*?bulwark:goto.*?page:\s*'test'",
            src, flags=re.DOTALL,
        )
        assert m, "Run a test CTA must dispatch bulwark:goto with page:'test'"

    def test_clear_filters_resets_all(self):
        """G-UI-EMPTY-003: clearFilters() sets filter+layerFilter+search back to defaults."""
        src = PAGE_EVENTS.read_text()
        m = re.search(
            r"const clearFilters = \(\) => \{([^}]*)\};",
            src,
        )
        assert m, "clearFilters handler not found"
        body = m.group(1)
        assert "setFilter('all')" in body
        assert "setLayerFilter('all')" in body
        assert "setSearch('')" in body


# ---------------------------------------------------------------------------
# G-UI-EXPAND-001 / 002 / 003 — row expansion detail
# ---------------------------------------------------------------------------


class TestRowExpansion:
    def test_modified_uses_metadata_before_after(self):
        """G-UI-EXPAND-001: modified verdict uses event.metadata.before/after."""
        src = PAGE_EVENTS.read_text()
        # Before/after extraction from metadata:
        assert "md.before ?? md.original" in src
        assert "md.after  ?? md.sanitized" in src
        # When both are present, render two panes (red-soft + green-soft):
        assert "var(--red-soft)"   in src
        assert "var(--green-soft)" in src

    def test_blocked_has_replay_button_dispatching_goto(self):
        """G-UI-EXPAND-002: blocked verdict renders Replay-in-Test → bulwark:goto."""
        src = PAGE_EVENTS.read_text()
        # Button sits inside a `{event.verdict === 'blocked' && (...)}` branch.
        # Its onClick dispatches bulwark:goto targeting the Test page.
        m = re.search(
            r"event\.verdict === 'blocked' &&.*?bulwark:goto.*?page:\s*'test'.*?Replay in Test",
            src, flags=re.DOTALL,
        )
        assert m, "Blocked row must have a Replay-in-Test button dispatching bulwark:goto"

    def test_trace_fallback_when_metadata_missing(self):
        """G-UI-EXPAND-003: _defaultTrace falls back to a per-layer pipeline view.

        v2.5.16: was `LAYERS.slice(0, 5)` (no-op cap on a 4-entry list, comment
        was v1 "5-step" vocabulary); now `LAYERS.map(...)` over the canonical
        4-layer list (sanitizer, detection, boundary, canary)."""
        src = PAGE_EVENTS.read_text()
        m = re.search(r"function _defaultTrace\(event\) \{.*?\}", src, flags=re.DOTALL)
        assert m, "_defaultTrace not found"
        body = m.group(0)
        assert "LAYERS.map" in body, "_defaultTrace should iterate LAYERS via .map(...)"
        assert "LAYERS.slice(0, 5)" not in body, (
            "v1 'first 5 layers' slice should be removed (LAYERS has 4 entries)"
        )


class TestNonGuarantees:
    def test_no_persisted_filters(self):
        """NG-UI-EVENTS-001: filter state is React-only — no localStorage."""
        src = PAGE_EVENTS.read_text()
        assert "localStorage" not in src

    def test_row_render_is_capped(self):
        """NG-UI-EVENTS-002: no more than 120 rows rendered at once."""
        src = PAGE_EVENTS.read_text()
        assert "filtered.slice(0, 120)" in src
