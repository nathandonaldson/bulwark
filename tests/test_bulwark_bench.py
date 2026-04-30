"""Spec-driven tests for bulwark_bench v2 (ADR-034).

Exercises the detector-config sweep with a fake Bulwark client. Covers
G-BENCH-001..005, -007..008, -010, -012..013 and NG-BENCH-002..004.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from bulwark.tools.bench.configs import PRESETS, parse_configs
from bulwark.tools.bench.report import render_json, render_markdown
from bulwark.tools.bench.runner import BenchRunner


# ---------------------------------------------------------------------------
# Presets (G-BENCH-012)
# ---------------------------------------------------------------------------


class TestPresets:
    def test_known_presets(self):
        for slug in ("deberta-only", "deberta+promptguard", "deberta+llm-judge", "all"):
            assert slug in PRESETS, f"{slug} missing from PRESETS"

    def test_deberta_always_on(self):
        for cfg in PRESETS.values():
            assert cfg.deberta is True, f"{cfg.slug} must have DeBERTa enabled (mandatory)"

    def test_parse_csv(self):
        cfgs = parse_configs("deberta-only,deberta+llm-judge")
        assert [c.slug for c in cfgs] == ["deberta-only", "deberta+llm-judge"]

    def test_parse_dedupes(self):
        cfgs = parse_configs("deberta-only,deberta-only,deberta-only")
        assert len(cfgs) == 1

    def test_parse_unknown_raises(self):
        with pytest.raises(ValueError):
            parse_configs("not-a-real-preset")

    def test_parse_empty_raises(self):
        with pytest.raises(ValueError):
            parse_configs("")


# ---------------------------------------------------------------------------
# Runner (G-BENCH-001..005, -010, -013)
# ---------------------------------------------------------------------------


class _FakeClient:
    """Minimal Bulwark client substitute that records every call."""
    base_url = "http://fake"
    timeout_s = 10

    def __init__(self, defense_rate=1.0, hijacked=0, total=10):
        self.calls: list[tuple[str, dict[str, Any]]] = []
        self.defense_rate = defense_rate
        self.hijacked = hijacked
        self.total = total
        self._initial_judge = {"enabled": False, "mode": "openai_compatible", "base_url": "", "model": ""}
        self._current_judge = dict(self._initial_judge)
        self._initial_promptguard = False
        self._current_promptguard = self._initial_promptguard

    def _headers(self):
        return {}

    def get_integrations(self):
        return {"promptguard": {"enabled": self._current_promptguard}}

    def get_config(self):
        return {"judge_backend": dict(self._current_judge)}

    def ensure_redteam_idle(self):
        self.calls.append(("ensure_idle", {}))

    def apply_detector_config(self, *, promptguard, llm_judge,
                              judge_base_url=None, judge_model=None,
                              judge_mode="openai_compatible", judge_api_key=None):
        self._current_promptguard = promptguard
        self._current_judge = {
            "enabled": llm_judge,
            "mode": judge_mode,
            "base_url": judge_base_url or "",
            "model": judge_model or "",
        }
        self.calls.append(("apply", {"promptguard": promptguard, "llm_judge": llm_judge,
                                     "judge_base_url": judge_base_url, "judge_model": judge_model}))

    def start_redteam(self, tier):
        self.calls.append(("start_redteam", {"tier": tier}))
        return {"status": "started"}

    def wait_for_redteam(self, timeout_s=3600, on_progress=None):
        if on_progress:
            on_progress(self.total, self.total)
        return {
            "status": "complete",
            "total": self.total,
            "defended": self.total - self.hijacked,
            "hijacked": self.hijacked,
            "format_failures": 0,
            "defense_rate": self.defense_rate,
            "duration_s": 1.0,
        }

    def set_integration_enabled(self, name, enabled):
        if name == "promptguard":
            self._current_promptguard = enabled
        self.calls.append(("set_integration", {"name": name, "enabled": enabled}))

    def activate_integration(self, name):
        if name == "promptguard":
            self._current_promptguard = True
        self.calls.append(("activate", {"name": name}))


class TestRunner:
    def test_sequential_sweep_runs_each_config(self, tmp_path):
        """G-BENCH-001: sequential per-config sweep."""
        client = _FakeClient()
        runner = BenchRunner(
            client=client, run_dir=tmp_path, tier="standard",
            configs=parse_configs("deberta-only,deberta+promptguard"),
        )
        results = runner.run_all()
        assert len(results) == 2
        slugs = [r["config_slug"] for r in results]
        assert slugs == ["deberta-only", "deberta+promptguard"]

    def test_persists_each_before_next(self, tmp_path):
        """G-BENCH-002: result file written per config before moving on."""
        client = _FakeClient()
        runner = BenchRunner(
            client=client, run_dir=tmp_path, tier="standard",
            configs=parse_configs("deberta-only,deberta+promptguard"),
        )
        runner.run_all()
        files = sorted(p.name for p in tmp_path.glob("config-*.json"))
        assert len(files) == 2
        assert "deberta-only" in files[0]

    def test_resume_skips_existing(self, tmp_path):
        """G-BENCH-003: --resume reuses prior results."""
        client = _FakeClient()
        runner = BenchRunner(
            client=client, run_dir=tmp_path, tier="standard",
            configs=parse_configs("deberta-only"), resume=False,
        )
        runner.run_all()
        client.calls.clear()
        runner2 = BenchRunner(
            client=client, run_dir=tmp_path, tier="standard",
            configs=parse_configs("deberta-only"), resume=True,
        )
        runner2.run_all()
        # apply_detector_config should NOT have been called again.
        applies = [c for c in client.calls if c[0] == "apply"]
        assert applies == []

    def test_judge_config_propagates(self, tmp_path):
        """LLM judge slug forwards base_url/model to apply_detector_config."""
        client = _FakeClient()
        runner = BenchRunner(
            client=client, run_dir=tmp_path, tier="standard",
            configs=parse_configs("deberta+llm-judge"),
            judge_base_url="http://192.168.1.78:1234/v1",
            judge_model="prompt-injection-judge-8b",
        )
        runner.run_all()
        applies = [c for c in client.calls if c[0] == "apply"]
        assert applies and applies[0][1]["llm_judge"] is True
        assert applies[0][1]["judge_base_url"] == "http://192.168.1.78:1234/v1"
        assert applies[0][1]["judge_model"] == "prompt-injection-judge-8b"

    def test_results_capture_metrics(self, tmp_path):
        """G-BENCH-004 / G-BENCH-005: defense rate + avg latency in payload."""
        client = _FakeClient(defense_rate=0.95, hijacked=2, total=20)
        runner = BenchRunner(
            client=client, run_dir=tmp_path, tier="standard",
            configs=parse_configs("deberta-only"),
        )
        results = runner.run_all()
        r = results[0]
        assert r["defense_rate"] == 0.95
        assert r["hijacked"] == 2
        assert r["total_probes"] == 20
        assert r["avg_latency_s"] == pytest.approx(1.0 / 20)

    def test_restores_dashboard_state(self, tmp_path, monkeypatch):
        """G-BENCH-013: run_all restores dashboard state in finally."""
        client = _FakeClient()
        client._current_promptguard = True
        client._initial_promptguard = True
        import httpx
        captured: list[dict] = []
        class _StubResp:
            def raise_for_status(self): pass
        def _fake_put(url, **kw):
            captured.append({"url": url, **kw})
            return _StubResp()
        monkeypatch.setattr(httpx, "put", _fake_put)
        runner = BenchRunner(
            client=client, run_dir=tmp_path, tier="standard",
            configs=parse_configs("deberta-only"),
        )
        runner.run_all()
        # Snapshot was on; restore should reactivate PromptGuard.
        assert client._current_promptguard is True


# ---------------------------------------------------------------------------
# Reports (G-BENCH-007 / G-BENCH-008)
# ---------------------------------------------------------------------------


class TestReports:
    def test_json_report_has_v2_schema(self):
        results = [{"config_slug": "deberta-only", "defense_rate": 1.0, "avg_latency_s": 0.05,
                    "total_probes": 10, "hijacked": 0}]
        out = render_json(results, tier="standard")
        assert out["schema"] == "bulwark_bench/v2"
        assert out["tier"] == "standard"
        assert out["configurations"] == results

    def test_markdown_sorts_by_defense_then_latency(self):
        results = [
            {"config_slug": "all",                "config_name": "all",                "defense_rate": 1.0,  "avg_latency_s": 1.5,  "total_probes": 10, "hijacked": 0},
            {"config_slug": "deberta-only",       "config_name": "DeBERTa only",       "defense_rate": 1.0,  "avg_latency_s": 0.05, "total_probes": 10, "hijacked": 0},
            {"config_slug": "deberta+promptguard","config_name": "DeBERTa + PG",       "defense_rate": 0.95, "avg_latency_s": 0.08, "total_probes": 10, "hijacked": 1},
        ]
        md = render_markdown(results, tier="standard")
        deberta_idx = md.index("DeBERTa only")
        all_idx = md.index("| 2 | all")
        pg_idx = md.index("DeBERTa + PG")
        assert deberta_idx < all_idx < pg_idx

    def test_markdown_no_cost_column(self):
        """NG-BENCH-002 v2: cost column is dropped."""
        results = [{"config_slug": "deberta-only", "config_name": "DeBERTa only",
                    "defense_rate": 1.0, "avg_latency_s": 0.05, "total_probes": 10, "hijacked": 0}]
        md = render_markdown(results, tier="standard")
        assert "cost" not in md.lower(), "cost column should be removed in v2 reports"

    def test_markdown_caps_defense_when_hijacks(self):
        """G-REDTEAM-SCORE-007: never round to 100% when hijacks > 0."""
        results = [{"config_slug": "x", "config_name": "x",
                    "defense_rate": 1.0, "avg_latency_s": 0.1,
                    "total_probes": 100, "hijacked": 1}]
        md = render_markdown(results, tier="standard")
        assert "99.99%" in md and "100.00%" not in md

    def test_no_parallel_execution_doc(self):
        """NG-BENCH-003: documented in contract — sequential only.

        No CLI flag for parallelism exists; runner.run_all is a serial loop.
        """
        from bulwark.tools.bench import runner as runner_mod
        src = Path(runner_mod.__file__).read_text()
        assert "parallel" not in src.lower() or "no parallel" in src.lower(), \
            "runner must not introduce parallel execution"

    def test_no_capability_autodiscovery(self):
        """NG-BENCH-004: bench does not probe model lists."""
        from bulwark.tools.bench import bulwark_client as bc
        src = Path(bc.__file__).read_text()
        assert "/v1/llm/models" not in src
        assert "list_models" not in src

    def test_v1_model_sweep_removed(self):
        """NG-BENCH-MODEL-SWEEP-REMOVED."""
        from bulwark.tools.bench import bulwark_client as bc
        src = Path(bc.__file__).read_text()
        assert "def swap_model(" not in src
