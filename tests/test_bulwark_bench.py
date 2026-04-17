"""Spec-driven tests for bulwark_bench — spec/contracts/bulwark_bench.yaml."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest


# ---------------------------------------------------------------------------
# Pricing table (G-BENCH-006, G-BENCH-009)
# ---------------------------------------------------------------------------

class TestPricing:
    def test_known_anthropic_model_priced(self):
        """G-BENCH-006: Anthropic models have non-zero $/Mtok entries."""
        from bulwark_bench.pricing import lookup
        p = lookup("claude-haiku-4-5")
        assert p.input_per_mtok > 0
        assert p.output_per_mtok > 0

    def test_local_model_defaults_to_free(self):
        """G-BENCH-006: Models served via known local backends default to $0."""
        from bulwark_bench.pricing import lookup
        p = lookup("google/gemma-4-26b-a4b")
        assert p.input_per_mtok == 0
        assert p.output_per_mtok == 0

    def test_unknown_model_returns_zero_with_warning(self, capsys):
        """G-BENCH-009: Unknown model returns $0 and warns on stderr."""
        from bulwark_bench.pricing import lookup
        p = lookup("nonexistent/imaginary-model-xyz")
        assert p.input_per_mtok == 0
        assert p.output_per_mtok == 0
        captured = capsys.readouterr()
        assert "imaginary-model-xyz" in (captured.err + captured.out)

    def test_lookup_is_case_insensitive(self):
        """G-BENCH-009: Lookup normalizes case so 'Claude-Haiku-4-5' finds the entry."""
        from bulwark_bench.pricing import lookup
        lower = lookup("claude-haiku-4-5")
        mixed = lookup("Claude-Haiku-4-5")
        assert mixed.input_per_mtok == lower.input_per_mtok

    def test_cost_calculation(self):
        """G-BENCH-006: Cost = (tokens_in * in_rate + tokens_out * out_rate) / 1e6."""
        from bulwark_bench.pricing import compute_cost, Pricing
        pricing = Pricing(input_per_mtok=1.0, output_per_mtok=2.0)  # $1/$2 per Mtok
        cost = compute_cost(pricing, prompt_tokens=1_000_000, completion_tokens=1_000_000)
        assert cost == pytest.approx(3.0), "1M in * $1 + 1M out * $2 = $3.00"


# ---------------------------------------------------------------------------
# Report generation (G-BENCH-007, G-BENCH-008)
# ---------------------------------------------------------------------------

def _make_result(model: str, defense_rate: float, avg_latency: float, cost: float = 0.0,
                 hijacked: int = 0, total: int = 100) -> dict[str, Any]:
    return {
        "model": model,
        "defense_rate": defense_rate,
        "avg_latency_s": avg_latency,
        "total_probes": total,
        "hijacked": hijacked,
        "duration_s": avg_latency * total,
        "cost_usd": cost,
        "tokens_in_sample": 800,
        "tokens_out_sample": 300,
    }


class TestReport:
    def test_markdown_table_sorted_by_defense_then_latency(self, tmp_path):
        """G-BENCH-008: defense desc, latency asc."""
        from bulwark_bench.report import render_markdown
        results = [
            _make_result("slow-but-perfect", 1.0, 5.0),
            _make_result("fast-leaky", 0.95, 0.3),
            _make_result("fast-perfect", 1.0, 0.5),
            _make_result("slow-leaky", 0.95, 4.0),
        ]
        md = render_markdown(results, tier="quick")
        # "fast-perfect" (100%, 0.5s) beats "slow-but-perfect" (100%, 5s)
        assert md.index("fast-perfect") < md.index("slow-but-perfect")
        # Both 100% beat the 95% models
        assert md.index("slow-but-perfect") < md.index("fast-leaky")
        assert md.index("fast-leaky") < md.index("slow-leaky")

    def test_json_report_preserves_input_order(self, tmp_path):
        """JSON records model order as provided (useful for matching CLI input)."""
        from bulwark_bench.report import render_json
        results = [
            _make_result("b", 0.98, 1.0),
            _make_result("a", 1.0, 1.0),
        ]
        payload = render_json(results, tier="quick")
        assert [r["model"] for r in payload["results"]] == ["b", "a"]

    def test_markdown_hijacks_shown_in_red_column(self, tmp_path):
        """Report highlights non-zero hijack counts so leaky models stand out."""
        from bulwark_bench.report import render_markdown
        results = [_make_result("some-model", 0.97, 1.0, hijacked=3)]
        md = render_markdown(results, tier="quick")
        assert "3" in md  # hijack count appears
        # Perfect defender should not have a hijack number polluting the row
        results2 = [_make_result("perfect", 1.0, 1.0, hijacked=0)]
        md2 = render_markdown(results2, tier="quick")
        # Present but zero — fine. Just ensure header mentions hijacks.
        assert "hijack" in md2.lower()

    def test_family_breakdown_rendered_when_present(self, tmp_path):
        """Standard-tier results with by_family payload get a per-family table."""
        from bulwark_bench.report import render_markdown
        results = [
            {**_make_result("a", 1.0, 1.0), "by_family": {
                "dan": {"total": 10, "defended": 10, "hijacked": 0, "format_failures": 0},
                "encoding": {"total": 20, "defended": 19, "hijacked": 0, "format_failures": 1},
            }},
            {**_make_result("b", 0.95, 2.0, hijacked=1), "by_family": {
                "dan": {"total": 10, "defended": 9, "hijacked": 1, "format_failures": 0},
                "encoding": {"total": 20, "defended": 20, "hijacked": 0, "format_failures": 0},
            }},
        ]
        md = render_markdown(results, tier="standard")
        assert "By probe family" in md
        assert "| dan |" in md
        assert "| encoding |" in md
        assert "⚠️1" in md  # hijack flagged in the family cell

    def test_report_shows_near_100_without_rounding_up(self, tmp_path):
        """G-REDTEAM-SCORE-007 discipline in the bench report — never '100%' when hijacks>0."""
        from bulwark_bench.report import render_markdown
        # 1 hijack in 4268 → 99.98% defended
        results = [_make_result("almost-perfect", 0.9998, 1.0, hijacked=1, total=4268)]
        md = render_markdown(results, tier="standard")
        assert "100%" not in md or "100.00%" not in md
        assert "99.98" in md or "99.97" in md


# ---------------------------------------------------------------------------
# Resume behavior (G-BENCH-002, G-BENCH-003)
# ---------------------------------------------------------------------------

class TestResume:
    def test_completed_result_skipped_on_resume(self, tmp_path):
        """G-BENCH-003: Existing per-model result file → runner skips that model."""
        from bulwark_bench.runner import _should_skip
        run_dir = tmp_path / "run"
        run_dir.mkdir()
        # Simulate a completed model
        (run_dir / "model-0-google_gemma.json").write_text('{"model":"google/gemma","defense_rate":0.99}')
        assert _should_skip(run_dir, 0, "google/gemma", resume=True) is True
        # Not resuming → never skip
        assert _should_skip(run_dir, 0, "google/gemma", resume=False) is False
        # Resume, but no result yet → don't skip
        assert _should_skip(run_dir, 1, "other/model", resume=True) is False

    def test_model_result_filename_is_filesystem_safe(self, tmp_path):
        """G-BENCH-002: Filenames from model ids are safe (no slashes, spaces)."""
        from bulwark_bench.runner import _result_filename
        name = _result_filename(0, "google/gemma-4-26b-a4b")
        assert "/" not in name
        assert name.startswith("model-0-")
        assert name.endswith(".json")

    def test_persist_before_next_model(self, tmp_path):
        """G-BENCH-002: A single model's result lands on disk before the next model starts."""
        from bulwark_bench.runner import _persist_result
        run_dir = tmp_path / "run"
        run_dir.mkdir()
        payload = {"model": "x", "defense_rate": 0.9}
        _persist_result(run_dir, 0, "x", payload)
        # File exists and decodes back
        files = list(run_dir.glob("model-0-*.json"))
        assert len(files) == 1
        assert json.loads(files[0].read_text())["defense_rate"] == 0.9


# ---------------------------------------------------------------------------
# Bulwark HTTP client (G-BENCH-010)
# ---------------------------------------------------------------------------

class TestBulwarkClient:
    def test_swap_model_sends_only_llm_backend_fields(self, monkeypatch):
        """G-BENCH-010: model swap goes through PUT /api/config with llm_backend block."""
        import bulwark_bench.bulwark_client as bc
        captured = {}

        class _Resp:
            status_code = 200
            def raise_for_status(self): pass
            def json(self): return {}

        def fake_put(url, **kw):
            captured["url"] = url
            captured["body"] = kw.get("json")
            return _Resp()

        monkeypatch.setattr(bc.httpx, "put", fake_put)
        client = bc.BulwarkClient("http://localhost:3001", token=None)
        client.swap_model(analyze_model="modelX", execute_model="modelX")
        assert captured["url"].endswith("/api/config")
        assert captured["body"] == {"llm_backend": {"analyze_model": "modelX", "execute_model": "modelX"}}

    def test_start_redteam_uses_configured_tier(self, monkeypatch):
        """Runner kicks off via POST /api/redteam/start with a tier payload."""
        import bulwark_bench.bulwark_client as bc
        captured = {}

        class _Resp:
            status_code = 200
            def raise_for_status(self): pass
            def json(self): return {"status": "started"}

        def fake_post(url, **kw):
            captured["url"] = url
            captured["body"] = kw.get("json")
            return _Resp()

        monkeypatch.setattr(bc.httpx, "post", fake_post)
        client = bc.BulwarkClient("http://localhost:3001", token=None)
        client.start_redteam("quick")
        assert captured["url"].endswith("/api/redteam/run")
        assert captured["body"]["tier"] == "quick"

    def test_auth_token_is_propagated(self, monkeypatch):
        """Bearer token is attached to protected requests."""
        import bulwark_bench.bulwark_client as bc
        captured = {}

        class _Resp:
            status_code = 200
            def raise_for_status(self): pass
            def json(self): return {}

        def fake_put(url, **kw):
            captured["headers"] = kw.get("headers")
            return _Resp()

        monkeypatch.setattr(bc.httpx, "put", fake_put)
        client = bc.BulwarkClient("http://localhost:3001", token="secret-token")
        client.swap_model(analyze_model="m")
        assert captured["headers"]["Authorization"] == "Bearer secret-token"


# ---------------------------------------------------------------------------
# Runner orchestration (G-BENCH-001, -004, -005)
# ---------------------------------------------------------------------------

class TestRunner:
    def test_runs_models_sequentially_and_collects_results(self, monkeypatch, tmp_path):
        """G-BENCH-001: Each model configured, benchmarked, and recorded in order."""
        from bulwark_bench.runner import BenchRunner

        calls: list[str] = []

        class FakeClient:
            def __init__(self, *a, **kw): pass
            def swap_model(self, analyze_model: str, execute_model: str | None = None):
                calls.append(f"swap:{analyze_model}")
            def start_redteam(self, tier: str):
                calls.append(f"start:{tier}")
                return {"status": "started"}
            def wait_for_redteam(self, timeout_s: int = 3600):
                calls.append("wait")
                return {
                    "status": "complete",
                    "total": 80,
                    "defended": 80,
                    "hijacked": 0,
                    "format_failures": 0,
                    "defense_rate": 1.0,
                    "duration_s": 40.0,
                }
            def sample_tokens(self, prompt: str) -> tuple[int, int]:
                return (800, 300)
            def warmup(self) -> None:
                calls.append("warmup")

        runner = BenchRunner(
            client=FakeClient(),
            run_dir=tmp_path / "run",
            tier="quick",
            warmup=True,
        )
        results = runner.run_all(["model-a", "model-b"])

        assert [r["model"] for r in results] == ["model-a", "model-b"]
        # Ordering proves sequential: for each model we swap -> warmup -> start -> wait
        assert calls == [
            "swap:model-a", "warmup", "start:quick", "wait",
            "swap:model-b", "warmup", "start:quick", "wait",
        ]
        # G-BENCH-004 + G-BENCH-005
        assert results[0]["defense_rate"] == 1.0
        assert results[0]["avg_latency_s"] == pytest.approx(0.5)  # 40s / 80 probes

    def test_per_model_failure_does_not_kill_sweep(self, monkeypatch, tmp_path):
        """G-BENCH-002: A crash on one model records a failure stub and moves on."""
        from bulwark_bench.runner import BenchRunner

        class FakeClient:
            def __init__(self, *a, **kw): pass
            def swap_model(self, analyze_model: str, execute_model=None): pass
            def start_redteam(self, tier):
                if tier == "quick":
                    return {"status": "started"}
            def wait_for_redteam(self, timeout_s=3600):
                raise RuntimeError("connection dropped")
            def sample_tokens(self, prompt): return (100, 50)
            def warmup(self): pass

        runner = BenchRunner(client=FakeClient(), run_dir=tmp_path / "run",
                             tier="quick", warmup=False)
        results = runner.run_all(["a", "b"])
        assert len(results) == 2
        assert all(r.get("error") for r in results)

    def test_tokens_are_single_sample_extrapolation(self, monkeypatch, tmp_path):
        """NG-BENCH-001: tokens_in_sample / tokens_out_sample are from one pre-run call, not per-probe."""
        from bulwark_bench.runner import BenchRunner

        sample_calls = {"n": 0}

        class FakeClient:
            def __init__(self, *a, **kw): pass
            def swap_model(self, analyze_model, execute_model=None): pass
            def start_redteam(self, tier): return {"status": "started"}
            def wait_for_redteam(self, timeout_s=3600):
                return {"status": "complete", "total": 10, "defended": 10,
                        "hijacked": 0, "format_failures": 0, "defense_rate": 1.0,
                        "duration_s": 5.0}
            def sample_tokens(self, prompt):
                sample_calls["n"] += 1
                return (400, 150)
            def warmup(self): pass

        runner = BenchRunner(client=FakeClient(), run_dir=tmp_path / "run",
                             tier="quick", warmup=False)
        results = runner.run_all(["model-a"])
        assert sample_calls["n"] == 1, "sample_tokens must fire exactly once per model"
        assert results[0]["tokens_in_sample"] == 400
        assert results[0]["tokens_out_sample"] == 150

    def test_cost_is_pricing_table_version_locked(self):
        """NG-BENCH-002: reports include the pricing table version used at run time."""
        from bulwark_bench.pricing import PRICING_TABLE_VERSION
        from bulwark_bench.report import render_json
        payload = render_json([], tier="quick", pricing_version=PRICING_TABLE_VERSION)
        assert payload["pricing_table_version"] == PRICING_TABLE_VERSION
        assert PRICING_TABLE_VERSION  # non-empty

    def test_runner_executes_models_sequentially_not_parallel(self, tmp_path):
        """NG-BENCH-003: swap+start+wait interleave strictly per model — no overlap."""
        from bulwark_bench.runner import BenchRunner

        timeline: list[tuple[str, str]] = []

        class FakeClient:
            def __init__(self, *a, **kw): pass
            def swap_model(self, analyze_model, execute_model=None):
                timeline.append(("swap", analyze_model))
            def start_redteam(self, tier):
                timeline.append(("start", tier))
                return {"status": "started"}
            def wait_for_redteam(self, timeout_s=3600):
                timeline.append(("wait", ""))
                return {"status": "complete", "total": 5, "defended": 5,
                        "hijacked": 0, "format_failures": 0, "defense_rate": 1.0,
                        "duration_s": 2.0}
            def sample_tokens(self, prompt): return (1, 1)
            def warmup(self): pass

        BenchRunner(client=FakeClient(), run_dir=tmp_path / "run",
                    tier="quick", warmup=False).run_all(["a", "b", "c"])
        # For each of 3 models, exactly one swap, one start, one wait — in that order.
        # No model's 'start' appears between another model's swap and wait.
        ops_per_model = 3
        for idx, model in enumerate("abc"):
            chunk = timeline[idx * ops_per_model:(idx + 1) * ops_per_model]
            assert chunk == [("swap", model), ("start", "quick"), ("wait", "")]

    def test_bypass_detectors_disables_then_restores(self, tmp_path):
        """G-BENCH-011: listed integrations toggle off before, back on after the sweep."""
        from bulwark_bench.runner import BenchRunner

        state = {"protectai": True, "promptguard": True}
        toggle_log: list[tuple[str, bool]] = []

        class FakeClient:
            def __init__(self): pass
            def get_integrations(self):
                return {k: {"enabled": v} for k, v in state.items()}
            def set_integration_enabled(self, name, enabled):
                state[name] = enabled
                toggle_log.append((name, enabled))
            def swap_model(self, analyze_model, execute_model=None): pass
            def start_redteam(self, tier): return {"status": "started"}
            def wait_for_redteam(self, timeout_s=3600):
                return {"status": "complete", "total": 10, "defended": 10,
                        "hijacked": 0, "format_failures": 0, "defense_rate": 1.0,
                        "duration_s": 5.0}
            def sample_tokens(self, prompt): return (100, 50)
            def warmup(self): pass
            def ensure_redteam_idle(self): pass

        runner = BenchRunner(
            client=FakeClient(), run_dir=tmp_path / "run",
            tier="llm-quick", warmup=False,
            bypass_detectors=("protectai", "promptguard"),
        )
        runner.run_all(["model-a"])
        # Protectai/promptguard turned off before run, back on after
        assert ("protectai", False) in toggle_log
        assert ("promptguard", False) in toggle_log
        assert ("protectai", True) in toggle_log
        assert ("promptguard", True) in toggle_log
        # Final state restored
        assert state == {"protectai": True, "promptguard": True}

    def test_bypass_restored_even_if_sweep_errors(self, tmp_path):
        """G-BENCH-011: restoration runs in a finally so detectors aren't left off."""
        from bulwark_bench.runner import BenchRunner

        state = {"protectai": True}
        toggle_log: list[tuple[str, bool]] = []

        class FakeClient:
            def get_integrations(self):
                return {"protectai": {"enabled": state["protectai"]}}
            def set_integration_enabled(self, name, enabled):
                state[name] = enabled
                toggle_log.append((name, enabled))
            def swap_model(self, analyze_model, execute_model=None):
                raise RuntimeError("boom")
            def start_redteam(self, tier): return {}
            def wait_for_redteam(self, timeout_s=3600): return {}
            def sample_tokens(self, prompt): return (0, 0)
            def warmup(self): pass
            def ensure_redteam_idle(self): pass

        runner = BenchRunner(
            client=FakeClient(), run_dir=tmp_path / "run",
            tier="llm-quick", warmup=False,
            bypass_detectors=("protectai",),
        )
        runner.run_all(["m"])  # per-model error is caught inside runner
        assert ("protectai", False) in toggle_log
        assert ("protectai", True) in toggle_log
        assert state["protectai"] is True

    def test_resume_skips_completed_models(self, monkeypatch, tmp_path):
        """G-BENCH-003: --resume honors existing per-model result files."""
        from bulwark_bench.runner import BenchRunner, _persist_result

        run_dir = tmp_path / "run"
        run_dir.mkdir()
        _persist_result(run_dir, 0, "model-a", {"model": "model-a", "defense_rate": 0.99,
                                                 "avg_latency_s": 0.5, "total_probes": 80,
                                                 "hijacked": 0, "duration_s": 40.0,
                                                 "cost_usd": 0.0})

        started: list[str] = []

        class FakeClient:
            def __init__(self, *a, **kw): pass
            def swap_model(self, analyze_model, execute_model=None): started.append(analyze_model)
            def start_redteam(self, tier): return {"status": "started"}
            def wait_for_redteam(self, timeout_s=3600):
                return {"status": "complete", "total": 80, "defended": 80,
                        "hijacked": 0, "format_failures": 0, "defense_rate": 1.0,
                        "duration_s": 40.0}
            def sample_tokens(self, prompt): return (100, 50)
            def warmup(self): pass

        runner = BenchRunner(client=FakeClient(), run_dir=run_dir, tier="quick",
                             warmup=False, resume=True)
        runner.run_all(["model-a", "model-b"])
        assert started == ["model-b"], "model-a was skipped, model-b ran"
