"""Sweep orchestrator for detector configurations (ADR-034).

For each preset: apply config → start red team → wait → persist.
G-BENCH-001..005, -007..008, -010, -012..013.
"""
from __future__ import annotations

import json
import re
import sys
import time
from pathlib import Path
from typing import Any, Optional

from bulwark_bench.configs import DetectorConfig


def _safe_id(s: str) -> str:
    return re.sub(r"[^a-zA-Z0-9._-]+", "_", s)


def _result_filename(index: int, cfg: DetectorConfig) -> str:
    return f"config-{index}-{_safe_id(cfg.slug)}.json"


def _result_path(run_dir: Path, index: int, cfg: DetectorConfig) -> Path:
    return run_dir / _result_filename(index, cfg)


def _persist(run_dir: Path, index: int, cfg: DetectorConfig, payload: dict[str, Any]) -> Path:
    """G-BENCH-002: write per-config result as soon as the run finishes."""
    run_dir.mkdir(parents=True, exist_ok=True)
    path = _result_path(run_dir, index, cfg)
    tmp = path.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(payload, indent=2))
    tmp.replace(path)
    return path


class BenchRunner:
    """Sweeps detector configurations against a fixed red-team tier."""

    def __init__(
        self, *,
        client: Any,
        run_dir: Path,
        tier: str,
        configs: list[DetectorConfig],
        judge_base_url: Optional[str] = None,
        judge_model: Optional[str] = None,
        judge_mode: str = "openai_compatible",
        judge_api_key: Optional[str] = None,
        resume: bool = False,
        redteam_timeout_s: int = 3600,
        progress_cb: Optional[Any] = None,
    ):
        self.client = client
        self.run_dir = Path(run_dir)
        self.tier = tier
        self.configs = configs
        self.judge_base_url = judge_base_url
        self.judge_model = judge_model
        self.judge_mode = judge_mode
        self.judge_api_key = judge_api_key
        self.resume = resume
        self.redteam_timeout_s = redteam_timeout_s
        self.progress_cb = progress_cb or (lambda _ev: None)

    def _event(self, event: dict[str, Any]) -> None:
        try:
            self.progress_cb(event)
        except Exception:
            pass

    def _snapshot(self) -> dict[str, Any]:
        """Capture current dashboard state so we can restore it later (G-BENCH-013)."""
        snap: dict[str, Any] = {"promptguard": False, "judge": {}}
        try:
            ints = self.client.get_integrations()
            snap["promptguard"] = bool((ints.get("promptguard") or {}).get("enabled", False))
        except Exception:
            pass
        try:
            cfg = self.client.get_config()
            snap["judge"] = dict(cfg.get("judge_backend") or {})
        except Exception:
            pass
        return snap

    def _restore(self, snap: dict[str, Any]) -> None:
        """G-BENCH-013: put the dashboard back in the state we found it."""
        try:
            if snap.get("promptguard"):
                self.client.activate_integration("promptguard")
            else:
                self.client.set_integration_enabled("promptguard", False)
        except Exception as exc:
            self._event({"type": "restore_error", "what": "promptguard", "error": str(exc)})
        try:
            j = snap.get("judge") or {}
            patch = {"enabled": bool(j.get("enabled", False))}
            for k in ("mode", "base_url", "model"):
                if k in j:
                    patch[k] = j[k]
            # Don't try to restore api_key — it was masked when we read it.
            self.client._put_config({"judge_backend": patch}) if hasattr(self.client, "_put_config") else \
                __import__("httpx").put(
                    f"{self.client.base_url}/api/config",
                    json={"judge_backend": patch},
                    headers=self.client._headers(),
                    timeout=self.client.timeout_s,
                ).raise_for_status()
        except Exception as exc:
            self._event({"type": "restore_error", "what": "judge", "error": str(exc)})

    def _run_one(self, index: int, cfg: DetectorConfig) -> dict[str, Any]:
        self._event({"type": "config_start", "index": index, "config": cfg.slug})

        if hasattr(self.client, "ensure_redteam_idle"):
            self.client.ensure_redteam_idle()

        self.client.apply_detector_config(
            promptguard=cfg.promptguard,
            llm_judge=cfg.llm_judge,
            judge_base_url=self.judge_base_url,
            judge_model=self.judge_model,
            judge_mode=self.judge_mode,
            judge_api_key=self.judge_api_key,
        )
        time.sleep(0.3)  # let dashboard settle

        self._event({"type": "redteam_start", "config": cfg.slug, "tier": self.tier})
        self.client.start_redteam(self.tier)
        t_rt_start = time.time()

        def _on_progress(completed: int, total: int) -> None:
            if total <= 0:
                return
            if completed == total or completed == 0 or (completed * 10 // total) != (
                (completed - 1) * 10 // total if completed else -1
            ):
                self._event({
                    "type": "progress", "config": cfg.slug,
                    "completed": completed, "total": total,
                })

        try:
            result = self.client.wait_for_redteam(
                timeout_s=self.redteam_timeout_s, on_progress=_on_progress,
            )
        except TypeError:
            result = self.client.wait_for_redteam(timeout_s=self.redteam_timeout_s)
        t_rt_end = time.time()

        total = int(result.get("total", 0) or 0)
        defended = int(result.get("defended", 0) or 0)
        hijacked = int(result.get("hijacked", 0) or 0)
        format_failures = int(result.get("format_failures", 0) or 0)
        defense_rate = float(result.get("defense_rate", 0) or 0)
        duration_s = float(result.get("duration_s", t_rt_end - t_rt_start) or 0)
        avg_latency = duration_s / total if total > 0 else 0.0
        by_family = result.get("by_family") or {}
        by_layer = result.get("by_layer") or {}

        payload = {
            "config_slug": cfg.slug,
            "config_name": cfg.name,
            "config": {
                "deberta": cfg.deberta,
                "promptguard": cfg.promptguard,
                "llm_judge": cfg.llm_judge,
            },
            "tier": self.tier,
            "total_probes": total,
            "defended": defended,
            "hijacked": hijacked,
            "format_failures": format_failures,
            "defense_rate": defense_rate,
            "duration_s": duration_s,
            "avg_latency_s": avg_latency,
            "by_family": by_family,
            "by_layer": by_layer,
        }
        self._event({"type": "config_complete", "config": cfg.slug, "result": payload})
        return payload

    def run_all(self) -> list[dict[str, Any]]:
        """G-BENCH-001 / -002: sequential sweep, persist each before next.

        G-BENCH-013: capture + restore the dashboard's original detector
        configuration via try/finally so an interrupted sweep doesn't
        leave the dashboard in a different state than it started.
        """
        self.run_dir.mkdir(parents=True, exist_ok=True)
        snapshot = self._snapshot()
        self._event({"type": "snapshot", "snapshot": snapshot})

        try:
            results: list[dict[str, Any]] = []
            for i, cfg in enumerate(self.configs):
                if self.resume and _result_path(self.run_dir, i, cfg).exists():
                    self._event({"type": "skipped", "index": i, "config": cfg.slug})
                    try:
                        results.append(json.loads(_result_path(self.run_dir, i, cfg).read_text()))
                    except Exception:
                        results.append({"config_slug": cfg.slug, "error": "result file unreadable"})
                    continue
                try:
                    payload = self._run_one(i, cfg)
                except Exception as exc:
                    payload = {
                        "config_slug": cfg.slug,
                        "config_name": cfg.name,
                        "tier": self.tier,
                        "error": f"{type(exc).__name__}: {exc}",
                    }
                    self._event({"type": "config_error", "config": cfg.slug, "error": str(exc)})
                _persist(self.run_dir, i, cfg, payload)
                results.append(payload)
            return results
        finally:
            self._restore(snapshot)
            self._event({"type": "snapshot_restored", "snapshot": snapshot})


# ---------------------------------------------------------------------------
# Convenience progress printer
# ---------------------------------------------------------------------------

def stderr_progress(event: dict[str, Any]) -> None:
    t = event.get("type")
    if t == "config_start":
        print(f"\n[{event['index']+1}] → {event['config']}", file=sys.stderr, flush=True)
    elif t == "redteam_start":
        print(f"    running {event['tier']} tier…", file=sys.stderr, flush=True)
    elif t == "progress":
        completed, total = event["completed"], event["total"]
        pct = completed * 100 / total if total else 0
        print(f"    probe {completed}/{total} ({pct:.0f}%)", file=sys.stderr, flush=True)
    elif t == "config_complete":
        r = event["result"]
        rate = r["defense_rate"] * 100
        print(
            f"    defense {rate:.2f}% / hijacks {r['hijacked']} / "
            f"avg {r['avg_latency_s']:.2f}s",
            file=sys.stderr, flush=True,
        )
    elif t == "skipped":
        print(f"[{event['index']+1}] ↪ {event['config']} (resume: already done)", file=sys.stderr, flush=True)
    elif t == "config_error":
        print(f"    ERROR: {event['error']}", file=sys.stderr, flush=True)
    elif t == "snapshot_restored":
        print(f"\n  dashboard config restored.", file=sys.stderr, flush=True)
