"""False-positive sweep runner (ADR-036, G-FP-001..004, -007).

Mirrors bulwark_bench's runner shape: snapshot → for each preset apply
config → run corpus → persist → restore. Uses the same DetectorConfig
preset list as bench (G-FP-003).
"""
from __future__ import annotations

import json
import re
import sys
import time
from pathlib import Path
from typing import Any, Optional

from bulwark_bench.configs import DetectorConfig
from bulwark_falsepos.corpus import CorpusEmail


def _safe_id(s: str) -> str:
    return re.sub(r"[^a-zA-Z0-9._-]+", "_", s)


def _result_path(run_dir: Path, index: int, cfg: DetectorConfig) -> Path:
    return run_dir / f"falsepos-{index}-{_safe_id(cfg.slug)}.json"


def _persist(run_dir: Path, index: int, cfg: DetectorConfig, payload: dict[str, Any]) -> Path:
    run_dir.mkdir(parents=True, exist_ok=True)
    path = _result_path(run_dir, index, cfg)
    tmp = path.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(payload, indent=2))
    tmp.replace(path)
    return path


class FalseposRunner:
    """Sweeps detector configurations against a benign corpus."""

    def __init__(
        self, *,
        client: Any,
        run_dir: Path,
        corpus: list[CorpusEmail],
        configs: list[DetectorConfig],
        judge_base_url: Optional[str] = None,
        judge_model: Optional[str] = None,
        judge_mode: str = "openai_compatible",
        judge_api_key: Optional[str] = None,
        resume: bool = False,
        per_request_timeout_s: float = 60.0,
        progress_cb: Optional[Any] = None,
    ):
        self.client = client
        self.run_dir = Path(run_dir)
        self.corpus = corpus
        self.configs = configs
        self.judge_base_url = judge_base_url
        self.judge_model = judge_model
        self.judge_mode = judge_mode
        self.judge_api_key = judge_api_key
        self.resume = resume
        self.per_request_timeout_s = per_request_timeout_s
        self.progress_cb = progress_cb or (lambda _ev: None)

    def _event(self, event: dict[str, Any]) -> None:
        try:
            self.progress_cb(event)
        except Exception:
            pass

    def _snapshot(self) -> dict[str, Any]:
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
            import httpx
            httpx.put(
                f"{self.client.base_url}/api/config",
                json={"judge_backend": patch},
                headers=self.client._headers(),
                timeout=self.client.timeout_s,
            ).raise_for_status()
        except Exception as exc:
            self._event({"type": "restore_error", "what": "judge", "error": str(exc)})

    def _run_one_email(self, email: CorpusEmail) -> dict[str, Any]:
        """Send one email through /v1/clean. Returns result + verdict shape."""
        import httpx
        url = f"{self.client.base_url}/v1/clean"
        body = {"content": email.text, "source": "falsepos"}
        try:
            resp = httpx.post(
                url, json=body,
                headers=self.client._headers(),
                timeout=self.per_request_timeout_s,
            )
        except Exception as exc:
            return {
                "id": email.id, "category": email.category,
                "blocked": False, "error": str(exc)[:200],
            }
        blocked = resp.status_code == 422
        layer = None
        reason = None
        if blocked:
            try:
                payload = resp.json()
                layer = payload.get("blocked_at")
                reason = payload.get("block_reason", "")[:200]
            except Exception:
                reason = resp.text[:200]
        return {
            "id": email.id,
            "category": email.category,
            "blocked": blocked,
            "blocking_layer": layer,
            "blocking_reason": reason,
        }

    def _run_one_config(self, index: int, cfg: DetectorConfig) -> dict[str, Any]:
        self._event({"type": "config_start", "index": index, "config": cfg.slug,
                     "corpus_size": len(self.corpus)})

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

        per_email: list[dict[str, Any]] = []
        t0 = time.time()
        for i, email in enumerate(self.corpus, start=1):
            r = self._run_one_email(email)
            per_email.append(r)
            self._event({
                "type": "email_done", "config": cfg.slug,
                "index": i, "total": len(self.corpus),
                "id": email.id, "blocked": r.get("blocked", False),
            })
        total_seconds = time.time() - t0

        blocked = [r for r in per_email if r.get("blocked")]
        by_category: dict[str, dict[str, int]] = {}
        for r in per_email:
            cat = r.get("category", "unknown")
            slot = by_category.setdefault(cat, {"total": 0, "blocked": 0})
            slot["total"] += 1
            if r.get("blocked"):
                slot["blocked"] += 1

        payload: dict[str, Any] = {
            "config_slug": cfg.slug,
            "config_name": cfg.name,
            "config": {
                "deberta": cfg.deberta,
                "promptguard": cfg.promptguard,
                "llm_judge": cfg.llm_judge,
            },
            "corpus_size": len(self.corpus),
            "blocked": len(blocked),
            "false_positive_rate": (len(blocked) / len(self.corpus)) if self.corpus else 0.0,
            "elapsed_seconds": total_seconds,
            "blocked_by_category": by_category,
            "blocked_emails": [
                {
                    "id": r["id"],
                    "category": r.get("category"),
                    "layer": r.get("blocking_layer"),
                    "reason": r.get("blocking_reason"),
                }
                for r in blocked
            ],
        }
        errored = [r for r in per_email if r.get("error")]
        if errored:
            payload["errored_count"] = len(errored)
            payload["errored_ids"] = [r["id"] for r in errored][:25]

        self._event({"type": "config_complete", "config": cfg.slug, "result": payload})
        return payload

    def run_all(self) -> list[dict[str, Any]]:
        """G-FP-001..002, -004: sequential per-config sweep with restore."""
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
                    payload = self._run_one_config(i, cfg)
                except Exception as exc:
                    payload = {
                        "config_slug": cfg.slug,
                        "config_name": cfg.name,
                        "error": f"{type(exc).__name__}: {exc}",
                    }
                    self._event({"type": "config_error", "config": cfg.slug, "error": str(exc)})
                _persist(self.run_dir, i, cfg, payload)
                results.append(payload)
            return results
        finally:
            self._restore(snapshot)
            self._event({"type": "snapshot_restored", "snapshot": snapshot})


def stderr_progress(event: dict[str, Any]) -> None:
    t = event.get("type")
    if t == "config_start":
        print(f"\n[{event['index']+1}] → {event['config']}  ({event['corpus_size']} emails)",
              file=sys.stderr, flush=True)
    elif t == "email_done":
        if event.get("blocked"):
            print(f"    BLOCKED: {event['id']}", file=sys.stderr, flush=True)
        # Per-email pass lines are too chatty — only print blocks.
    elif t == "config_complete":
        r = event["result"]
        rate = r["false_positive_rate"] * 100
        print(
            f"    false-positive rate {rate:.2f}% "
            f"({r['blocked']}/{r['corpus_size']}) in {r['elapsed_seconds']:.1f}s",
            file=sys.stderr, flush=True,
        )
    elif t == "skipped":
        print(f"[{event['index']+1}] ↪ {event['config']} (resume: already done)",
              file=sys.stderr, flush=True)
    elif t == "config_error":
        print(f"    ERROR: {event['error']}", file=sys.stderr, flush=True)
    elif t == "snapshot_restored":
        print("\n  dashboard config restored.", file=sys.stderr, flush=True)
