"""HTTP client for the Bulwark dashboard API.

G-BENCH-010: model swaps go only through the dashboard API; the bench never
owns the dashboard lifecycle.
"""
from __future__ import annotations

import time
from typing import Any, Optional

import httpx


class BulwarkClient:
    def __init__(self, base_url: str, *, token: Optional[str] = None,
                 timeout_s: float = 300.0, poll_s: float = 3.0):
        self.base_url = base_url.rstrip("/")
        self.token = token
        self.timeout_s = timeout_s
        self.poll_s = poll_s

    # ------------------------------------------------------------------
    # Low-level helpers
    # ------------------------------------------------------------------
    def _headers(self) -> dict[str, str]:
        h: dict[str, str] = {"Content-Type": "application/json"}
        if self.token:
            h["Authorization"] = f"Bearer {self.token}"
        return h

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    def healthz(self) -> dict[str, Any]:
        r = httpx.get(f"{self.base_url}/healthz", timeout=self.timeout_s)
        r.raise_for_status()
        return r.json()

    def get_config(self) -> dict[str, Any]:
        r = httpx.get(f"{self.base_url}/api/config", headers=self._headers(), timeout=self.timeout_s)
        r.raise_for_status()
        return r.json()

    def apply_detector_config(
        self, *,
        promptguard: bool,
        llm_judge: bool,
        judge_base_url: Optional[str] = None,
        judge_model: Optional[str] = None,
        judge_mode: str = "openai_compatible",
        judge_api_key: Optional[str] = None,
    ) -> None:
        """G-BENCH-010 / ADR-034: apply a detector configuration to the dashboard.

        DeBERTa is assumed mandatory and ensured loaded. PromptGuard is
        toggled via the integrations endpoints (so it actually loads/unloads
        from _detection_checks). LLM judge is toggled via PUT /api/config.
        """
        # 1) DeBERTa: ensure loaded.
        try:
            self.activate_integration("protectai")
        except Exception:
            # Already loaded is fine; some dashboards return 200 either way.
            pass

        # 2) PromptGuard.
        if promptguard:
            try:
                self.activate_integration("promptguard")
            except Exception as exc:
                raise RuntimeError(
                    f"failed to enable PromptGuard: {exc}. "
                    f"Make sure HuggingFace approval is granted and the model is downloaded."
                ) from exc
        else:
            self.set_integration_enabled("promptguard", False)

        # 3) LLM judge.
        judge_patch: dict[str, Any] = {"enabled": bool(llm_judge)}
        if llm_judge:
            if not (judge_base_url or judge_mode == "anthropic"):
                raise ValueError("LLM judge requires --judge-base-url for openai_compatible mode")
            if not judge_model:
                raise ValueError("LLM judge requires --judge-model")
            judge_patch.update({
                "mode": judge_mode,
                "base_url": judge_base_url or "",
                "model": judge_model,
            })
            if judge_api_key:
                judge_patch["api_key"] = judge_api_key
        r = httpx.put(
            f"{self.base_url}/api/config",
            json={"judge_backend": judge_patch},
            headers=self._headers(),
            timeout=self.timeout_s,
        )
        r.raise_for_status()

    def stop_redteam(self) -> dict[str, Any]:
        r = httpx.post(
            f"{self.base_url}/api/redteam/stop",
            headers=self._headers(),
            timeout=self.timeout_s,
        )
        r.raise_for_status()
        return r.json()

    def ensure_redteam_idle(self, poll_s: float = 1.0, timeout_s: int = 120) -> None:
        """Stop any active red team and wait for it to settle.

        Bench runs must start from a clean slate: if a previous run (ours or someone
        else's) is still in progress, we stop it and wait for the status to leave
        the running/stopping states before proceeding.
        """
        status = self.get_redteam_status()
        state = status.get("status")
        if state in {"running", "stopping"}:
            try:
                self.stop_redteam()
            except Exception:
                pass
        deadline = time.time() + timeout_s
        while True:
            status = self.get_redteam_status()
            if status.get("status") not in {"running", "stopping"}:
                return
            if time.time() >= deadline:
                raise TimeoutError("red team did not return to idle within timeout")
            time.sleep(poll_s)

    def start_redteam(self, tier: str) -> dict[str, Any]:
        r = httpx.post(
            f"{self.base_url}/api/redteam/run",
            json={"tier": tier},
            headers=self._headers(),
            timeout=self.timeout_s,
        )
        r.raise_for_status()
        body = r.json()
        # Dashboard returns 200 with this shape when another run is in flight.
        if isinstance(body, dict) and body.get("message") == "Red team is already running":
            raise RuntimeError("a red team run is already active; call ensure_redteam_idle() first")
        return body

    def get_redteam_status(self) -> dict[str, Any]:
        r = httpx.get(
            f"{self.base_url}/api/redteam/status",
            headers=self._headers(),
            timeout=self.timeout_s,
        )
        r.raise_for_status()
        return r.json()

    def wait_for_redteam(self, timeout_s: int = 3600,
                         on_progress: Optional[Any] = None) -> dict[str, Any]:
        """Poll until the red-team run reports complete. Raises on timeout or failure.

        on_progress(completed, total) is called when the numbers change — useful
        for emitting a progress line during a long standard-tier sweep.
        """
        deadline = time.time() + timeout_s
        last_completed = -1
        while True:
            status = self.get_redteam_status()
            state = status.get("status")
            if on_progress is not None:
                completed = int(status.get("completed", 0) or 0)
                total = int(status.get("total", 0) or 0)
                if completed != last_completed and total > 0:
                    try:
                        on_progress(completed, total)
                    except Exception:
                        pass
                    last_completed = completed
            if state == "complete":
                return status
            if state in {"error", "failed"}:
                raise RuntimeError(f"red team run reported {state}: {status.get('error', 'unknown')}")
            if time.time() >= deadline:
                raise TimeoutError(f"red team did not complete within {timeout_s}s (last status={state})")
            time.sleep(self.poll_s)

    def sample_tokens(self, prompt: str) -> tuple[int, int]:
        """Send a probe-shaped prompt via /v1/clean and return (prompt_tokens, completion_tokens).

        /v1/clean does not expose tokens directly, so we make a direct chat-completion
        call to the same endpoint Bulwark is pointed at. If that fails (e.g. API key
        shape mismatch), we fall back to (0, 0). Token estimate is best-effort by design
        (NG-BENCH-001).
        """
        cfg = self.get_config()
        backend = cfg.get("llm_backend", {})
        mode = backend.get("mode", "none")
        base_url = backend.get("base_url")
        model = backend.get("analyze_model")
        api_key = backend.get("api_key") or ""
        if "..." in api_key or not api_key:
            # api_key is masked in /api/config responses — we don't have the real key here.
            # For local inference that's fine (any key works); for Anthropic we can't sample.
            api_key = "local"
        if mode == "openai_compatible" and base_url and model:
            try:
                r = httpx.post(
                    f"{base_url.rstrip('/')}/chat/completions",
                    json={
                        "model": model,
                        "messages": [
                            {"role": "system", "content": "You are analyzing untrusted content. Output concise JSON."},
                            {"role": "user", "content": prompt},
                        ],
                        "max_tokens": 128,
                    },
                    headers={"Content-Type": "application/json", "Authorization": f"Bearer {api_key}"},
                    timeout=120.0,
                )
                r.raise_for_status()
                usage = (r.json().get("usage") or {})
                return (int(usage.get("prompt_tokens", 0)), int(usage.get("completion_tokens", 0)))
            except Exception:
                return (0, 0)
        return (0, 0)

    def get_integrations(self) -> dict[str, Any]:
        """Snapshot current integration state, combining config toggles + live-loaded detectors.

        config.integrations may be empty while detectors are actually loaded in memory
        (dashboard restart edge case). We consider a detector 'enabled' for bypass
        purposes if it's in active-checks OR config.integrations[name].enabled=True.
        """
        try:
            active = httpx.get(
                f"{self.base_url}/api/integrations/active-checks",
                headers=self._headers(),
                timeout=self.timeout_s,
            ).json()
            active_names = set(active.get("active") or [])
        except Exception:
            active_names = set()

        cfg_integrations = self.get_config().get("integrations") or {}
        merged: dict[str, Any] = {}
        for name in active_names | set(cfg_integrations.keys()):
            merged[name] = {
                "enabled": name in active_names or bool(
                    (cfg_integrations.get(name) or {}).get("enabled", False)
                )
            }
        return merged

    def set_integration_enabled(self, name: str, enabled: bool) -> None:
        """Toggle a single integration's enabled flag.

        Uses PUT /api/integrations/{name} (not /api/config) so the dashboard
        removes the detector from _detection_checks immediately on disable —
        otherwise the pipeline keeps running it.
        """
        r = httpx.put(
            f"{self.base_url}/api/integrations/{name}",
            json={"enabled": enabled},
            headers=self._headers(),
            timeout=self.timeout_s,
        )
        r.raise_for_status()

    def activate_integration(self, name: str) -> None:
        """Re-load a detector into _detection_checks.

        PUT with enabled=true only updates the flag (NG-INTEGRATIONS-001); the
        model must be re-activated via this endpoint to actually run again.
        """
        r = httpx.post(
            f"{self.base_url}/api/integrations/{name}/activate",
            headers=self._headers(),
            timeout=max(self.timeout_s, 60.0),
        )
        r.raise_for_status()

    def warmup(self) -> None:
        """Force the model to load into memory with a throwaway request.

        First-probe latency on a local GPU includes model-load time (10-30s for
        a 26B model). Warming avoids polluting steady-state latency numbers.
        """
        try:
            httpx.post(
                f"{self.base_url}/v1/clean",
                json={"content": "warmup", "source": "bench"},
                headers=self._headers(),
                timeout=300.0,
            )
        except Exception:
            pass
