"""Garak red-teaming integration for Bulwark.

Wraps NVIDIA's Garak LLM vulnerability scanner to run prompt injection
probes against a Bulwark-defended pipeline. Two modes:

1. Live scan: `GarakAdapter().run()` invokes `garak` CLI as a subprocess
   with the `promptinject` and `knownbadsignatures` probe families.
2. Import: `import_garak_results("path/to/report.jsonl")` parses a
   previously-run Garak report and converts results to BulwarkEvents.

Results flow into the dashboard event stream via the existing emitter system.

Garak is an optional dependency: `pip install bulwark-ai[testing]`

Usage:
    from bulwark.integrations.garak import GarakAdapter, import_garak_results
    from bulwark.events import CollectorEmitter

    # Live scan (requires garak installed)
    adapter = GarakAdapter(emitter=my_emitter)
    summary = adapter.run()

    # Import pre-run results
    summary = import_garak_results("garak.report.jsonl", emitter=my_emitter)
"""
from __future__ import annotations

import json
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

from bulwark.events import BulwarkEvent, Layer, Verdict, EventEmitter, NullEmitter


# ── Constants ─────────────────────────────────────────────────────

GARAK_PROBE_FAMILIES: list[str] = [
    "promptinject",
    "knownbadsignatures",
]

# Default Garak report directory (garak writes to ~/.local/share/garak/)
_DEFAULT_REPORT_DIR = str(Path.home() / ".local" / "share" / "garak")


# ── Data classes ──────────────────────────────────────────────────

@dataclass
class GarakProbeResult:
    """Result of a single Garak probe attempt."""
    probe: str          # e.g. "promptinject.HijackHateHumans"
    prompt: str         # The probe payload sent
    output: str         # The model/pipeline response
    detector: str       # Which detector evaluated it
    passed: bool        # True = model defended against the probe
    score: float        # 0.0 (failed defense) to 1.0 (defended)

    def to_bulwark_event(self) -> BulwarkEvent:
        """Convert to a BulwarkEvent for the dashboard event stream."""
        return BulwarkEvent(
            timestamp=time.time(),
            layer=Layer.SANITIZER,  # Garak probes test the full pipeline
            verdict=Verdict.PASSED if self.passed else Verdict.BLOCKED,
            source_id=f"garak:{self.probe}",
            detail=f"Garak probe {self.probe}: {'defended' if self.passed else 'vulnerable'}",
            metadata={
                "source": "garak",
                "probe": self.probe,
                "detector": self.detector,
                "score": self.score,
                "prompt_preview": self.prompt[:100],
                "output_preview": self.output[:100] if self.output else "",
            },
        )


@dataclass
class GarakScanSummary:
    """Summary of a complete Garak scan."""
    total: int
    passed: int
    failed: int
    pass_rate: float
    probes_tested: list[str]
    results: list[GarakProbeResult]

    @classmethod
    def from_results(cls, results: list[GarakProbeResult]) -> "GarakScanSummary":
        if not results:
            return cls(
                total=0, passed=0, failed=0, pass_rate=0.0,
                probes_tested=[], results=[],
            )
        passed = sum(1 for r in results if r.passed)
        failed = len(results) - passed
        probes_tested = sorted(set(r.probe for r in results))
        return cls(
            total=len(results),
            passed=passed,
            failed=failed,
            pass_rate=passed / len(results),
            probes_tested=probes_tested,
            results=results,
        )


# ── Report parsing ────────────────────────────────────────────────

def parse_garak_report(path: str) -> list[GarakProbeResult]:
    """Parse a Garak JSONL report file into GarakProbeResults.

    Only processes entries with entry_type="attempt" and status=2
    (fully evaluated). Skips init, eval, and unevaluated entries.

    Args:
        path: Path to a .jsonl report file.

    Returns:
        List of GarakProbeResult for each evaluated attempt.
    """
    results: list[GarakProbeResult] = []
    report_path = Path(path)

    if not report_path.exists():
        return results

    for line in report_path.read_text().splitlines():
        line = line.strip()
        if not line:
            continue

        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            continue

        if entry.get("entry_type") != "attempt":
            continue
        if entry.get("status") != 2:
            continue

        outputs = entry.get("outputs", [])
        output_text = outputs[0] if outputs else ""

        results.append(GarakProbeResult(
            probe=entry.get("probe", "unknown"),
            prompt=entry.get("prompt", ""),
            output=output_text,
            detector=entry.get("detector", "unknown"),
            passed=entry.get("passed", False),
            score=entry.get("score", 0.0),
        ))

    return results


def import_garak_results(
    path: str,
    emitter: Optional[EventEmitter] = None,
) -> GarakScanSummary:
    """Import results from a Garak report file and emit as BulwarkEvents.

    Args:
        path: Path to a Garak .jsonl report file.
        emitter: Optional EventEmitter for dashboard integration.

    Returns:
        GarakScanSummary with totals and per-probe results.
    """
    results = parse_garak_report(path)

    if emitter is not None:
        for result in results:
            emitter.emit(result.to_bulwark_event())

    return GarakScanSummary.from_results(results)


# ── Adapter (wraps Garak CLI) ────────────────────────────────────

class GarakAdapter:
    """Wraps the Garak CLI to run probes against the Bulwark pipeline.

    By default, runs the `promptinject` and `knownbadsignatures` probe
    families using Garak's `function` generator (which wraps a Python
    callable). For systems not accessible as a Python function, use
    `generator_module` and `generator_name` to specify a different
    Garak generator (e.g. "rest.RestGenerator").

    Args:
        probe_families: List of Garak probe module names to run.
        generator_module: Garak generator module (default: "function.Single").
        generator_name: Generator name/path (default: built-in pipeline wrapper).
        report_dir: Directory where Garak writes report files.
        emitter: Optional EventEmitter for dashboard integration.
    """

    def __init__(
        self,
        probe_families: Optional[list[str]] = None,
        generator_module: Optional[str] = None,
        generator_name: Optional[str] = None,
        report_dir: Optional[str] = None,
        emitter: Optional[EventEmitter] = None,
    ):
        self.probe_families = probe_families or list(GARAK_PROBE_FAMILIES)
        self.generator_module = generator_module or "test.Blank"
        self.generator_name = generator_name
        self.report_dir = report_dir or _DEFAULT_REPORT_DIR
        self.emitter = emitter or NullEmitter()

    def _build_command(self, report_prefix: str) -> list[str]:
        """Build the garak CLI command."""
        import sys
        cmd = [
            sys.executable, "-m", "garak",
            "--model_type", self.generator_module,
            "--probes", ",".join(self.probe_families),
            "--report_prefix", report_prefix,
        ]
        if self.generator_name:
            cmd.extend(["--model_name", self.generator_name])
        return cmd

    def run(self) -> GarakScanSummary:
        """Run Garak probes and return a summary.

        Invokes the Garak CLI as a subprocess, then parses the output
        report. Emits BulwarkEvents for each probe result.

        Returns:
            GarakScanSummary with per-probe results.

        Raises:
            RuntimeError: If Garak CLI fails or no report is generated.
        """
        import tempfile
        report_prefix = str(Path(tempfile.gettempdir()) / f"bulwark-garak-{int(time.time())}")
        report_path = f"{report_prefix}.report.jsonl"

        cmd = self._build_command(report_prefix)

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=600,  # 10 minute timeout for large probe sets
        )

        if result.returncode != 0:
            raise RuntimeError(
                f"Garak CLI failed (exit {result.returncode}): "
                f"{result.stderr or result.stdout}"
            )

        if not Path(report_path).exists():
            raise RuntimeError(
                f"Garak report not found at {report_path}. "
                f"Garak output: {result.stdout[-500:] if result.stdout else 'none'}"
            )

        return import_garak_results(report_path, emitter=self.emitter)
