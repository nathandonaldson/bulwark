"""CLI entry point: `python -m bulwark_bench`."""
from __future__ import annotations

import argparse
import datetime as _dt
import json
import os
import sys
from pathlib import Path

from bulwark_bench import __version__
from bulwark_bench.bulwark_client import BulwarkClient
from bulwark_bench.pricing import PRICING_TABLE_VERSION
from bulwark_bench.report import render_json, render_markdown
from bulwark_bench.runner import BenchRunner, stderr_progress


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="bulwark_bench",
        description="Benchmark LLM models against a running Bulwark dashboard.",
    )
    p.add_argument("--models", required=True,
                   help="Comma-separated model ids to benchmark (up to 5 recommended).")
    p.add_argument("--bulwark", default=os.environ.get("BULWARK_URL", "http://localhost:3001"),
                   help="Base URL of the Bulwark dashboard (default: http://localhost:3001).")
    p.add_argument("--token", default=os.environ.get("BULWARK_API_TOKEN"),
                   help="Bearer token for protected endpoints (env: BULWARK_API_TOKEN).")
    p.add_argument("--tier", default="quick",
                   help="Red-team tier to run (default: quick).")
    p.add_argument("--output", default=None,
                   help="Directory to write report.json / report.md and per-model files.")
    p.add_argument("--no-warmup", action="store_true",
                   help="Skip warmup probe before each model (warmup is on by default).")
    p.add_argument("--resume", action="store_true",
                   help="Skip models whose per-model result already exists in --output.")
    p.add_argument("--redteam-timeout", type=int, default=3600,
                   help="Seconds to wait for a single model's red-team run (default: 3600).")
    p.add_argument("--title", default="Bulwark model benchmark",
                   help="Title on the markdown report.")
    p.add_argument("--version", action="version", version=f"bulwark_bench {__version__}")
    return p


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)

    models = [m.strip() for m in args.models.split(",") if m.strip()]
    if not models:
        print("No models specified.", file=sys.stderr)
        return 2

    if args.output:
        run_dir = Path(args.output)
    else:
        stamp = _dt.datetime.now().strftime("%Y-%m-%d-%H%M%S")
        run_dir = Path("benchmarks") / f"run-{stamp}"

    run_dir.mkdir(parents=True, exist_ok=True)

    print(f"bulwark_bench {__version__} — sweeping {len(models)} model(s) against {args.bulwark}",
          file=sys.stderr, flush=True)
    print(f"  tier: {args.tier}", file=sys.stderr)
    print(f"  run dir: {run_dir}", file=sys.stderr)
    print(f"  warmup: {'yes' if not args.no_warmup else 'no'}   resume: {args.resume}",
          file=sys.stderr, flush=True)
    if args.tier == "quick":
        print(
            "  note: 'quick' tier (10 probes) mostly gets blocked by sanitizer / "
            "trust_boundary / detectors before reaching the LLM.\n"
            "        Use --tier standard for LLM-meaningful model comparisons "
            "(slower, thousands of probes).",
            file=sys.stderr, flush=True,
        )

    client = BulwarkClient(args.bulwark, token=args.token)
    try:
        health = client.healthz()
        print(f"  dashboard: v{health.get('version', '?')} (docker={health.get('docker')})",
              file=sys.stderr, flush=True)
    except Exception as e:
        print(f"  [ERROR] dashboard unreachable: {e}", file=sys.stderr, flush=True)
        return 1

    runner = BenchRunner(
        client=client,
        run_dir=run_dir,
        tier=args.tier,
        warmup=not args.no_warmup,
        resume=args.resume,
        redteam_timeout_s=args.redteam_timeout,
        progress_cb=stderr_progress,
    )
    results = runner.run_all(models)

    # Write final reports
    j = render_json(results, tier=args.tier, pricing_version=PRICING_TABLE_VERSION)
    md = render_markdown(results, tier=args.tier, title=args.title)
    (run_dir / "report.json").write_text(json.dumps(j, indent=2))
    (run_dir / "report.md").write_text(md)

    print(f"\nReports written to {run_dir}", file=sys.stderr, flush=True)
    print(md)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
