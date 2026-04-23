"""CLI entry point: `python -m bulwark_bench` (v2.0.0, ADR-034)."""
from __future__ import annotations

import argparse
import datetime as _dt
import json
import os
import sys
from pathlib import Path

from bulwark_bench import __version__
from bulwark_bench.bulwark_client import BulwarkClient
from bulwark_bench.configs import PRESETS, parse_configs
from bulwark_bench.report import render_json, render_markdown
from bulwark_bench.runner import BenchRunner, stderr_progress


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="bulwark_bench",
        description="Compare Bulwark detector configurations against a red-team tier.",
    )
    p.add_argument(
        "--configs", default="deberta-only,deberta+promptguard,deberta+llm-judge",
        help="Comma-separated detector preset slugs. "
             f"Available: {', '.join(sorted(PRESETS))}.",
    )
    p.add_argument(
        "--bulwark", default=os.environ.get("BULWARK_URL", "http://localhost:3001"),
        help="Base URL of the Bulwark dashboard (default: http://localhost:3001).",
    )
    p.add_argument(
        "--token", default=os.environ.get("BULWARK_API_TOKEN"),
        help="Bearer token for protected endpoints (env: BULWARK_API_TOKEN).",
    )
    p.add_argument("--tier", default="standard",
                   help="Red-team tier to run (default: standard).")
    p.add_argument("--output", default=None,
                   help="Directory to write report.json / report.md and per-config files.")
    p.add_argument("--resume", action="store_true",
                   help="Skip configurations whose result already exists in --output.")
    p.add_argument("--redteam-timeout", type=int, default=3600,
                   help="Seconds to wait for one config's red-team run (default: 3600).")
    p.add_argument("--judge-base-url", default=os.environ.get("BULWARK_JUDGE_URL"),
                   help="Base URL of the LLM judge endpoint (e.g. http://192.168.1.78:1234/v1). "
                        "Required when any selected preset enables the LLM judge.")
    p.add_argument("--judge-model", default=os.environ.get("BULWARK_JUDGE_MODEL"),
                   help="Judge model identifier (e.g. prompt-injection-judge-8b).")
    p.add_argument("--judge-mode", default="openai_compatible",
                   choices=("openai_compatible", "anthropic"),
                   help="Judge backend mode (default: openai_compatible).")
    p.add_argument("--judge-api-key", default=os.environ.get("BULWARK_JUDGE_API_KEY"),
                   help="API key for the judge endpoint (optional for local LM Studio).")
    p.add_argument("--title", default="Bulwark detector-config benchmark",
                   help="Title on the markdown report.")
    p.add_argument("--version", action="version", version=f"bulwark_bench {__version__}")
    return p


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)

    try:
        configs = parse_configs(args.configs)
    except ValueError as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        return 2

    if any(c.llm_judge for c in configs) and not args.judge_model:
        print(
            "[ERROR] one or more selected presets includes the LLM judge — "
            "you must pass --judge-model (and --judge-base-url for openai_compatible mode).",
            file=sys.stderr,
        )
        return 2

    if args.output:
        run_dir = Path(args.output)
    else:
        stamp = _dt.datetime.now().strftime("%Y-%m-%d-%H%M%S")
        run_dir = Path("benchmarks") / f"run-{stamp}"
    run_dir.mkdir(parents=True, exist_ok=True)

    print(f"bulwark_bench {__version__} — sweeping {len(configs)} config(s) against {args.bulwark}",
          file=sys.stderr, flush=True)
    print(f"  tier: {args.tier}", file=sys.stderr)
    print(f"  run dir: {run_dir}", file=sys.stderr)
    for c in configs:
        print(f"    · {c.slug:24s} ({c.description()})", file=sys.stderr)

    client = BulwarkClient(args.bulwark, token=args.token)
    try:
        health = client.healthz()
        print(f"  dashboard: v{health.get('version', '?')} (docker={health.get('docker')})",
              file=sys.stderr, flush=True)
    except Exception as exc:
        print(f"  [ERROR] dashboard unreachable: {exc}", file=sys.stderr, flush=True)
        return 1

    runner = BenchRunner(
        client=client,
        run_dir=run_dir,
        tier=args.tier,
        configs=configs,
        judge_base_url=args.judge_base_url,
        judge_model=args.judge_model,
        judge_mode=args.judge_mode,
        judge_api_key=args.judge_api_key,
        resume=args.resume,
        redteam_timeout_s=args.redteam_timeout,
        progress_cb=stderr_progress,
    )
    results = runner.run_all()

    j = render_json(results, tier=args.tier)
    md = render_markdown(results, tier=args.tier, title=args.title)
    (run_dir / "report.json").write_text(json.dumps(j, indent=2))
    (run_dir / "report.md").write_text(md)

    print(f"\nReports written to {run_dir}", file=sys.stderr, flush=True)
    print(md)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
