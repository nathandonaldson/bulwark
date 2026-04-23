"""CLI entry point: `python -m bulwark_falsepos` (ADR-036)."""
from __future__ import annotations

import argparse
import datetime as _dt
import json
import os
import sys
from pathlib import Path

from bulwark_bench.bulwark_client import BulwarkClient
from bulwark_bench.configs import PRESETS, parse_configs
from bulwark_falsepos import __version__
from bulwark_falsepos.corpus import categories, load_corpus
from bulwark_falsepos.report import render_json, render_markdown
from bulwark_falsepos.runner import FalseposRunner, stderr_progress


_DEFAULT_CORPUS = Path(__file__).resolve().parents[2] / "spec" / "falsepos_corpus.jsonl"


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="bulwark_falsepos",
        description="Measure Bulwark false-positive rate per detector configuration.",
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
    p.add_argument(
        "--corpus", default=str(_DEFAULT_CORPUS),
        help="Path to a JSONL benign corpus (default: spec/falsepos_corpus.jsonl).",
    )
    p.add_argument("--output", default=None,
                   help="Directory for report.json / report.md and per-config files.")
    p.add_argument("--resume", action="store_true",
                   help="Skip configurations whose result already exists in --output.")
    p.add_argument("--per-request-timeout", type=float, default=60.0,
                   help="Per-email /v1/clean timeout in seconds (default: 60).")
    p.add_argument("--max-fp-rate", type=float, default=None,
                   help="G-FP-008: exit 1 when any config exceeds this false-positive rate (e.g. 0.05).")
    p.add_argument("--judge-base-url", default=os.environ.get("BULWARK_JUDGE_URL"),
                   help="LLM judge endpoint (required when any selected preset enables the judge).")
    p.add_argument("--judge-model", default=os.environ.get("BULWARK_JUDGE_MODEL"),
                   help="Judge model identifier.")
    p.add_argument("--judge-mode", default="openai_compatible",
                   choices=("openai_compatible", "anthropic"),
                   help="Judge backend mode.")
    p.add_argument("--judge-api-key", default=os.environ.get("BULWARK_JUDGE_API_KEY"),
                   help="API key for the judge endpoint.")
    p.add_argument("--title", default="Bulwark false-positive harness",
                   help="Title on the markdown report.")
    p.add_argument("--version", action="version", version=f"bulwark_falsepos {__version__}")
    return p


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)

    try:
        configs = parse_configs(args.configs)
    except ValueError as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        return 2

    if any(c.llm_judge for c in configs) and not args.judge_model:
        print("[ERROR] one or more selected presets includes the LLM judge — "
              "you must pass --judge-model (and --judge-base-url for openai_compatible mode).",
              file=sys.stderr)
        return 2

    try:
        corpus = load_corpus(args.corpus)
    except (FileNotFoundError, ValueError) as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        return 2

    if args.output:
        run_dir = Path(args.output)
    else:
        stamp = _dt.datetime.now().strftime("%Y-%m-%d-%H%M%S")
        run_dir = Path("benchmarks") / f"falsepos-{stamp}"
    run_dir.mkdir(parents=True, exist_ok=True)

    print(f"bulwark_falsepos {__version__} — {len(corpus)} emails × {len(configs)} configs",
          file=sys.stderr, flush=True)
    print(f"  corpus: {args.corpus}", file=sys.stderr)
    cats = categories(corpus)
    for cat in sorted(cats):
        print(f"    · {cat:18s} {cats[cat]}", file=sys.stderr)
    print(f"  run dir: {run_dir}", file=sys.stderr)
    for c in configs:
        print(f"    · {c.slug:24s} ({c.description()})", file=sys.stderr)

    client = BulwarkClient(args.bulwark, token=args.token)
    try:
        health = client.healthz()
        print(f"  dashboard: v{health.get('version', '?')}", file=sys.stderr, flush=True)
    except Exception as exc:
        print(f"  [ERROR] dashboard unreachable: {exc}", file=sys.stderr, flush=True)
        return 1

    runner = FalseposRunner(
        client=client,
        run_dir=run_dir,
        corpus=corpus,
        configs=configs,
        judge_base_url=args.judge_base_url,
        judge_model=args.judge_model,
        judge_mode=args.judge_mode,
        judge_api_key=args.judge_api_key,
        resume=args.resume,
        per_request_timeout_s=args.per_request_timeout,
        progress_cb=stderr_progress,
    )
    results = runner.run_all()

    j = render_json(results, corpus_path=args.corpus)
    md = render_markdown(results, corpus_path=args.corpus, corpus_size=len(corpus),
                         title=args.title)
    (run_dir / "report.json").write_text(json.dumps(j, indent=2))
    (run_dir / "report.md").write_text(md)

    print(f"\nReports written to {run_dir}", file=sys.stderr, flush=True)
    print(md)

    # G-FP-008: --max-fp-rate gate
    if args.max_fp_rate is not None:
        offenders = [
            r for r in results
            if not r.get("error") and float(r.get("false_positive_rate", 0)) > args.max_fp_rate
        ]
        if offenders:
            for r in offenders:
                print(f"[FAIL] {r['config_slug']} false-positive rate "
                      f"{r['false_positive_rate']:.4f} > --max-fp-rate {args.max_fp_rate}",
                      file=sys.stderr)
            return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
