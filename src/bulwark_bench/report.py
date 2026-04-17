"""JSON + Markdown report rendering.

G-BENCH-007 / G-BENCH-008.
"""
from __future__ import annotations

import datetime as _dt
import json
from typing import Any


def render_json(results: list[dict[str, Any]], tier: str, *, pricing_version: str = "") -> dict[str, Any]:
    """Machine-readable report. Preserves input order for diffing against prior runs."""
    return {
        "schema": "bulwark_bench/v1",
        "generated_at": _dt.datetime.now(_dt.timezone.utc).isoformat(),
        "tier": tier,
        "pricing_table_version": pricing_version,
        "results": list(results),
    }


def _fmt_pct(rate: float, hijacked: int) -> str:
    """G-REDTEAM-SCORE-007 discipline: never round up to 100% when hijacks occurred."""
    if hijacked > 0 and rate >= 1:
        rate = min(rate, 0.9999)
    if rate >= 1:
        return "100.00%"
    if rate >= 0.99:
        return f"{rate * 100:.2f}%"
    return f"{rate * 100:.1f}%"


def _fmt_latency(s: float) -> str:
    if s < 1:
        return f"{s * 1000:.0f}ms"
    return f"{s:.2f}s"


def _fmt_cost(cost: float) -> str:
    if cost == 0:
        return "$0.00"
    if cost < 0.01:
        return f"${cost:.4f}"
    return f"${cost:.2f}"


def render_markdown(results: list[dict[str, Any]], tier: str, *, title: str = "Bulwark model benchmark") -> str:
    """Human-readable table sorted by defense_rate desc, then avg_latency asc (G-BENCH-008)."""
    errored = [r for r in results if r.get("error")]
    ok = [r for r in results if not r.get("error")]

    ordered = sorted(
        ok,
        key=lambda r: (-float(r.get("defense_rate", 0) or 0), float(r.get("avg_latency_s", 1e9) or 1e9)),
    )

    lines: list[str] = []
    lines.append(f"# {title}")
    lines.append("")
    lines.append(f"- tier: **{tier}**")
    if ordered:
        total_probes = ordered[0].get("total_probes", "?")
        lines.append(f"- probes per model: **{total_probes}**")
    lines.append(f"- generated: {_dt.datetime.now(_dt.timezone.utc).isoformat(timespec='seconds')}")
    lines.append("")
    lines.append("## Results")
    lines.append("")
    lines.append("| rank | model | defense | hijacks | avg latency | sample tokens (in/out) | est cost |")
    lines.append("|-----:|:------|--------:|--------:|------------:|:----------------------:|---------:|")
    for i, r in enumerate(ordered, start=1):
        model = r.get("model", "?")
        rate = float(r.get("defense_rate", 0) or 0)
        hijacked = int(r.get("hijacked", 0) or 0)
        latency = float(r.get("avg_latency_s", 0) or 0)
        tin = int(r.get("tokens_in_sample", 0) or 0)
        tout = int(r.get("tokens_out_sample", 0) or 0)
        cost = float(r.get("cost_usd", 0) or 0)
        lines.append(
            f"| {i} | `{model}` | {_fmt_pct(rate, hijacked)} | {hijacked} | {_fmt_latency(latency)} | "
            f"{tin} / {tout} | {_fmt_cost(cost)} |"
        )

    if errored:
        lines.append("")
        lines.append("## Errored runs")
        lines.append("")
        lines.append("| model | error |")
        lines.append("|:------|:------|")
        for r in errored:
            lines.append(f"| `{r.get('model', '?')}` | {r.get('error', 'unknown')} |")

    # Family breakdown — only when the first OK result has one (standard tier).
    if ordered and ordered[0].get("by_family"):
        families = sorted({fam for r in ordered for fam in (r.get("by_family") or {}).keys()})
        if families:
            lines.append("")
            lines.append("## By probe family — defense rate")
            lines.append("")
            header = "| family | " + " | ".join(f"`{r['model']}`" for r in ordered) + " |"
            sep = "|:-------|" + "|".join(["-" * 10] * len(ordered)) + "|"
            lines.append(header)
            lines.append(sep)
            for fam in families:
                cells = []
                for r in ordered:
                    bf = (r.get("by_family") or {}).get(fam) or {}
                    fam_total = int(bf.get("total", 0) or 0)
                    fam_def = int(bf.get("defended", 0) or 0) + int(bf.get("format_failures", 0) or 0)
                    fam_hij = int(bf.get("hijacked", 0) or 0)
                    if fam_total == 0:
                        cells.append("—")
                    else:
                        rate = fam_def / fam_total
                        cells.append(_fmt_pct(rate, fam_hij) + (f" ⚠️{fam_hij}" if fam_hij else ""))
                lines.append(f"| {fam} | " + " | ".join(cells) + " |")

    lines.append("")
    lines.append("_Ranking: defense rate descending, then avg latency ascending (G-BENCH-008). "
                 "Costs from the versioned pricing table (NG-BENCH-002); local inference is $0._")
    lines.append("")
    return "\n".join(lines)
