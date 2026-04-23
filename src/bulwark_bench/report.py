"""JSON + Markdown report rendering (v2.0.0, ADR-034).

G-BENCH-007 / G-BENCH-008. Cost column dropped (NG-BENCH-002 v2):
detector configs don't have a meaningful per-config dollar cost.
"""
from __future__ import annotations

import datetime as _dt
from typing import Any


def render_json(results: list[dict[str, Any]], tier: str) -> dict[str, Any]:
    """Machine-readable report. Preserves input order for diffing across runs."""
    return {
        "schema": "bulwark_bench/v2",
        "generated_at": _dt.datetime.now(_dt.timezone.utc).isoformat(),
        "tier": tier,
        "configurations": list(results),
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


def render_markdown(
    results: list[dict[str, Any]], tier: str,
    *, title: str = "Bulwark detector-config benchmark",
) -> str:
    """Human-readable table sorted by defense_rate desc, then avg_latency asc (G-BENCH-008)."""
    errored = [r for r in results if r.get("error")]
    ok = [r for r in results if not r.get("error")]

    ordered = sorted(
        ok,
        key=lambda r: (-float(r.get("defense_rate", 0) or 0),
                        float(r.get("avg_latency_s", 1e9) or 1e9)),
    )

    lines: list[str] = []
    lines.append(f"# {title}")
    lines.append("")
    lines.append(f"- tier: **{tier}**")
    if ordered:
        total_probes = ordered[0].get("total_probes", "?")
        lines.append(f"- probes per configuration: **{total_probes}**")
    lines.append(f"- generated: {_dt.datetime.now(_dt.timezone.utc).isoformat(timespec='seconds')}")
    lines.append("")
    lines.append("## Results")
    lines.append("")
    lines.append("| rank | configuration | defense | hijacks | avg latency |")
    lines.append("|-----:|:--------------|--------:|--------:|------------:|")
    for i, r in enumerate(ordered, start=1):
        name = r.get("config_name") or r.get("config_slug", "?")
        rate = float(r.get("defense_rate", 0) or 0)
        hijacked = int(r.get("hijacked", 0) or 0)
        latency = float(r.get("avg_latency_s", 0) or 0)
        lines.append(
            f"| {i} | {name} | {_fmt_pct(rate, hijacked)} | {hijacked} | "
            f"{_fmt_latency(latency)} |"
        )

    if errored:
        lines.append("")
        lines.append("## Errored runs")
        lines.append("")
        lines.append("| configuration | error |")
        lines.append("|:--------------|:------|")
        for r in errored:
            lines.append(
                f"| {r.get('config_name') or r.get('config_slug', '?')} | "
                f"{r.get('error', 'unknown')} |"
            )

    if ordered and ordered[0].get("by_family"):
        families = sorted({fam for r in ordered for fam in (r.get("by_family") or {}).keys()})
        if families:
            lines.append("")
            lines.append("## By probe family — defense rate")
            lines.append("")
            header = "| family | " + " | ".join(
                f"{r.get('config_name') or r.get('config_slug', '?')}" for r in ordered
            ) + " |"
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
    lines.append("_Ranking: defense rate descending, then avg latency ascending (G-BENCH-008)._")
    lines.append("")
    return "\n".join(lines)
