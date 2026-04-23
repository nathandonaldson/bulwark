"""JSON + Markdown report (G-FP-006, G-FP-007, NG-FP-001)."""
from __future__ import annotations

import datetime as _dt
from typing import Any


def render_json(results: list[dict[str, Any]], corpus_path: str = "") -> dict[str, Any]:
    return {
        "schema": "bulwark_falsepos/v1",
        "generated_at": _dt.datetime.now(_dt.timezone.utc).isoformat(),
        "corpus": corpus_path,
        "configurations": list(results),
    }


def _fmt_pct(rate: float) -> str:
    if rate <= 0:
        return "0.00%"
    if rate < 0.0001:
        return "<0.01%"
    return f"{rate * 100:.2f}%"


def render_markdown(
    results: list[dict[str, Any]],
    corpus_path: str = "",
    corpus_size: int = 0,
    *, title: str = "Bulwark false-positive harness",
) -> str:
    """Sort by false_positive_rate ASC; ties broken by elapsed_seconds ASC."""
    errored = [r for r in results if r.get("error")]
    ok = [r for r in results if not r.get("error")]
    ordered = sorted(
        ok,
        key=lambda r: (
            float(r.get("false_positive_rate", 1) or 1),
            float(r.get("elapsed_seconds", 1e9) or 1e9),
        ),
    )

    lines: list[str] = []
    lines.append(f"# {title}")
    lines.append("")
    if corpus_path:
        lines.append(f"- corpus: `{corpus_path}`")
    if corpus_size:
        lines.append(f"- emails per configuration: **{corpus_size}**")
    lines.append(f"- generated: {_dt.datetime.now(_dt.timezone.utc).isoformat(timespec='seconds')}")
    lines.append("")
    lines.append("> **NG-FP-001:** the corpus is curated and small. Treat this as a "
                 "regression suite for known false-positive shapes, not a representative "
                 "sample of all benign traffic.")
    lines.append("")
    lines.append("## Results")
    lines.append("")
    lines.append("| rank | configuration | false-positive rate | blocked | elapsed |")
    lines.append("|-----:|:--------------|--------------------:|--------:|--------:|")
    for i, r in enumerate(ordered, start=1):
        name = r.get("config_name") or r.get("config_slug", "?")
        rate = float(r.get("false_positive_rate", 0) or 0)
        blocked = int(r.get("blocked", 0) or 0)
        size = int(r.get("corpus_size", 0) or 0)
        elapsed = float(r.get("elapsed_seconds", 0) or 0)
        lines.append(
            f"| {i} | {name} | {_fmt_pct(rate)} | {blocked} / {size} | {elapsed:.1f}s |"
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

    # Per-category breakdown for the leading config.
    if ordered:
        lead = ordered[0]
        cats = lead.get("blocked_by_category") or {}
        if cats:
            lines.append("")
            lines.append(f"## Per-category breakdown — {lead.get('config_name') or lead.get('config_slug')}")
            lines.append("")
            lines.append("| category | blocked / total | rate |")
            lines.append("|:---------|----------------:|-----:|")
            for cat in sorted(cats):
                slot = cats[cat]
                t = int(slot.get("total", 0) or 0)
                b = int(slot.get("blocked", 0) or 0)
                rate = (b / t) if t else 0
                lines.append(f"| {cat} | {b} / {t} | {_fmt_pct(rate)} |")

    # List blocked emails per config (G-FP-007).
    any_blocked = any((r.get("blocked", 0) or 0) for r in ordered)
    if any_blocked:
        lines.append("")
        lines.append("## Blocked emails")
        lines.append("")
        for r in ordered:
            blocked_list = r.get("blocked_emails") or []
            if not blocked_list:
                continue
            lines.append(f"### {r.get('config_name') or r.get('config_slug')}")
            lines.append("")
            lines.append("| id | category | layer | reason |")
            lines.append("|:---|:---------|:------|:-------|")
            for entry in blocked_list:
                lines.append(
                    f"| `{entry.get('id', '?')}` | {entry.get('category', '?')} | "
                    f"`{entry.get('layer', '?')}` | {entry.get('reason', '')[:120]} |"
                )
            lines.append("")

    lines.append("")
    lines.append("_Ranking: false-positive rate ascending, then elapsed seconds ascending (G-FP-006)._")
    lines.append("")
    return "\n".join(lines)
