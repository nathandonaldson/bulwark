"""Bulwark CLI — prompt injection defense from the command line."""
from __future__ import annotations

import json
import sys

try:
    import click
except ImportError:
    raise ImportError(
        "CLI requires click. Install with: pip install bulwark-shield[cli]"
    )

from bulwark.sanitizer import Sanitizer
from bulwark.trust_boundary import TrustBoundary, BoundaryFormat
from bulwark.canary import CanarySystem


def _get_version() -> str:
    """Get version, falling back to __version__ if package metadata unavailable."""
    try:
        from importlib.metadata import version
        return version("bulwark-shield")
    except Exception:
        from bulwark import __version__
        return __version__


@click.group()
@click.version_option(version=_get_version(), prog_name="bulwark-shield")
def main():
    """Bulwark: Architectural defense against prompt injection."""
    pass


@main.command()
@click.option('--max-length', type=int, default=3000, help='Max output length')
@click.option('--no-html', is_flag=True, help='Disable HTML stripping')
@click.option('--no-css', is_flag=True, help='Disable CSS hidden text removal')
@click.option('--no-zero-width', is_flag=True, help='Disable zero-width char removal')
def sanitize(max_length, no_html, no_css, no_zero_width):
    """Sanitize untrusted text from stdin."""
    text = sys.stdin.read()
    s = Sanitizer(
        max_length=max_length,
        strip_html=not no_html,
        strip_css_hidden=not no_css,
        strip_zero_width=not no_zero_width,
    )
    click.echo(s.clean(text))


@main.command('canary-check')
@click.option('--tokens', required=True, type=click.Path(exists=True), help='Path to canary tokens JSON file')
def canary_check(tokens):
    """Check stdin for canary token leaks. Exit 1 if found."""
    text = sys.stdin.read()
    canary = CanarySystem.from_file(tokens)
    result = canary.check(text)
    if result.leaked:
        click.echo(f"CANARY ALERT: {len(result.found_tokens)} token(s) detected!", err=True)
        for source in result.sources:
            click.echo(f"  - Leaked from: {source}", err=True)
        sys.exit(1)


@main.command('canary-generate')
@click.argument('sources', nargs=-1, required=True)
@click.option('--output', '-o', type=click.Path(), help='Save tokens to JSON file')
@click.option('--prefix', default='BLWK-CANARY', help='Token prefix')
def canary_generate(sources, output, prefix):
    """Generate canary tokens for the given source names."""
    canary = CanarySystem(prefix=prefix)
    for source in sources:
        token = canary.generate(source)
        click.echo(f"{source}: {token}")
    if output:
        canary.save(output)
        click.echo(f"\nSaved to {output}")


@main.command()
@click.option('--source', default='external', help='Source identifier')
@click.option('--label', default=None, help='Label for the tag')
@click.option('--format', 'fmt', type=click.Choice(['xml', 'markdown', 'delimiter']), default='xml')
def wrap(source, label, fmt):
    """Wrap stdin content in trust boundary tags."""
    text = sys.stdin.read()
    format_map = {
        'xml': BoundaryFormat.XML,
        'markdown': BoundaryFormat.MARKDOWN_FENCE,
        'delimiter': BoundaryFormat.DELIMITER,
    }
    tb = TrustBoundary(format=format_map[fmt])
    click.echo(tb.wrap(text, source=source, label=label))


# ── Preset attacks for `bulwark test` (matches dashboard) ──────

PRESET_ATTACKS = [
    {
        "label": "Zero-width steganography",
        "attack_name": "zero_width_instructions",
    },
    {
        "label": "XML boundary escape",
        "attack_name": "xml_close_reopen",
    },
    {
        "label": "Instruction override",
        "attack_name": "direct_override",
    },
    {
        "label": "Base64 canary exfil",
        "attack_name": "base64_canary_bypass",
    },
    {
        "label": "Emoji smuggling",
        "attack_name": "emoji_smuggling",
    },
    {
        "label": "MCP tool injection",
        "attack_name": "mcp_tool_injection",
    },
    {
        "label": "Multilingual override",
        "attack_name": "multilingual_override_chinese",
    },
    {
        "label": "Bridge instruction inject",
        "attack_name": "bridge_trust_escape",
    },
]

PAYLOAD_PREVIEW_MAX = 50


def _catching_layer(result) -> str:
    """Determine which defense layer caught an attack."""
    from bulwark.validator import DefenseVerdict
    if result.sanitizer_verdict in (DefenseVerdict.BLOCKED, DefenseVerdict.REDUCED):
        return "sanitizer"
    if result.boundary_verdict in (DefenseVerdict.BLOCKED, DefenseVerdict.REDUCED):
        return "boundary"
    if result.canary_verdict in (DefenseVerdict.BLOCKED, DefenseVerdict.REDUCED):
        return "canary"
    return "pipeline"


def _truncate_payload(payload: str, max_len: int = PAYLOAD_PREVIEW_MAX) -> str:
    """Truncate payload for display, collapsing whitespace."""
    # Collapse newlines and multiple spaces into single space
    preview = " ".join(payload.split())
    if len(preview) > max_len:
        return preview[:max_len] + "..."
    return preview


def _verdict_label(result) -> tuple[str, str]:
    """Return (label, color) for a verdict."""
    from bulwark.validator import DefenseVerdict
    v = result.overall_verdict
    if v == DefenseVerdict.BLOCKED:
        return "BLOCKED", "green"
    elif v == DefenseVerdict.REDUCED:
        return "NEUTRALIZED", "yellow"
    else:
        return "PASSED", "red"


def _format_attack_line(label: str, payload: str, verdict_text: str, verdict_color: str, layer: str) -> str:
    """Format a single attack result line with color."""
    name_styled = click.style(f"  {label:<30s}", bold=True)
    preview = _truncate_payload(payload)
    preview_styled = click.style(f"{preview:<54s}", dim=True)
    verdict_styled = click.style(f"{verdict_text:<12s}", fg=verdict_color, bold=True)
    layer_styled = click.style(f"[{layer}]", dim=True)
    return f"{name_styled} {preview_styled} {verdict_styled} {layer_styled}"


@main.command()
@click.option('--full', is_flag=True, help='Run all 77 attacks (default: 8 presets)')
@click.option('--category', '-c', multiple=True, help='Filter by attack category (implies --full)')
@click.option('--garak', 'run_garak', is_flag=True, help='Run Garak red-team probes (requires garak installed)')
@click.option('--garak-import', 'garak_import_path', type=click.Path(), default=None,
              help='Import results from an externally-run Garak report (.jsonl)')
def test(full, category, run_garak, garak_import_path):
    """Run attack suite against your pipeline and show scorecard."""

    # Validate mutual exclusivity of --garak and --garak-import
    if run_garak and garak_import_path:
        click.echo(click.style(
            "Cannot use --garak and --garak-import together (mutually exclusive).",
            fg="red",
        ))
        sys.exit(2)

    # ── Garak import mode ──────────────────────────────────────
    if garak_import_path:
        _run_garak_import(garak_import_path)
        return

    # ── Garak live scan mode ───────────────────────────────────
    if run_garak:
        _run_garak_live()
        return

    # ── Built-in attack suite (default) ────────────────────────
    from bulwark.validator import PipelineValidator, DefenseVerdict
    from bulwark.attacks import AttackSuite, AttackCategory

    # Build pipeline with all defaults
    validator = PipelineValidator(
        sanitizer=Sanitizer(),
        trust_boundary=TrustBoundary(),
        canary=CanarySystem(),
    )

    suite = AttackSuite()

    # Determine which attacks to run
    if category:
        # --category implies full mode, filtered
        full = True
        categories = [AttackCategory(c) for c in category]
        attacks = [a for a in suite.attacks if a.category in categories]
    elif full:
        attacks = suite.attacks
    else:
        # Default: 8 preset attacks
        attack_by_name = {a.name: a for a in suite.attacks}
        attacks = []
        for preset in PRESET_ATTACKS:
            attack = attack_by_name.get(preset["attack_name"])
            if attack:
                attacks.append(attack)

    # Build preset label lookup
    preset_label_map = {p["attack_name"]: p["label"] for p in PRESET_ATTACKS}

    # Header
    total = len(attacks)
    if not full and not category:
        header = f"Bulwark Defense Test — 8 preset attacks"
    elif category:
        cats = ", ".join(category)
        header = f"Bulwark Defense Test — {total} attacks [{cats}]"
    else:
        header = f"Bulwark Defense Test — Full suite, {total} attacks"
    click.echo(click.style(header, bold=True))
    click.echo(click.style("=" * len(header), dim=True))
    click.echo()

    # Run each attack and display
    caught = 0
    warnings = []
    for attack in attacks:
        result = validator._test_attack(attack)
        verdict_text, verdict_color = _verdict_label(result)
        layer = _catching_layer(result)

        # Use preset label if available, otherwise attack name
        label = preset_label_map.get(attack.name, attack.name)

        is_caught = result.overall_verdict in (DefenseVerdict.BLOCKED, DefenseVerdict.REDUCED)
        if is_caught:
            caught += 1
        else:
            warnings.append((label, attack.target))

        line = _format_attack_line(label, attack.payload, verdict_text, verdict_color, layer)
        click.echo(line)

    # Warnings for attacks that passed through
    if warnings:
        click.echo()
        for label, expected_layer in warnings:
            click.echo(click.style(
                f"  WARNING: {label} — expected to be caught by {expected_layer}",
                fg="red",
            ))

    # Summary
    click.echo()
    if caught == total:
        summary = f"{caught}/{total} attacks caught. Your defenses are working."
        click.echo(click.style(summary, fg="green", bold=True))
    else:
        missed = total - caught
        summary = f"{caught}/{total} caught, {missed} warning{'s' if missed != 1 else ''}."
        click.echo(click.style(summary, fg="yellow", bold=True))

    sys.exit(0 if caught == total else 1)


def _run_garak_import(path: str):
    """Handle `bulwark test --garak-import <path>`."""
    from pathlib import Path
    if not Path(path).exists():
        click.echo(click.style(f"File not found: {path}", fg="red"))
        sys.exit(2)

    from bulwark.integrations.garak import import_garak_results, GarakScanSummary

    click.echo(click.style("Garak Results Import", bold=True))
    click.echo(click.style("=" * 40, dim=True))
    click.echo()

    summary = import_garak_results(path)
    _display_garak_summary(summary)
    sys.exit(0 if summary.failed == 0 else 1)


def _run_garak_live():
    """Handle `bulwark test --garak`."""
    from bulwark.integrations.garak import GarakAdapter

    click.echo(click.style("Garak Red-Team Scan", bold=True))
    click.echo(click.style("=" * 40, dim=True))
    click.echo()
    click.echo("Running Garak probes... (this may take a few minutes)")
    click.echo()

    try:
        adapter = GarakAdapter()
        summary = adapter.run()
    except RuntimeError as e:
        click.echo(click.style(f"Garak scan failed: {e}", fg="red"))
        sys.exit(2)

    _display_garak_summary(summary)
    sys.exit(0 if summary.failed == 0 else 1)


def _display_garak_summary(summary):
    """Display a GarakScanSummary in a formatted table."""
    # Per-probe results
    if summary.results:
        for result in summary.results:
            probe_name = result.probe
            if result.passed:
                verdict = click.style("PASS", fg="green", bold=True)
            else:
                verdict = click.style("FAIL", fg="red", bold=True)
            prompt_preview = _truncate_payload(result.prompt)
            click.echo(
                f"  {probe_name:<40s} {prompt_preview:<40s} {verdict}"
            )
        click.echo()

    # Summary line
    if summary.total == 0:
        click.echo(click.style("No Garak probe results found.", fg="yellow"))
        return

    click.echo(f"Probes tested: {', '.join(summary.probes_tested)}")
    click.echo()

    if summary.failed == 0:
        msg = f"{summary.passed}/{summary.total} probes passed. No vulnerabilities found."
        click.echo(click.style(msg, fg="green", bold=True))
    else:
        msg = f"{summary.passed}/{summary.total} passed, {summary.failed} failed (vulnerabilities found)."
        click.echo(click.style(msg, fg="red", bold=True))
