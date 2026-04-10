"""Bulwark CLI — prompt injection defense from the command line."""
from __future__ import annotations

import json
import sys

try:
    import click
except ImportError:
    raise ImportError(
        "CLI requires click. Install with: pip install bulwark-ai[cli]"
    )

from bulwark.sanitizer import Sanitizer
from bulwark.trust_boundary import TrustBoundary, BoundaryFormat
from bulwark.canary import CanarySystem


def _get_version() -> str:
    """Get version, falling back to __version__ if package metadata unavailable."""
    try:
        from importlib.metadata import version
        return version("bulwark-ai")
    except Exception:
        from bulwark import __version__
        return __version__


@click.group()
@click.version_option(version=_get_version(), prog_name="bulwark-ai")
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


@main.command()
@click.option('--category', '-c', multiple=True, help='Filter by attack category')
@click.option('--verbose', '-v', is_flag=True, help='Show details for each attack')
def test(category, verbose):
    """Run attack suite against your pipeline and show scorecard."""
    from bulwark.validator import PipelineValidator, ValidationReport
    from bulwark.attacks import AttackCategory

    # Build pipeline with all defaults
    validator = PipelineValidator(
        sanitizer=Sanitizer(),
        trust_boundary=TrustBoundary(),
        canary=CanarySystem(),
    )

    categories = None
    if category:
        categories = [AttackCategory(c) for c in category]

    report = validator.validate(categories=categories)
    click.echo(report.summary())

    if verbose:
        click.echo("\nDetailed results:")
        for r in report.results:
            icon = "\u2705" if r.overall_verdict.value == "blocked" else "\u26a0\ufe0f" if r.overall_verdict.value == "reduced" else "\u274c"
            click.echo(f"  {icon} {r.attack.name} [{r.attack.severity}]: {r.overall_verdict.value}")
            if r.details:
                click.echo(f"     {r.details}")

    sys.exit(0 if report.exposed == 0 else 1)
