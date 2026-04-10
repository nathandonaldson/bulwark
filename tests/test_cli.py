"""Tests for the Bulwark CLI."""
from __future__ import annotations

import json

from click.testing import CliRunner
from bulwark.cli import main
from bulwark.canary import CanarySystem


def test_sanitize_strips_html():
    """bulwark sanitize reads stdin and outputs cleaned text."""
    runner = CliRunner()
    result = runner.invoke(main, ['sanitize'], input="Hello<script>alert('xss')</script> world")
    assert result.exit_code == 0
    assert "Hello world" in result.output
    assert "<script>" not in result.output


def test_sanitize_max_length():
    """bulwark sanitize --max-length truncates output."""
    runner = CliRunner()
    result = runner.invoke(main, ['sanitize', '--max-length', '10'], input="A" * 100)
    assert result.exit_code == 0
    # Output includes trailing newline from click.echo
    assert len(result.output.strip()) <= 10


def test_sanitize_no_html_preserves_tags():
    """bulwark sanitize --no-html preserves HTML tags."""
    runner = CliRunner()
    result = runner.invoke(main, ['sanitize', '--no-html'], input="<b>bold</b>")
    assert result.exit_code == 0
    assert "<b>bold</b>" in result.output


def test_canary_check_clean_text(tmp_path):
    """bulwark canary-check exits 0 for clean text."""
    tokens_file = tmp_path / "canaries.json"
    canary = CanarySystem()
    canary.generate("user_data")
    canary.save(str(tokens_file))

    runner = CliRunner()
    result = runner.invoke(main, ['canary-check', '--tokens', str(tokens_file)],
                           input="this is clean output with no tokens")
    assert result.exit_code == 0


def test_canary_check_leaked_text(tmp_path):
    """bulwark canary-check exits 1 for leaked text, prints alert."""
    tokens_file = tmp_path / "canaries.json"
    canary = CanarySystem()
    token = canary.generate("user_data")
    canary.save(str(tokens_file))

    runner = CliRunner()
    result = runner.invoke(main, ['canary-check', '--tokens', str(tokens_file)],
                           input=f"output contains {token} oops")
    assert result.exit_code == 1
    assert "CANARY ALERT" in result.output


def test_canary_generate_prints_tokens():
    """bulwark canary-generate prints tokens for each source."""
    runner = CliRunner()
    result = runner.invoke(main, ['canary-generate', 'source1', 'source2'])
    assert result.exit_code == 0
    assert "source1:" in result.output
    assert "source2:" in result.output
    assert "BLWK-CANARY" in result.output


def test_canary_generate_saves_file(tmp_path):
    """bulwark canary-generate -o saves tokens to JSON file."""
    output_file = tmp_path / "tokens.json"
    runner = CliRunner()
    result = runner.invoke(main, ['canary-generate', 'source1', '-o', str(output_file)])
    assert result.exit_code == 0
    assert "Saved to" in result.output
    assert output_file.exists()

    data = json.loads(output_file.read_text())
    assert "source1" in data


def test_wrap_xml_default():
    """bulwark wrap --source email wraps in XML tags."""
    runner = CliRunner()
    result = runner.invoke(main, ['wrap', '--source', 'email'], input="untrusted email body")
    assert result.exit_code == 0
    assert "<untrusted_email" in result.output
    assert 'source="email"' in result.output
    assert "untrusted email body" in result.output
    assert "</untrusted_email>" in result.output


def test_wrap_markdown_format():
    """bulwark wrap --format markdown wraps in markdown fences."""
    runner = CliRunner()
    result = runner.invoke(main, ['wrap', '--source', 'email', '--format', 'markdown'],
                           input="untrusted content")
    assert result.exit_code == 0
    assert "```untrusted_email" in result.output
    assert "untrusted content" in result.output


def test_wrap_with_label():
    """bulwark wrap --source email --label body uses label in tag name."""
    runner = CliRunner()
    result = runner.invoke(main, ['wrap', '--source', 'email', '--label', 'body'],
                           input="email body text")
    assert result.exit_code == 0
    assert "<untrusted_body" in result.output
    assert 'source="email"' in result.output


def test_version():
    """bulwark --version prints version."""
    runner = CliRunner()
    result = runner.invoke(main, ['--version'])
    assert result.exit_code == 0
    assert "0.1.0" in result.output
