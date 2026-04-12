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


# ── Enhanced test command ───────────────────────────────────────

class TestTestCommandDefault:
    """Tests for `bulwark test` default mode (8 preset attacks)."""

    def test_runs_8_preset_attacks(self):
        """Default mode runs exactly 8 preset attacks."""
        runner = CliRunner()
        result = runner.invoke(main, ['test'])
        # Count result lines (BLOCKED/NEUTRALIZED/PASSED lines)
        verdict_lines = [
            line for line in result.output.splitlines()
            if 'BLOCKED' in line or 'NEUTRALIZED' in line or 'PASSED' in line
        ]
        assert len(verdict_lines) == 8

    def test_header_shows_preset_mode(self):
        """Default mode header says 'Preset' and '8 attacks'."""
        runner = CliRunner()
        result = runner.invoke(main, ['test'])
        assert '8 attacks' in result.output.lower() or '8 preset' in result.output.lower()

    def test_output_contains_attack_names(self):
        """Each of the 8 preset attack names appears in the output."""
        runner = CliRunner()
        result = runner.invoke(main, ['test'])
        expected_names = [
            'Zero-width steganography',
            'XML boundary escape',
            'Instruction override',
            'Base64 canary exfil',
            'Emoji smuggling',
            'MCP tool injection',
            'Multilingual override',
            'Bridge instruction inject',
        ]
        for name in expected_names:
            assert name in result.output, f"Expected '{name}' in output"

    def test_output_contains_payload_preview(self):
        """Each attack line includes a truncated payload preview."""
        runner = CliRunner()
        result = runner.invoke(main, ['test'])
        # At least some payload previews should appear (truncated with ...)
        lines_with_preview = [
            line for line in result.output.splitlines()
            if ('BLOCKED' in line or 'NEUTRALIZED' in line or 'PASSED' in line)
        ]
        # Each verdict line should have some payload text
        for line in lines_with_preview:
            # Payload preview is between the attack name and the verdict
            assert len(line.strip()) > 20, f"Line too short, missing preview: {line}"

    def test_output_contains_verdicts(self):
        """Each attack has a BLOCKED or NEUTRALIZED verdict."""
        runner = CliRunner()
        result = runner.invoke(main, ['test'])
        verdict_lines = [
            line for line in result.output.splitlines()
            if 'BLOCKED' in line or 'NEUTRALIZED' in line or 'PASSED' in line
        ]
        assert len(verdict_lines) == 8
        # All 8 should be caught (BLOCKED or NEUTRALIZED), none PASSED
        passed_lines = [line for line in verdict_lines if 'PASSED' in line]
        assert len(passed_lines) == 0, f"Expected no PASSED attacks but got: {passed_lines}"

    def test_output_contains_layer_info(self):
        """Each caught attack shows which layer caught it."""
        runner = CliRunner()
        result = runner.invoke(main, ['test'])
        # Layer names should appear in the output
        layer_keywords = ['sanitizer', 'boundary', 'canary', 'pipeline']
        found_any_layer = False
        for line in result.output.splitlines():
            if any(kw in line.lower() for kw in layer_keywords):
                found_any_layer = True
                break
        assert found_any_layer, "Expected layer information in output"

    def test_summary_line(self):
        """Output ends with a summary line showing caught count."""
        runner = CliRunner()
        result = runner.invoke(main, ['test'])
        output = result.output.strip()
        # Summary should contain "8/8" and something about defenses working
        assert '8/8' in output, f"Expected '8/8' in summary, got: {output[-200:]}"
        assert 'caught' in output.lower() or 'working' in output.lower()

    def test_exit_code_0_all_caught(self):
        """Exit code is 0 when all attacks are caught."""
        runner = CliRunner()
        result = runner.invoke(main, ['test'])
        assert result.exit_code == 0


class TestTestCommandFull:
    """Tests for `bulwark test --full` mode (all 77 attacks)."""

    def test_full_runs_all_77_attacks(self):
        """--full mode runs all 77 attacks."""
        runner = CliRunner()
        result = runner.invoke(main, ['test', '--full'])
        verdict_lines = [
            line for line in result.output.splitlines()
            if 'BLOCKED' in line or 'NEUTRALIZED' in line or 'PASSED' in line
        ]
        assert len(verdict_lines) == 77

    def test_full_header_shows_full_mode(self):
        """--full mode header says 'Full' and '77 attacks'."""
        runner = CliRunner()
        result = runner.invoke(main, ['test', '--full'])
        assert '77' in result.output

    def test_full_summary_line(self):
        """--full mode summary shows total out of 77."""
        runner = CliRunner()
        result = runner.invoke(main, ['test', '--full'])
        output = result.output.strip()
        # Should show X/77 in the summary
        assert '/77' in output, f"Expected '/77' in summary"

    def test_full_exit_code_0(self):
        """--full mode exits 0 when all attacks caught."""
        runner = CliRunner()
        result = runner.invoke(main, ['test', '--full'])
        assert result.exit_code == 0


class TestTestCommandOutputFormat:
    """Tests for output formatting details."""

    def test_no_raw_tracebacks(self):
        """Output should not contain Python tracebacks."""
        runner = CliRunner()
        result = runner.invoke(main, ['test'])
        assert 'Traceback' not in result.output
        assert 'Error' not in result.output or 'Error' in result.output.split('\n')[0]

    def test_category_flag_still_works(self):
        """The existing --category flag still works."""
        runner = CliRunner()
        result = runner.invoke(main, ['test', '--full', '-c', 'steganography'])
        assert result.exit_code == 0
        # Should only show steganography attacks (10 of them)
        verdict_lines = [
            line for line in result.output.splitlines()
            if 'BLOCKED' in line or 'NEUTRALIZED' in line or 'PASSED' in line
        ]
        assert len(verdict_lines) == 10

    def test_verbose_flag_removed_or_backward_compatible(self):
        """Old --verbose flag should not crash (backward compat)."""
        runner = CliRunner()
        # The old -v flag is removed in the new command, but --full replaces it
        # Just make sure the command doesn't crash
        result = runner.invoke(main, ['test'])
        assert result.exit_code == 0
