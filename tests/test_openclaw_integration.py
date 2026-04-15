"""Spec-driven tests for OpenClaw integration — spec/contracts/openclaw_integration.yaml.

Verifies the integration files exist, are well-formed, and reference
the correct Bulwark API endpoints and OpenClaw hooks.
"""
import json
import pytest
from pathlib import Path

INTEGRATION_DIR = Path(__file__).parent.parent / "integrations" / "openclaw"
PLUGIN_DIR = INTEGRATION_DIR / "plugin"


class TestDockerSidecar:
    """G-OPENCLAW-001, G-OPENCLAW-006: Docker sidecar configuration."""

    def test_compose_overlay_exists(self):
        """G-OPENCLAW-001: Docker sidecar compose overlay exists."""
        path = INTEGRATION_DIR / "docker-compose.bulwark.yml"
        assert path.exists()

    def test_compose_overlay_port_8100(self):
        """G-OPENCLAW-001: Compose overlay configures Bulwark on port 8100."""
        import yaml
        path = INTEGRATION_DIR / "docker-compose.bulwark.yml"
        data = yaml.safe_load(path.read_text())
        bulwark = data["services"]["bulwark"]
        env = bulwark.get("environment", [])
        assert any("8100" in str(e) for e in env)

    def test_compose_overlay_shares_network(self):
        """G-OPENCLAW-006: Sidecar shares network with OpenClaw gateway."""
        import yaml
        path = INTEGRATION_DIR / "docker-compose.bulwark.yml"
        data = yaml.safe_load(path.read_text())
        bulwark = data["services"]["bulwark"]
        assert "network_mode" in bulwark


class TestPlugin:
    """G-OPENCLAW-002, G-OPENCLAW-003, G-OPENCLAW-004, G-OPENCLAW-007, G-OPENCLAW-008."""

    def test_package_json_exists(self):
        """G-OPENCLAW-007: Plugin is an npm package."""
        path = PLUGIN_DIR / "package.json"
        assert path.exists()

    def test_package_json_has_openclaw_hooks(self):
        """G-OPENCLAW-007: package.json declares openclaw.hooks."""
        pkg = json.loads((PLUGIN_DIR / "package.json").read_text())
        assert "openclaw" in pkg, "package.json must have openclaw config"
        assert "hooks" in pkg["openclaw"], "openclaw config must declare hooks"

    def test_plugin_entry_exists(self):
        """Plugin main entry file exists."""
        pkg = json.loads((PLUGIN_DIR / "package.json").read_text())
        main = pkg.get("main", "index.js")
        assert (PLUGIN_DIR / main).exists()

    def test_plugin_registers_message_received(self):
        """G-OPENCLAW-002: Plugin hooks message:received for inbound sanitization."""
        pkg = json.loads((PLUGIN_DIR / "package.json").read_text())
        main = pkg.get("main", "index.js")
        source = (PLUGIN_DIR / main).read_text()
        assert "message:received" in source

    def test_plugin_registers_tool_result_persist(self):
        """G-OPENCLAW-003: Plugin hooks tool_result_persist for tool result sanitization."""
        pkg = json.loads((PLUGIN_DIR / "package.json").read_text())
        main = pkg.get("main", "index.js")
        source = (PLUGIN_DIR / main).read_text()
        assert "tool_result_persist" in source

    def test_plugin_registers_before_message_write(self):
        """G-OPENCLAW-004: Plugin hooks before_message_write for outbound guard."""
        pkg = json.loads((PLUGIN_DIR / "package.json").read_text())
        main = pkg.get("main", "index.js")
        source = (PLUGIN_DIR / main).read_text()
        assert "before_message_write" in source

    def test_plugin_calls_v1_clean(self):
        """G-OPENCLAW-002/003: Plugin calls /v1/clean for sanitization."""
        pkg = json.loads((PLUGIN_DIR / "package.json").read_text())
        main = pkg.get("main", "index.js")
        source = (PLUGIN_DIR / main).read_text()
        assert "/v1/clean" in source

    def test_plugin_calls_v1_guard(self):
        """G-OPENCLAW-004: Plugin calls /v1/guard for outbound check."""
        pkg = json.loads((PLUGIN_DIR / "package.json").read_text())
        main = pkg.get("main", "index.js")
        source = (PLUGIN_DIR / main).read_text()
        assert "/v1/guard" in source

    def test_plugin_handles_unreachable_sidecar(self):
        """G-OPENCLAW-008: Plugin logs warning and passes through when sidecar is down."""
        pkg = json.loads((PLUGIN_DIR / "package.json").read_text())
        main = pkg.get("main", "index.js")
        source = (PLUGIN_DIR / main).read_text()
        # Should have error handling that doesn't throw
        assert "catch" in source or "catch" in source.lower()

    def test_no_new_endpoints_needed(self):
        """G-OPENCLAW-005: Integration uses only existing endpoints."""
        import yaml
        spec_path = Path(__file__).parent.parent / "spec" / "openapi.yaml"
        spec = yaml.safe_load(spec_path.read_text())
        paths = spec.get("paths", {})
        assert "/v1/clean" in paths
        assert "/v1/guard" in paths


class TestSkill:
    """G-OPENCLAW-009: Skill documents Bulwark for agent awareness."""

    def test_skill_exists(self):
        """G-OPENCLAW-009: Skill SKILL.md exists."""
        path = INTEGRATION_DIR / "skills" / "bulwark-sanitize" / "SKILL.md"
        assert path.exists()

    def test_skill_references_endpoints(self):
        """Skill references both /v1/clean and /v1/guard."""
        content = (INTEGRATION_DIR / "skills" / "bulwark-sanitize" / "SKILL.md").read_text()
        assert "/v1/clean" in content
        assert "/v1/guard" in content


class TestInstaller:
    """G-OPENCLAW-004 (updated): Install script handles plugin + skill + compose."""

    def test_install_script_exists(self):
        path = INTEGRATION_DIR / "install.sh"
        assert path.exists()

    def test_install_script_copies_skill(self):
        content = (INTEGRATION_DIR / "install.sh").read_text()
        assert "bulwark-sanitize" in content

    def test_install_script_copies_plugin(self):
        content = (INTEGRATION_DIR / "install.sh").read_text()
        assert "plugin" in content.lower()

    def test_readme_exists(self):
        path = INTEGRATION_DIR / "README.md"
        assert path.exists()
