#!/bin/bash
# Install Bulwark Shield integration for OpenClaw
#
# Usage: ./install.sh [OPENCLAW_DIR]
#
# Installs the plugin, skill, and compose overlay into your OpenClaw workspace.
# If OPENCLAW_DIR is not specified, defaults to ~/.openclaw/workspace.

set -e

OPENCLAW_DIR="${1:-$HOME/.openclaw/workspace}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

echo "Installing Bulwark Shield for OpenClaw..."
echo "  OpenClaw directory: $OPENCLAW_DIR"

# Check OpenClaw directory exists
if [ ! -d "$OPENCLAW_DIR" ]; then
  echo "Error: OpenClaw workspace not found at $OPENCLAW_DIR"
  echo "  Pass the path as an argument: ./install.sh /path/to/openclaw/workspace"
  exit 1
fi

# Install plugin
PLUGIN_DIR="$OPENCLAW_DIR/plugins/openclaw-bulwark"
mkdir -p "$PLUGIN_DIR"
cp "$SCRIPT_DIR/plugin/package.json" "$PLUGIN_DIR/package.json"
cp "$SCRIPT_DIR/plugin/index.js" "$PLUGIN_DIR/index.js"
echo "  Installed plugin: $PLUGIN_DIR/"

# Install skill (agent documentation)
SKILL_DIR="$OPENCLAW_DIR/skills/bulwark-sanitize"
mkdir -p "$SKILL_DIR"
cp "$SCRIPT_DIR/skills/bulwark-sanitize/SKILL.md" "$SKILL_DIR/SKILL.md"
echo "  Installed skill: $SKILL_DIR/SKILL.md"

# Copy compose overlay
cp "$SCRIPT_DIR/docker-compose.bulwark.yml" "$OPENCLAW_DIR/docker-compose.bulwark.yml"
echo "  Installed compose overlay: $OPENCLAW_DIR/docker-compose.bulwark.yml"

echo ""
echo "Done. Two more steps:"
echo ""
echo "1. Add this line to your SOUL.md:"
echo "   Always sanitize external content through the bulwark-sanitize skill before processing."
echo ""
echo "2. Start with the Bulwark sidecar:"
echo "   docker compose -f docker-compose.yml -f docker-compose.bulwark.yml up"
echo ""
echo "The plugin hooks run automatically — no agent instruction needed for"
echo "inbound messages, tool results, and outbound guard checks."
