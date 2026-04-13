#!/bin/bash
# Run the Bulwark dashboard from the repo, using the runtime venv for dependencies.
# This script is called by the launchd plist.

REPO_DIR="/Users/musicmac/Documents/wintermute-claude/bulwark-ai"
VENV_PYTHON="/Users/musicmac/Library/Application Support/bulwark-dashboard/.venv/bin/python3"

export PYTHONPATH="$REPO_DIR:$REPO_DIR/src"
cd "$REPO_DIR"

exec "$VENV_PYTHON" -m dashboard --port 3000
