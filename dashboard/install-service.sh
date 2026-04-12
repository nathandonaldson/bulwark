#!/usr/bin/env bash
# Install Bulwark Dashboard as a persistent macOS service.
# Usage: bash dashboard/install-service.sh [install|uninstall|status|restart|sync]
#
# The dashboard runs from ~/Library/Application Support/bulwark-dashboard/
# because ~/Documents is TCC-protected and launchd agents can't access it.
# Use 'sync' to update the runtime copy after editing dashboard source.

set -euo pipefail

PLIST_NAME="com.bulwark.dashboard"
PLIST_SRC="$(cd "$(dirname "$0")" && pwd)/$PLIST_NAME.plist"
PLIST_DST="$HOME/Library/LaunchAgents/$PLIST_NAME.plist"
RUNTIME_DIR="$HOME/Library/Application Support/bulwark-dashboard"
SOURCE_DIR="$(cd "$(dirname "$0")/.." && pwd)"

sync_runtime() {
    mkdir -p "$RUNTIME_DIR"
    rsync -a --delete "$SOURCE_DIR/dashboard/" "$RUNTIME_DIR/dashboard/"
    cp "$SOURCE_DIR/bulwark-config.yaml" "$RUNTIME_DIR/" 2>/dev/null || true
    cp "$SOURCE_DIR/bulwark-dashboard.db" "$RUNTIME_DIR/" 2>/dev/null || true
    rsync -a "$SOURCE_DIR/src/" "$RUNTIME_DIR/src/" 2>/dev/null || true

    # Create venv if missing
    if [ ! -d "$RUNTIME_DIR/.venv" ]; then
        echo "Creating virtualenv..."
        /usr/bin/python3 -m venv "$RUNTIME_DIR/.venv"
        "$RUNTIME_DIR/.venv/bin/pip" install fastapi uvicorn pyyaml 2>&1 | tail -1
    fi
}

case "${1:-install}" in
  install)
    echo "Syncing dashboard to runtime directory..."
    sync_runtime

    # Kill any existing dashboard on port 3000
    lsof -ti:3000 | xargs kill -9 2>/dev/null || true
    sleep 1

    # Copy plist to LaunchAgents
    cp "$PLIST_SRC" "$PLIST_DST"

    # Load the service
    launchctl load "$PLIST_DST"

    echo "Bulwark Dashboard installed and started."
    echo "  URL: http://localhost:3000"
    echo "  Runtime: $RUNTIME_DIR"
    echo "  Log: $RUNTIME_DIR/bulwark-dashboard.log"
    echo "  Uninstall: bash $0 uninstall"

    # Wait and verify
    sleep 1
    if curl -s http://localhost:3000/api/metrics > /dev/null 2>&1; then
      echo "  Status: RUNNING"
    else
      echo "  Status: STARTING (check log if it doesn't come up)"
    fi
    ;;

  uninstall)
    launchctl unload "$PLIST_DST" 2>/dev/null || true
    rm -f "$PLIST_DST"
    echo "Bulwark Dashboard uninstalled."
    echo "  Runtime dir preserved at: $RUNTIME_DIR"
    echo "  To fully remove: rm -rf \"$RUNTIME_DIR\""
    ;;

  status)
    if curl -s http://localhost:3000/api/metrics > /dev/null 2>&1; then
      METRICS=$(curl -s http://localhost:3000/api/metrics)
      echo "Bulwark Dashboard: RUNNING"
      echo "  URL: http://localhost:3000"
      echo "  Metrics: $METRICS"
    else
      echo "Bulwark Dashboard: NOT RUNNING"
      if [ -f "$PLIST_DST" ]; then
        echo "  Service is installed but not responding. Check log:"
        echo "  tail -20 \"$RUNTIME_DIR/bulwark-dashboard.log\""
      else
        echo "  Service is not installed. Run: bash $0 install"
      fi
    fi
    ;;

  restart)
    launchctl unload "$PLIST_DST" 2>/dev/null || true
    lsof -ti:3000 | xargs kill -9 2>/dev/null || true
    sleep 1
    launchctl load "$PLIST_DST"
    echo "Bulwark Dashboard restarted."
    sleep 1
    if curl -s http://localhost:3000/api/metrics > /dev/null 2>&1; then
      echo "  Status: RUNNING"
    else
      echo "  Status: STARTING"
    fi
    ;;

  sync)
    echo "Syncing dashboard source to runtime..."
    sync_runtime
    echo "Done. Restart the service to pick up changes:"
    echo "  bash $0 restart"
    ;;

  *)
    echo "Usage: $0 [install|uninstall|status|restart|sync]"
    exit 1
    ;;
esac
