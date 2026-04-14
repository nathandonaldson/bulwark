"""Run the Bulwark Dashboard server.

Usage: python -m bulwark.dashboard [--port PORT] [--host HOST]
"""
import argparse
import os
import shutil
from pathlib import Path


def _auto_sync():
    """Sync from repo if running as installed service and repo is accessible."""
    runtime_dir = Path(__file__).parent.parent  # ~/Library/Application Support/bulwark-dashboard/
    marker = runtime_dir / ".source-repo"

    if not marker.exists():
        return

    repo_dir = Path(marker.read_text().strip())
    if not repo_dir.exists() or not (repo_dir / "dashboard" / "app.py").exists():
        return

    # Sync dashboard Python files
    for f in (repo_dir / "dashboard").glob("*.py"):
        dest = runtime_dir / "dashboard" / f.name
        if not dest.exists() or f.stat().st_mtime > dest.stat().st_mtime:
            shutil.copy2(str(f), str(dest))

    # Sync static files
    src_static = repo_dir / "dashboard" / "static"
    dst_static = runtime_dir / "dashboard" / "static"
    if src_static.exists():
        for f in src_static.iterdir():
            dest = dst_static / f.name
            if not dest.exists() or f.stat().st_mtime > dest.stat().st_mtime:
                shutil.copy2(str(f), str(dest))

    # Sync bulwark source
    src_bulwark = repo_dir / "src" / "bulwark"
    dst_bulwark = runtime_dir / "src" / "bulwark"
    if src_bulwark.exists():
        for f in src_bulwark.rglob("*.py"):
            rel = f.relative_to(src_bulwark)
            dest = dst_bulwark / rel
            dest.parent.mkdir(parents=True, exist_ok=True)
            if not dest.exists() or f.stat().st_mtime > dest.stat().st_mtime:
                shutil.copy2(str(f), str(dest))


def main():
    parser = argparse.ArgumentParser(description="Bulwark Dashboard")
    parser.add_argument("--port", type=int, default=3000, help="Port to listen on")
    parser.add_argument("--host", type=str, default="127.0.0.1", help="Host to bind to (default: localhost only)")
    args = parser.parse_args()

    # Auto-sync from repo on startup if configured
    try:
        _auto_sync()
    except Exception:
        pass  # Don't block startup if sync fails

    import uvicorn
    uvicorn.run("bulwark.dashboard.app:app", host=args.host, port=args.port, reload=False)


if __name__ == "__main__":
    main()
