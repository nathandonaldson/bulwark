"""Run the Bulwark Dashboard server.

Usage: python -m bulwark.dashboard [--port PORT] [--host HOST]
"""
import argparse
import os
import shutil
from pathlib import Path


def _load_dotenv(path: str = ".env") -> list[str]:
    """G-ENV-010: Load KEY=VALUE pairs from a .env file into os.environ.

    Existing env vars are never overridden. Returns the list of key names
    that were newly set (for startup logging — values never leave this
    function).
    """
    p = Path(path)
    if not p.exists():
        return []
    loaded: list[str] = []
    try:
        text = p.read_text()
    except Exception:
        return []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, val = line.partition("=")
        key = key.strip()
        val = val.strip()
        if (val.startswith('"') and val.endswith('"')) or (val.startswith("'") and val.endswith("'")):
            val = val[1:-1]
        if key and key not in os.environ:
            os.environ[key] = val
            loaded.append(key)
    return loaded


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

    # G-ENV-010: Pick up .env from cwd before any config is constructed.
    loaded_keys = _load_dotenv()
    if loaded_keys:
        bulwark_keys = [k for k in loaded_keys if k.startswith("BULWARK_")]
        print(f"Loaded {len(loaded_keys)} var(s) from .env" + (
            f" (BULWARK_*: {', '.join(bulwark_keys)})" if bulwark_keys else ""
        ))

    # Auto-sync from repo on startup if configured
    try:
        _auto_sync()
    except Exception:
        pass  # Don't block startup if sync fails

    # Make the port available to the app (for red team / webhook emitter self-references)
    os.environ["BULWARK_DASHBOARD_PORT"] = str(args.port)

    import uvicorn
    uvicorn.run("bulwark.dashboard.app:app", host=args.host, port=args.port, reload=False)


if __name__ == "__main__":
    main()
