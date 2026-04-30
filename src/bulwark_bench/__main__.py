"""Back-compat shim: `python -m bulwark_bench` → `bulwark.tools.bench` (ADR-050)."""
from bulwark.tools.bench.__main__ import main

if __name__ == "__main__":
    raise SystemExit(main())
