"""Back-compat shim: `python -m bulwark_falsepos` → `bulwark.tools.falsepos` (ADR-050)."""
from bulwark.tools.falsepos.__main__ import main

if __name__ == "__main__":
    raise SystemExit(main())
