"""Back-compat shim: `bulwark_falsepos` → `bulwark.tools.falsepos` (ADR-050).

The real module moved to `bulwark.tools.falsepos` in v2.5.13. This shim
keeps `python -m bulwark_falsepos`, `from bulwark_falsepos import ...`,
and `from bulwark_falsepos.<submodule> import ...` working for v2.5.x.

**Will be removed in v3.** Migrate to `import bulwark.tools.falsepos`.
"""
from __future__ import annotations

import sys as _sys

from bulwark.tools import falsepos as _real
from bulwark.tools.falsepos import (  # noqa: F401  (re-exports)
    corpus,
    report,
    runner,
)

__version__ = _real.__version__

_sys.modules[__name__ + ".corpus"] = corpus
_sys.modules[__name__ + ".report"] = report
_sys.modules[__name__ + ".runner"] = runner
