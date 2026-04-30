"""Back-compat shim: `bulwark_bench` → `bulwark.tools.bench` (ADR-050).

The real module moved to `bulwark.tools.bench` in v2.5.13. This shim
keeps `python -m bulwark_bench`, `from bulwark_bench import ...`, and
`from bulwark_bench.<submodule> import ...` working for v2.5.x.

**Will be removed in v3.** Migrate to `import bulwark.tools.bench`.
"""
from __future__ import annotations

import sys as _sys

from bulwark.tools import bench as _real
from bulwark.tools.bench import (  # noqa: F401  (re-exports)
    bulwark_client,
    configs,
    report,
    runner,
)

__version__ = _real.__version__

# Make `from bulwark_bench.configs import X` resolve to the real submodules
# without re-importing them under the old name.
_sys.modules[__name__ + ".bulwark_client"] = bulwark_client
_sys.modules[__name__ + ".configs"] = configs
_sys.modules[__name__ + ".report"] = report
_sys.modules[__name__ + ".runner"] = runner
