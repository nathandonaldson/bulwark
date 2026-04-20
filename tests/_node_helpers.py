"""Shared helper for dashboard UI tests that exercise JSX logic via Node.js.

Three UI test modules (events / shell / shield) previously each had their
own `node = shutil.which("node") / pytest.skip` + subprocess.run + json.loads
block. Centralizing keeps the skip reason consistent and the timeout in
one place.
"""
from __future__ import annotations

import json
import shutil
import subprocess

import pytest


def run_node_eval(harness: str, *, skip_reason: str = "node not on PATH", timeout_s: float = 5.0) -> object:
    """Evaluate `harness` as a Node.js one-liner and JSON-parse its stdout.

    Skips the calling test if `node` is not on PATH (common on minimal CI
    images and for contributors who don't run the UI locally).
    """
    node = shutil.which("node")
    if not node:
        pytest.skip(skip_reason)
    out = subprocess.run(
        [node, "-e", harness],
        check=True,
        capture_output=True,
        text=True,
        timeout=timeout_s,
    )
    return json.loads(out.stdout)
