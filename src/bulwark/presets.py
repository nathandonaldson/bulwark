"""Attack-preset loader.

Contract: spec/contracts/presets.yaml
ADR:      spec/decisions/021-presets-source-of-truth.md
          spec/decisions/023-bundle-presets-into-wheel.md
"""

from __future__ import annotations

from dataclasses import dataclass, field
from importlib import resources
from pathlib import Path
from typing import ClassVar

import yaml


_ALLOWED_FAMILIES: frozenset[str] = frozenset(
    {"sanitizer", "boundary", "detection", "canary"}
)


@dataclass(frozen=True)
class Preset:
    id: str
    name: str
    family: str
    payload: str
    description: str = ""

    REQUIRED_FIELDS: ClassVar[tuple[str, ...]] = ("id", "name", "family", "payload")

    def to_dict(self) -> dict[str, str]:
        return {
            "id": self.id,
            "name": self.name,
            "family": self.family,
            "payload": self.payload,
            "description": self.description,
        }


def _packaged_spec_path() -> Path | None:
    """Resolve the wheel-bundled copy via importlib.resources — ADR-023."""
    try:
        ref = resources.files("bulwark") / "_data" / "presets.yaml"
    except (ModuleNotFoundError, FileNotFoundError):
        return None
    if not ref.is_file():
        return None
    # Traversable → Path: in a regular (non-zip) wheel install this round-trips.
    # For zip-installed wheels, resources.as_file() would be needed — we don't
    # ship zip wheels, so accept the str(...) cast.
    return Path(str(ref))


def _walkup_spec_path() -> Path | None:
    """Walk up from this module to find repo-root/spec/presets.yaml — editable installs."""
    here = Path(__file__).resolve()
    for parent in here.parents:
        candidate = parent / "spec" / "presets.yaml"
        if candidate.is_file():
            return candidate
    return None


def _default_spec_path() -> Path:
    # Try the wheel-bundled copy first (installed environments), then walk up
    # (editable installs and source checkouts). See ADR-023 — G-PRESETS-007.
    for resolver in (_packaged_spec_path, _walkup_spec_path):
        path = resolver()
        if path is not None:
            return path
    raise FileNotFoundError(
        "spec/presets.yaml not found — neither bundled at bulwark/_data/presets.yaml "
        "nor discoverable via walk-up from " + str(Path(__file__).resolve())
    )


def load_presets(path: Path | str | None = None) -> list[Preset]:
    """Load presets from YAML. Fail loud on any schema violation — G-PRESETS-006."""
    spec_path = Path(path) if path is not None else _default_spec_path()

    with spec_path.open("r", encoding="utf-8") as f:
        data = yaml.safe_load(f)

    if not isinstance(data, dict) or "presets" not in data:
        raise ValueError(f"{spec_path}: top-level 'presets' key missing")

    raw = data["presets"]
    if not isinstance(raw, list) or not raw:
        raise ValueError(f"{spec_path}: 'presets' must be a non-empty list — G-PRESETS-001")

    seen_ids: set[str] = set()
    presets: list[Preset] = []

    for i, entry in enumerate(raw):
        if not isinstance(entry, dict):
            raise ValueError(f"{spec_path}: preset[{i}] must be a mapping")

        missing = [k for k in Preset.REQUIRED_FIELDS if k not in entry]
        if missing:
            raise ValueError(
                f"{spec_path}: preset[{i}] missing required fields {missing} — G-PRESETS-002"
            )

        pid = str(entry["id"])
        if pid in seen_ids:
            raise ValueError(f"{spec_path}: duplicate preset id '{pid}' — G-PRESETS-003")
        seen_ids.add(pid)

        family = str(entry["family"])
        if family not in _ALLOWED_FAMILIES:
            raise ValueError(
                f"{spec_path}: preset '{pid}' has invalid family '{family}'. "
                f"Expected one of {sorted(_ALLOWED_FAMILIES)} — G-PRESETS-004"
            )

        presets.append(
            Preset(
                id=pid,
                name=str(entry["name"]),
                family=family,
                payload=str(entry["payload"]),
                description=str(entry.get("description", "")).strip(),
            )
        )

    return presets
