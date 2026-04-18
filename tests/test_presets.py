"""Spec-driven tests for presets — spec/contracts/presets.yaml + ADR-021."""
import os
import textwrap
from pathlib import Path

import pytest
import yaml

from bulwark.presets import Preset, load_presets, _ALLOWED_FAMILIES


try:
    from fastapi.testclient import TestClient
    HAS_FASTAPI = True
except ImportError:
    HAS_FASTAPI = False


class TestLoader:
    """Loader tests — spec/presets.yaml default + temp override."""

    def test_default_spec_yaml_loads(self):
        """G-PRESETS-001: spec/presets.yaml loads and returns a non-empty list."""
        presets = load_presets()
        assert isinstance(presets, list)
        assert len(presets) > 0
        assert all(isinstance(p, Preset) for p in presets)

    def test_every_preset_has_required_fields(self):
        """G-PRESETS-002: every preset has id, name, family, payload."""
        for p in load_presets():
            assert p.id, f"preset missing id"
            assert p.name, f"preset {p.id} missing name"
            assert p.family, f"preset {p.id} missing family"
            assert p.payload, f"preset {p.id} missing payload"

    def test_every_preset_has_allowed_family(self):
        """G-PRESETS-004: every preset family is one of the allowed values."""
        for p in load_presets():
            assert p.family in _ALLOWED_FAMILIES, (
                f"preset {p.id} has invalid family '{p.family}'"
            )

    def test_ids_are_unique(self):
        """G-PRESETS-003: preset ids are unique."""
        ids = [p.id for p in load_presets()]
        assert len(ids) == len(set(ids)), "duplicate preset id"

    def test_duplicate_id_raises(self, tmp_path):
        """G-PRESETS-003: duplicate id raises ValueError at load time."""
        bad = tmp_path / "presets.yaml"
        bad.write_text(textwrap.dedent("""
            presets:
              - id: dup
                name: A
                family: sanitizer
                payload: x
              - id: dup
                name: B
                family: sanitizer
                payload: y
        """).strip())
        with pytest.raises(ValueError, match="duplicate preset id"):
            load_presets(bad)

    def test_invalid_family_raises(self, tmp_path):
        """G-PRESETS-004: invalid family raises ValueError at load time."""
        bad = tmp_path / "presets.yaml"
        bad.write_text(textwrap.dedent("""
            presets:
              - id: bad
                name: X
                family: nonsense
                payload: x
        """).strip())
        with pytest.raises(ValueError, match="invalid family"):
            load_presets(bad)

    def test_missing_required_field_raises(self, tmp_path):
        """G-PRESETS-002: missing field raises ValueError."""
        bad = tmp_path / "presets.yaml"
        bad.write_text(textwrap.dedent("""
            presets:
              - id: x
                name: X
                family: sanitizer
        """).strip())
        with pytest.raises(ValueError, match="missing required fields"):
            load_presets(bad)

    def test_empty_list_raises(self, tmp_path):
        """G-PRESETS-001: empty presets list raises (non-empty guarantee)."""
        bad = tmp_path / "presets.yaml"
        bad.write_text("presets: []")
        with pytest.raises(ValueError, match="non-empty"):
            load_presets(bad)

    def test_missing_top_level_key_raises(self, tmp_path):
        """G-PRESETS-006: malformed YAML raises."""
        bad = tmp_path / "presets.yaml"
        bad.write_text("other: key\n")
        with pytest.raises(ValueError, match="'presets' key missing"):
            load_presets(bad)


@pytest.mark.skipif(not HAS_FASTAPI, reason="FastAPI not installed")
class TestEndpoint:
    """HTTP endpoint tests — G-PRESETS-005."""

    def _client(self):
        from fastapi.testclient import TestClient
        from bulwark.dashboard.app import app
        return TestClient(app)

    def test_returns_200_with_presets_list(self):
        """G-PRESETS-005: GET /api/presets returns {presets:[...]} with 200."""
        resp = self._client().get("/api/presets")
        assert resp.status_code == 200
        body = resp.json()
        assert "presets" in body
        assert isinstance(body["presets"], list)
        assert len(body["presets"]) > 0

    def test_endpoint_fields_match_contract(self):
        """G-PRESETS-005: endpoint body mirrors YAML fields."""
        resp = self._client().get("/api/presets")
        for p in resp.json()["presets"]:
            assert "id" in p
            assert "name" in p
            assert "family" in p
            assert "payload" in p
            assert "description" in p
            assert p["family"] in _ALLOWED_FAMILIES

    def test_endpoint_is_public_no_auth_required(self, monkeypatch):
        """Presets are documented threat-model examples — public per ADR-021."""
        monkeypatch.setenv("BULWARK_API_TOKEN", "required-token")
        # Need a fresh import of app since auth middleware reads env at dispatch-time
        from fastapi.testclient import TestClient
        from bulwark.dashboard.app import app
        client = TestClient(app)
        resp = client.get("/api/presets")
        assert resp.status_code == 200

    def test_nongoal_no_translation_layer(self):
        """NG-PRESETS-001: presets are not translated. Multilingual payloads ship literal."""
        # The contract asserts no localization layer — verify a known multilingual
        # preset arrives byte-for-byte as it appears in the YAML.
        yaml_presets = {p.id: p for p in load_presets()}
        assert "multi" in yaml_presets
        body = self._client().get("/api/presets").json()
        served = next(p for p in body["presets"] if p["id"] == "multi")
        assert served["payload"] == yaml_presets["multi"].payload

    def test_nongoal_no_runtime_mutation(self):
        """NG-PRESETS-002: preset list is not user-editable at runtime. Only GET exists."""
        client = self._client()
        # No POST/PUT/DELETE/PATCH endpoints for /api/presets — all should 405.
        assert client.post("/api/presets", json={}).status_code in (404, 405)
        assert client.put("/api/presets", json={}).status_code in (404, 405)
        assert client.delete("/api/presets").status_code in (404, 405)
        assert client.patch("/api/presets", json={}).status_code in (404, 405)

    def test_nongoal_family_is_intent_not_guarantee(self):
        """NG-PRESETS-003: family field expresses intent, not a guarantee of blocking.

        The contract does not assert that `bulwark.clean(preset.payload)` blocks
        at preset.family. We assert only the contract shape: every preset carries
        a family, and it's one of the allowed values. No runtime block assertion.
        """
        for p in load_presets():
            assert p.family in _ALLOWED_FAMILIES
