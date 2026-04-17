"""Spec-driven tests for the LLM-facing red-team tiers.

spec/contracts/llm_facing_tiers.yaml and ADR-018.
"""
from __future__ import annotations

import pytest


class TestLLMTierSelection:
    def test_llm_quick_selector_shape(self):
        """G-LLM-TIER-001: 10 probes across 10 distinct families, one prompt per class."""
        from bulwark.integrations.redteam import ProductionRedTeam as PRT
        selectors = PRT.TIER_CLASS_SELECTORS["llm-quick"]
        assert len(selectors) == 10, "llm-quick must declare exactly 10 probe classes"
        families = {fam for fam, _cls, _n in selectors}
        assert len(families) == 10, "llm-quick must span 10 distinct families"
        for _fam, _cls, n in selectors:
            assert n == 1, "llm-quick takes exactly one prompt per class"

    def test_llm_suite_selector_shape(self):
        """G-LLM-TIER-002: ~200 probes across ≥15 families with per-class caps."""
        from bulwark.integrations.redteam import ProductionRedTeam as PRT
        selectors = PRT.TIER_CLASS_SELECTORS["llm-suite"]
        total = sum(n for _fam, _cls, n in selectors)
        families = {fam for fam, _cls, _n in selectors}
        assert 150 <= total <= 300, f"llm-suite should be ~200 prompts, got {total}"
        assert len(families) >= 15, f"llm-suite must span ≥15 families, got {len(families)}"
        # No single family dominates
        from collections import Counter
        fam_counts = Counter()
        for fam, _cls, n in selectors:
            fam_counts[fam] += n
        assert max(fam_counts.values()) <= total * 0.20, "no family should exceed 20% of the suite"

    def test_new_tiers_use_class_selectors_not_families(self):
        """G-LLM-TIER-003: llm-* tiers live in TIER_CLASS_SELECTORS."""
        from bulwark.integrations.redteam import ProductionRedTeam as PRT
        assert "llm-quick" in PRT.TIER_CLASS_SELECTORS
        assert "llm-suite" in PRT.TIER_CLASS_SELECTORS
        # And NOT in TIER_FAMILIES
        assert "llm-quick" not in PRT.TIER_FAMILIES
        assert "llm-suite" not in PRT.TIER_FAMILIES

    def test_unavailable_class_is_skipped_not_fatal(self, monkeypatch):
        """G-LLM-TIER-004: broken garak class doesn't crash the whole tier load."""
        from bulwark.integrations.redteam import ProductionRedTeam

        # Monkey-patch selectors so one entry references a fake class.
        fake_selectors = [
            ("garak_family_that_does_not_exist", "FakeClass", 1),
        ]
        monkeypatch.setattr(
            ProductionRedTeam,
            "TIER_CLASS_SELECTORS",
            {"llm-quick-test-only": fake_selectors},
        )
        runner = ProductionRedTeam(project_dir=".", tier="llm-quick-test-only")
        payloads = runner._get_class_selector_payloads()
        assert payloads == []  # no crash, empty list

    def test_dashboard_exposes_new_tiers(self):
        """G-LLM-TIER-005: /api/redteam/tiers lists llm-quick + llm-suite."""
        pytest.importorskip("fastapi")
        pytest.importorskip("garak")
        # Bust cache so our new tiers show up
        import bulwark.dashboard.app as app_mod
        app_mod._redteam_tiers_cache = None
        tiers_payload = app_mod._compute_redteam_tiers()
        ids = {t["id"] for t in tiers_payload["tiers"]}
        assert "llm-quick" in ids
        assert "llm-suite" in ids
        # Probe counts are non-zero and sensible
        for t in tiers_payload["tiers"]:
            if t["id"] == "llm-quick":
                assert t["probe_count"] == 10
            elif t["id"] == "llm-suite":
                assert 150 <= t["probe_count"] <= 300


class TestIntegrationToggleCoherence:
    def test_disable_pops_from_detection_checks(self, monkeypatch):
        """G-INTEGRATIONS-001: PUT integrations/{name} with enabled=false removes live check."""
        pytest.importorskip("fastapi")
        from fastapi.testclient import TestClient
        import bulwark.dashboard.app as app_mod

        # Seed a fake check into _detection_checks
        app_mod._detection_checks["protectai"] = lambda text: None
        # Ensure config has the entry too
        from bulwark.dashboard.config import IntegrationConfig
        app_mod.config.integrations["protectai"] = IntegrationConfig(enabled=True, installed=True)

        client = TestClient(app_mod.app)
        r = client.put("/api/integrations/protectai", json={"enabled": False})
        assert r.status_code == 200
        assert "protectai" not in app_mod._detection_checks, \
            "detector must be removed from _detection_checks on disable"

    def test_enable_without_activate_does_not_reload(self):
        """NG-INTEGRATIONS-001: PUT enabled=true alone does not auto-load the model."""
        pytest.importorskip("fastapi")
        from fastapi.testclient import TestClient
        import bulwark.dashboard.app as app_mod

        app_mod._detection_checks.pop("protectai", None)
        client = TestClient(app_mod.app)
        client.put("/api/integrations/protectai", json={"enabled": True})
        # Flag set, but model not loaded — explicit activate required (G-INTEGRATIONS-002)
        assert "protectai" not in app_mod._detection_checks


class TestLLMTierNonGuarantees:
    def test_detector_filtering_acknowledged(self):
        """NG-LLM-TIER-001: the curated list assumes detectors may still filter probes.

        This is a documentary test — ADR-018 explicitly documents the detector-bypass
        recommendation. The non-guarantee exists so users don't think these tiers
        magically bypass the full stack.
        """
        from pathlib import Path
        adr = Path(__file__).parent.parent / "spec" / "decisions" / "018-llm-facing-tiers.md"
        assert adr.exists()
        body = adr.read_text().lower()
        assert "bypass-detectors" in body

    def test_class_list_is_static(self):
        """NG-LLM-TIER-002: the selector list is a code-level constant, not auto-refreshed."""
        from bulwark.integrations.redteam import ProductionRedTeam as PRT
        # Read the module source to confirm the selectors are inline tuples, not a query.
        import inspect
        src = inspect.getsource(PRT)
        assert "TIER_CLASS_SELECTORS" in src
        assert 'ProbeRegistry' not in src  # nothing dynamic here
