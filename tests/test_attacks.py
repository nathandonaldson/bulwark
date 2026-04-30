"""Tests for the attack suite library."""
from __future__ import annotations

import pytest

from bulwark.attacks import Attack, AttackCategory, AttackSuite


class TestAttackSuiteLoading:
    """Tests that the suite loads correctly with all built-in attacks."""

    def test_suite_loads_without_error(self):
        suite = AttackSuite()
        assert suite.attacks is not None

    def test_suite_has_attacks(self):
        suite = AttackSuite()
        assert len(suite.attacks) > 0

    def test_suite_has_at_least_75_attacks(self):
        suite = AttackSuite()
        assert len(suite.attacks) >= 75, (
            f"Expected at least 75 attacks, got {len(suite.attacks)}"
        )


class TestAttackCompleteness:
    """Tests that every attack has all required fields populated."""

    @pytest.fixture()
    def suite(self):
        return AttackSuite()

    def test_all_attacks_have_name(self, suite: AttackSuite):
        for attack in suite.attacks:
            assert attack.name, f"Attack missing name: {attack}"

    def test_all_attacks_have_category(self, suite: AttackSuite):
        for attack in suite.attacks:
            assert isinstance(attack.category, AttackCategory), (
                f"Attack '{attack.name}' has invalid category: {attack.category}"
            )

    def test_all_attacks_have_description(self, suite: AttackSuite):
        for attack in suite.attacks:
            assert attack.description, (
                f"Attack '{attack.name}' missing description"
            )

    def test_all_attacks_have_nonempty_payload(self, suite: AttackSuite):
        for attack in suite.attacks:
            assert attack.payload, (
                f"Attack '{attack.name}' has empty payload"
            )
            assert len(attack.payload) > 0, (
                f"Attack '{attack.name}' has zero-length payload"
            )

    def test_all_attacks_have_target(self, suite: AttackSuite):
        valid_targets = {"sanitizer", "boundary", "canary", "executor", "isolator"}
        for attack in suite.attacks:
            assert attack.target in valid_targets, (
                f"Attack '{attack.name}' has invalid target '{attack.target}'. "
                f"Must be one of {valid_targets}"
            )

    def test_all_attacks_have_severity(self, suite: AttackSuite):
        valid_severities = {"low", "medium", "high", "critical"}
        for attack in suite.attacks:
            assert attack.severity in valid_severities, (
                f"Attack '{attack.name}' has invalid severity '{attack.severity}'. "
                f"Must be one of {valid_severities}"
            )

    def test_no_duplicate_attack_names(self, suite: AttackSuite):
        names = [a.name for a in suite.attacks]
        duplicates = [n for n in names if names.count(n) > 1]
        assert len(set(duplicates)) == 0, (
            f"Duplicate attack names found: {set(duplicates)}"
        )


class TestCategoryFiltering:
    """Tests for get_by_category."""

    @pytest.fixture()
    def suite(self):
        return AttackSuite()

    def test_each_category_has_at_least_2_attacks(self, suite: AttackSuite):
        for category in AttackCategory:
            # SPLIT_EVASION is tokenizer-dependent and generated on demand
            # by AttackSuite.generate_split_evasion_samples — not loaded
            # into the static catalog. See ADR-046.
            if category is AttackCategory.SPLIT_EVASION:
                continue
            attacks = suite.get_by_category(category)
            assert len(attacks) >= 2, (
                f"Category {category.value} has only {len(attacks)} attack(s), "
                f"expected at least 2"
            )

    def test_filter_returns_correct_category(self, suite: AttackSuite):
        for category in AttackCategory:
            attacks = suite.get_by_category(category)
            for attack in attacks:
                assert attack.category == category, (
                    f"Attack '{attack.name}' has category {attack.category} "
                    f"but was returned for {category}"
                )

    def test_all_categories_sum_to_total(self, suite: AttackSuite):
        total = sum(
            len(suite.get_by_category(cat)) for cat in AttackCategory
        )
        assert total == len(suite.attacks), (
            f"Category counts ({total}) don't sum to total ({len(suite.attacks)})"
        )

    def test_instruction_override_has_attacks(self, suite: AttackSuite):
        attacks = suite.get_by_category(AttackCategory.INSTRUCTION_OVERRIDE)
        assert len(attacks) >= 3

    def test_steganography_has_attacks(self, suite: AttackSuite):
        attacks = suite.get_by_category(AttackCategory.STEGANOGRAPHY)
        assert len(attacks) >= 2

    def test_boundary_escape_has_attacks(self, suite: AttackSuite):
        attacks = suite.get_by_category(AttackCategory.BOUNDARY_ESCAPE)
        assert len(attacks) >= 2

    def test_tool_manipulation_has_attacks(self, suite: AttackSuite):
        attacks = suite.get_by_category(AttackCategory.TOOL_MANIPULATION)
        assert len(attacks) >= 2


class TestTargetFiltering:
    """Tests for get_by_target."""

    @pytest.fixture()
    def suite(self):
        return AttackSuite()

    def test_boundary_target_returns_results(self, suite: AttackSuite):
        attacks = suite.get_by_target("boundary")
        assert len(attacks) > 0

    def test_sanitizer_target_returns_results(self, suite: AttackSuite):
        attacks = suite.get_by_target("sanitizer")
        assert len(attacks) > 0

    def test_canary_target_returns_results(self, suite: AttackSuite):
        attacks = suite.get_by_target("canary")
        assert len(attacks) > 0

    def test_executor_target_returns_results(self, suite: AttackSuite):
        attacks = suite.get_by_target("executor")
        assert len(attacks) > 0

    def test_isolator_target_returns_results(self, suite: AttackSuite):
        attacks = suite.get_by_target("isolator")
        assert len(attacks) > 0

    def test_filter_returns_correct_target(self, suite: AttackSuite):
        for target in ("sanitizer", "boundary", "canary", "executor", "isolator"):
            attacks = suite.get_by_target(target)
            for attack in attacks:
                assert attack.target == target, (
                    f"Attack '{attack.name}' has target '{attack.target}' "
                    f"but was returned for '{target}'"
                )

    def test_nonexistent_target_returns_empty(self, suite: AttackSuite):
        attacks = suite.get_by_target("nonexistent")
        assert attacks == []

    def test_all_targets_sum_to_total(self, suite: AttackSuite):
        targets = {"sanitizer", "boundary", "canary", "executor", "isolator"}
        total = sum(len(suite.get_by_target(t)) for t in targets)
        assert total == len(suite.attacks)


class TestSeverityFiltering:
    """Tests for get_by_severity."""

    @pytest.fixture()
    def suite(self):
        return AttackSuite()

    def test_critical_severity_returns_results(self, suite: AttackSuite):
        attacks = suite.get_by_severity("critical")
        assert len(attacks) > 0

    def test_high_severity_returns_results(self, suite: AttackSuite):
        attacks = suite.get_by_severity("high")
        assert len(attacks) > 0

    def test_medium_severity_returns_results(self, suite: AttackSuite):
        attacks = suite.get_by_severity("medium")
        assert len(attacks) > 0

    def test_filter_returns_correct_severity(self, suite: AttackSuite):
        for severity in ("low", "medium", "high", "critical"):
            attacks = suite.get_by_severity(severity)
            for attack in attacks:
                assert attack.severity == severity

    def test_nonexistent_severity_returns_empty(self, suite: AttackSuite):
        attacks = suite.get_by_severity("nonexistent")
        assert attacks == []


class TestAttackDataclass:
    """Tests for the Attack dataclass itself."""

    def test_attack_creation(self):
        attack = Attack(
            name="test",
            category=AttackCategory.ENCODING,
            description="A test attack",
            payload="test payload",
            target="sanitizer",
            severity="low",
        )
        assert attack.name == "test"
        assert attack.category == AttackCategory.ENCODING
        assert attack.payload == "test payload"

    def test_attack_equality(self):
        kwargs = dict(
            name="test",
            category=AttackCategory.ENCODING,
            description="desc",
            payload="payload",
            target="sanitizer",
            severity="low",
        )
        assert Attack(**kwargs) == Attack(**kwargs)

    def test_attack_inequality(self):
        base = dict(
            name="test",
            category=AttackCategory.ENCODING,
            description="desc",
            payload="payload",
            target="sanitizer",
            severity="low",
        )
        a1 = Attack(**base)
        a2 = Attack(**{**base, "name": "different"})
        assert a1 != a2


class TestAttackCategory:
    """Tests for the AttackCategory enum."""

    def test_all_categories_exist(self):
        expected = {
            "instruction_override",
            "data_exfiltration",
            "cross_contamination",
            "steganography",
            "delimiter_escape",
            "encoding",
            "social_engineering",
            "multi_turn",
            "boundary_escape",
            "tool_manipulation",
            # split_evasion (ADR-046) — tokenizer-dependent corpus
            # generated by AttackSuite.generate_split_evasion_samples;
            # not in the static catalog but is a valid category.
            "split_evasion",
        }
        actual = {c.value for c in AttackCategory}
        assert actual == expected

    def test_category_count(self):
        # 10 static categories + split_evasion (ADR-046, generated on demand).
        assert len(AttackCategory) == 11
