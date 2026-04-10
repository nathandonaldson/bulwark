"""Pipeline validator — run attack patterns against your defenses."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional, Callable
from enum import Enum

from bulwark.sanitizer import Sanitizer
from bulwark.trust_boundary import TrustBoundary
from bulwark.canary import CanarySystem
from bulwark.attacks import AttackSuite, Attack, AttackCategory


class DefenseVerdict(Enum):
    BLOCKED = "blocked"      # Attack was neutralized
    REDUCED = "reduced"      # Attack was partially mitigated
    EXPOSED = "exposed"      # Attack passed through unmitigated
    SKIPPED = "skipped"      # Defense layer not configured


@dataclass
class AttackResult:
    """Result of running one attack against the pipeline."""
    attack: Attack
    sanitizer_verdict: DefenseVerdict
    boundary_verdict: DefenseVerdict
    canary_verdict: DefenseVerdict
    overall_verdict: DefenseVerdict
    details: str = ""


@dataclass
class ValidationReport:
    """Full report from running the attack suite."""
    results: list[AttackResult]

    @property
    def total(self) -> int:
        return len(self.results)

    @property
    def blocked(self) -> int:
        return sum(1 for r in self.results if r.overall_verdict == DefenseVerdict.BLOCKED)

    @property
    def reduced(self) -> int:
        return sum(1 for r in self.results if r.overall_verdict == DefenseVerdict.REDUCED)

    @property
    def exposed(self) -> int:
        return sum(1 for r in self.results if r.overall_verdict == DefenseVerdict.EXPOSED)

    @property
    def score(self) -> float:
        """Defense score 0-100. Blocked=full credit, Reduced=half, Exposed=zero."""
        if not self.results:
            return 0.0
        points = sum(
            1.0 if r.overall_verdict == DefenseVerdict.BLOCKED
            else 0.5 if r.overall_verdict == DefenseVerdict.REDUCED
            else 0.0
            for r in self.results
        )
        return round((points / len(self.results)) * 100, 1)

    def by_category(self) -> dict[AttackCategory, list[AttackResult]]:
        result = {}
        for r in self.results:
            cat = r.attack.category
            if cat not in result:
                result[cat] = []
            result[cat].append(r)
        return result

    def summary(self) -> str:
        """Human-readable summary."""
        lines = [
            f"Bulwark Validation Report",
            f"========================",
            f"Score: {self.score}/100",
            f"",
            f"  Blocked:  {self.blocked}/{self.total}",
            f"  Reduced:  {self.reduced}/{self.total}",
            f"  Exposed:  {self.exposed}/{self.total}",
            f"",
        ]

        # Per-category breakdown
        for cat, results in self.by_category().items():
            cat_blocked = sum(1 for r in results if r.overall_verdict == DefenseVerdict.BLOCKED)
            cat_total = len(results)
            status = "\u2705" if cat_blocked == cat_total else "\u26a0\ufe0f" if cat_blocked > 0 else "\u274c"
            lines.append(f"  {status} {cat.value}: {cat_blocked}/{cat_total} blocked")

        # List exposed attacks
        exposed = [r for r in self.results if r.overall_verdict == DefenseVerdict.EXPOSED]
        if exposed:
            lines.append(f"\nExposed attacks ({len(exposed)}):")
            for r in exposed:
                lines.append(f"  \u274c [{r.attack.severity}] {r.attack.name}: {r.attack.description}")
                if r.details:
                    lines.append(f"     {r.details}")

        return "\n".join(lines)


@dataclass
class PipelineValidator:
    """Validate a Bulwark pipeline against known attack patterns.

    Runs each attack through configured defense layers and reports
    which attacks are blocked, reduced, or exposed.
    """
    sanitizer: Optional[Sanitizer] = None
    trust_boundary: Optional[TrustBoundary] = None
    canary: Optional[CanarySystem] = None
    attack_suite: Optional[AttackSuite] = None

    def validate(self, categories: Optional[list[AttackCategory]] = None) -> ValidationReport:
        """Run all attacks (or filtered by category) and produce a report.

        For each attack:
        1. Test sanitizer: does clean() meaningfully change the payload?
        2. Test trust boundary: does wrap() add protective context?
        3. Test canary: if payload tries to include canary tokens, does check() detect it?
        4. Determine overall verdict based on target layer and results.
        """
        suite = self.attack_suite or AttackSuite()
        attacks = suite.attacks
        if categories:
            attacks = [a for a in attacks if a.category in categories]

        results = []
        for attack in attacks:
            result = self._test_attack(attack)
            results.append(result)

        return ValidationReport(results=results)

    def _test_attack(self, attack: Attack) -> AttackResult:
        """Test a single attack against all configured layers."""
        sanitizer_verdict = DefenseVerdict.SKIPPED
        boundary_verdict = DefenseVerdict.SKIPPED
        canary_verdict = DefenseVerdict.SKIPPED
        details_parts = []

        # Test sanitizer
        if self.sanitizer:
            cleaned = self.sanitizer.clean(attack.payload)
            if cleaned != attack.payload:
                # Sanitizer modified the payload
                reduction = 1.0 - (len(cleaned) / max(len(attack.payload), 1))
                if reduction > 0.5:
                    sanitizer_verdict = DefenseVerdict.BLOCKED
                    details_parts.append(f"Sanitizer removed {reduction:.0%} of payload")
                else:
                    sanitizer_verdict = DefenseVerdict.REDUCED
                    details_parts.append(f"Sanitizer reduced payload by {reduction:.0%}")
            else:
                sanitizer_verdict = DefenseVerdict.EXPOSED
                details_parts.append("Sanitizer: payload unchanged")

        # Test trust boundary
        if self.trust_boundary:
            wrapped = self.trust_boundary.wrap(attack.payload, source="test")
            # Check if the payload contains delimiter escape attempts
            has_escape_attempt = any(marker in attack.payload for marker in [
                '</untrusted_', '<system', '<trusted_', '```\n\n',
                '[END', 'END]',
            ])
            if has_escape_attempt:
                boundary_verdict = DefenseVerdict.REDUCED
                details_parts.append("Trust boundary: escape attempt detected in payload")
            else:
                boundary_verdict = DefenseVerdict.BLOCKED
                details_parts.append("Trust boundary: content properly wrapped")

        # Test canary
        if self.canary:
            # Check if the payload could trigger canary detection
            check_result = self.canary.check(attack.payload)
            if check_result.leaked:
                canary_verdict = DefenseVerdict.BLOCKED
                details_parts.append(f"Canary detected tokens: {check_result.sources}")
            else:
                # Canary only catches exfiltration in output, not in input
                # For exfiltration attacks, the verdict depends on whether
                # canaries would catch the output, not the input
                if attack.category == AttackCategory.DATA_EXFILTRATION:
                    canary_verdict = DefenseVerdict.REDUCED
                    details_parts.append("Canary: would detect if tokens appear in output")
                else:
                    canary_verdict = DefenseVerdict.SKIPPED

        # Determine overall verdict based on attack target
        target_verdict = {
            "sanitizer": sanitizer_verdict,
            "boundary": boundary_verdict,
            "canary": canary_verdict,
            "executor": DefenseVerdict.BLOCKED if self.sanitizer and self.trust_boundary else DefenseVerdict.EXPOSED,
            "isolator": DefenseVerdict.BLOCKED if self.sanitizer and self.trust_boundary else DefenseVerdict.EXPOSED,
        }.get(attack.target, DefenseVerdict.EXPOSED)

        # If any layer blocked it, overall is at least reduced
        verdicts = [sanitizer_verdict, boundary_verdict, canary_verdict]
        active_verdicts = [v for v in verdicts if v != DefenseVerdict.SKIPPED]

        if any(v == DefenseVerdict.BLOCKED for v in active_verdicts):
            overall = DefenseVerdict.BLOCKED
        elif any(v == DefenseVerdict.REDUCED for v in active_verdicts):
            overall = DefenseVerdict.REDUCED
        elif target_verdict != DefenseVerdict.SKIPPED:
            overall = target_verdict
        else:
            overall = DefenseVerdict.EXPOSED

        return AttackResult(
            attack=attack,
            sanitizer_verdict=sanitizer_verdict,
            boundary_verdict=boundary_verdict,
            canary_verdict=canary_verdict,
            overall_verdict=overall,
            details="; ".join(details_parts),
        )
