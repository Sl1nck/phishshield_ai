from typing import Any

import pytest

from phishshield.core.rules.base import BaseRule
from phishshield.core.rules.schemas import RuleResult, RuleSeverity


class ConcreteDummyRule(BaseRule):
    """Regla concreta de prueba para verificar la interfaz BaseRule."""

    def evaluate(self, url: str, parsed_dom: Any | None = None) -> RuleResult:
        return RuleResult(
            rule_id=self.rule_id,
            name=self.name,
            triggered=True,
            severity=RuleSeverity.LOW,
            score_impact=10,
            description="Regla dummy ejecutada correctamente.",
        )


def test_base_rule_cannot_be_instantiated_directly():
    """Verifica que BaseRule no se pueda instanciar directamente por ser abstracta."""
    with pytest.raises(TypeError):
        BaseRule(rule_id="RULE-TEST-001", name="Test Rule")  # type: ignore


def test_concrete_rule_implementation():
    """Verifica la ejecución de una regla concreta derivada de BaseRule."""
    rule = ConcreteDummyRule(rule_id="RULE-TEST-001", name="Test Rule")
    result = rule.evaluate("https://example.com")

    assert result.rule_id == "RULE-TEST-001"
    assert result.name == "Test Rule"
    assert result.triggered is True
    assert result.severity == RuleSeverity.LOW
    assert result.score_impact == 10
