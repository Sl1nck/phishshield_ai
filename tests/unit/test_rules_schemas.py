from phishshield.core.rules.schemas import (
    HeuristicAnalysisResult,
    RuleResult,
    RuleSeverity,
)


def test_rule_result_instantiation():
    result = RuleResult(
        rule_id="RULE-URL-001",
        name="Prueba IP Directa",
        triggered=True,
        severity=RuleSeverity.HIGH,
        score_impact=40,
        description="Uso de dirección IP en lugar de dominio",
    )
    assert result.rule_id == "RULE-URL-001"
    assert result.triggered is True
    assert result.severity == RuleSeverity.HIGH
    assert result.score_impact == 40


def test_heuristic_analysis_result_defaults():
    analysis = HeuristicAnalysisResult()
    assert analysis.total_heuristic_score == 0
    assert analysis.highest_severity == RuleSeverity.INFO
    assert analysis.triggered_rules == []
    assert analysis.executed_rules_count == 0
    assert analysis.should_escalate_to_ai is True
