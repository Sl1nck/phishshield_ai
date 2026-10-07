from phishshield.core.rules.engine import HeuristicEngine
from phishshield.core.rules.schemas import RuleSeverity


def test_heuristic_engine_clean_url():
    engine = HeuristicEngine()
    result = engine.analyze("https://google.com")

    assert result.total_heuristic_score == 0
    assert result.highest_severity == RuleSeverity.INFO
    assert len(result.triggered_rules) == 0
    assert result.executed_rules_count == 3


def test_heuristic_engine_suspicious_url():
    engine = HeuristicEngine()
    # URL con IP directa
    result = engine.analyze("http://192.168.1.1/login")

    assert len(result.triggered_rules) >= 1
    assert result.total_heuristic_score >= 40
    assert result.highest_severity == RuleSeverity.HIGH
    assert result.should_escalate_to_ai is True
