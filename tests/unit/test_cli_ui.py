from unittest.mock import MagicMock

from phishshield.cli.ui import render_ai_report, render_heuristic_report
from phishshield.core.llm.schemas import RiskLevel, ThreatAnalysisReport


def test_render_heuristic_report(capsys):
    mock_rule = MagicMock()
    mock_rule.rule_id = "HEUR-01"
    mock_rule.name = "Formulario HTTP Inseguro"
    mock_rule.score_impact = 30
    mock_rule.description = "El formulario envía datos por HTTP no cifrado."

    mock_heuristic_result = MagicMock()
    mock_heuristic_result.triggered_rules = [mock_rule]
    mock_heuristic_result.total_score = 30

    render_heuristic_report(mock_heuristic_result)
    captured = capsys.readouterr()

    assert "HEUR-01" in captured.out
    assert "Formulario HTTP Inseguro" in captured.out
    assert "30/100" in captured.out


def test_render_ai_report_with_report(capsys):
    report = ThreatAnalysisReport(
        risk_score=85,
        risk_level=RiskLevel.HIGH,
        impersonated_brand="Banco Falso",
        detected_indicators=["Inyección de credenciales", "HTTP Inseguro"],
        reasoning="El sitio solicita clave secreta sobre canal sin SSL.",
        recommended_action="Bloquear acceso inmediatamente.",
    )

    render_ai_report(report)
    captured = capsys.readouterr()

    assert "85/100" in captured.out
    assert "Banco Falso" in captured.out
    assert "Inyección de credenciales" in captured.out
    assert "Bloquear acceso inmediatamente." in captured.out


def test_render_ai_report_none(capsys):
    render_ai_report(None)
    captured = capsys.readouterr()

    assert "no requirió evaluación con IA" in captured.out