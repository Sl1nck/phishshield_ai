import json
from unittest.mock import MagicMock

from phishshield.core.llm.schemas import RiskLevel, ThreatAnalysisReport
from phishshield.pipeline import PipelineReport
from phishshield.scraper.parser import ParsedDOM
from phishshield.takedown.generator import TakedownGenerator
from phishshield.takedown.schemas import NoticeSeverity


def test_takedown_notice_generation():
    mock_parsed_dom = ParsedDOM(title="Fake Login", input_fields=[], form_actions=[])

    mock_heuristic = MagicMock()
    mock_heuristic.total_score = 85

    mock_ai_report = ThreatAnalysisReport(
        risk_score=90,
        risk_level=RiskLevel.HIGH,
        impersonated_brand="Banco Test",
        detected_indicators=["Inyección de Script", "Formulario Cripto"],
        reasoning="Captura maliciosa de llaves privadas.",
        recommended_action="Takedown inmediato.",
    )

    pipeline_report = PipelineReport(
        url="https://phishing-site.com",
        parsed_dom=mock_parsed_dom,
        heuristic_result=mock_heuristic,
        ai_report=mock_ai_report,
    )

    generator = TakedownGenerator()
    notice = generator.generate_notice(
        pipeline_report, abuse_email="abuse@hostingprovider.com"
    )

    assert notice.target_url == "https://phishing-site.com"
    assert notice.severity == NoticeSeverity.CRITICAL
    assert notice.impersonated_brand == "Banco Test"
    assert "SOLICITUD URGENTE DE DESACTIVACIÓN" in notice.notice_body
    assert notice.abuse_email == "abuse@hostingprovider.com"


def test_takedown_export_to_json():
    mock_parsed_dom = ParsedDOM(title="Fake Login", input_fields=[], form_actions=[])
    mock_heuristic = MagicMock(total_score=85)
    mock_ai_report = ThreatAnalysisReport(
        risk_score=90,
        risk_level=RiskLevel.HIGH,
        impersonated_brand="Banco Test",
        detected_indicators=["Inyección de Script"],
        reasoning="Captura maliciosa.",
        recommended_action="Takedown inmediato.",
    )
    pipeline_report = PipelineReport(
        url="https://phishing-site.com",
        parsed_dom=mock_parsed_dom,
        heuristic_result=mock_heuristic,
        ai_report=mock_ai_report,
    )

    generator = TakedownGenerator()
    notice = generator.generate_notice(pipeline_report, abuse_email="abuse@test.com")
    json_output = generator.to_json(notice)

    data = json.loads(json_output)
    assert data["target_url"] == "https://phishing-site.com"
    assert data["abuse_email"] == "abuse@test.com"
    assert "notice_body" in data


def test_takedown_export_to_text():
    mock_parsed_dom = ParsedDOM(title="Fake Login", input_fields=[], form_actions=[])
    mock_heuristic = MagicMock(total_score=85)
    mock_ai_report = ThreatAnalysisReport(
        risk_score=90,
        risk_level=RiskLevel.HIGH,
        impersonated_brand="Banco Test",
        detected_indicators=["Inyección de Script"],
        reasoning="Captura maliciosa.",
        recommended_action="Takedown inmediato.",
    )
    pipeline_report = PipelineReport(
        url="https://phishing-site.com",
        parsed_dom=mock_parsed_dom,
        heuristic_result=mock_heuristic,
        ai_report=mock_ai_report,
    )

    generator = TakedownGenerator()
    notice = generator.generate_notice(pipeline_report, abuse_email="abuse@test.com")
    text_output = generator.to_text(notice)

    assert isinstance(text_output, str)
    assert "https://phishing-site.com" in text_output
    assert "abuse@test.com" in text_output


def test_takedown_notice_fallback_without_ai():
    mock_parsed_dom = ParsedDOM(title="Fake Login", input_fields=[], form_actions=[])
    mock_heuristic = MagicMock(total_score=60)
    pipeline_report = PipelineReport(
        url="https://phishing-site.com",
        parsed_dom=mock_parsed_dom,
        heuristic_result=mock_heuristic,
        ai_report=None,
    )

    generator = TakedownGenerator()
    notice = generator.generate_notice(pipeline_report)

    assert notice.target_url == "https://phishing-site.com"
    assert notice.severity in [NoticeSeverity.HIGH, NoticeSeverity.MEDIUM]
