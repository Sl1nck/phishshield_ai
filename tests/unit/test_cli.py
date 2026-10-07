from dataclasses import dataclass
from unittest.mock import AsyncMock, MagicMock, patch

from typer.testing import CliRunner

from phishshield.cli.main import app
from phishshield.core.llm.schemas import RiskLevel, ThreatAnalysisReport
from phishshield.heuristics.engine import HeuristicResult, RuleResult
from phishshield.pipeline import PipelineReport
from phishshield.scraper.parser import ParsedDOM

runner = CliRunner()


@dataclass
class MockArtifacts:
    url: str
    final_url: str
    status_code: int
    html_content: str
    screenshot_bytes: bytes


@patch("phishshield.cli.main.PlaywrightScraper")
@patch("phishshield.cli.main.GeminiAdapter")
def test_cli_scan_url_command(mock_gemini_cls, mock_scraper_cls):
    # Mock de Playwright
    mock_scraper = MagicMock()
    mock_scraper.scrape_url = AsyncMock(
        return_value=MockArtifacts(
            url="http://192.168.1.1/login",
            final_url="http://192.168.1.1/login",
            status_code=200,
            html_content="<html><body><form action='http://192.168.1.1/post'><input type='password'></form></body></html>",
            screenshot_bytes=b"fake_png_bytes",
        )
    )
    mock_scraper_cls.return_value = mock_scraper

    # Mock de GeminiAdapter
    mock_gemini = MagicMock()
    mock_gemini.analyze_phishing_site = AsyncMock(
        return_value=ThreatAnalysisReport(
            risk_score=85,
            risk_level=RiskLevel.HIGH,
            is_phishing=True,
            impersonated_brand="Unknown Bank",
            detected_indicators=["Ip in host", "Password field over HTTP"],
            reasoning="Página maliciosa detectada.",
            recommended_action="Bloquear dominio",
        )
    )
    mock_gemini_cls.return_value = mock_gemini

    result = runner.invoke(app, ["-u", "http://192.168.1.1/login"])

    assert result.exit_code == 0
    assert "Artefactos Extraídos" in result.output
    assert "Hallazgos del Motor Heurístico" in result.output
    assert "HEUR-01" in result.output  # Detectó la dirección IP en el host
    assert "Dictamen de Amenaza - PhishShield AI" in result.output


@patch("phishshield.cli.main.PhishShieldPipeline")
def test_cli_analyze_command_success(mock_pipeline_cls):
    # Setup del mock de reporte para el comando 'analyze'
    mock_pipeline_instance = mock_pipeline_cls.return_value
    mock_pipeline_instance.analyze_url_async = AsyncMock(
        return_value=PipelineReport(
            url="https://paypa1-security.com",
            parsed_dom=ParsedDOM(title="Fake Paypal"),
            heuristic_result=HeuristicResult(
                total_score=55,
                triggered_rules=[
                    RuleResult(
                        rule_id="HEUR-05",
                        name="Typosquatting",
                        triggered=True,
                        score_impact=30,
                        description="Imita a PayPal",
                    )
                ],
            ),
            ai_report=ThreatAnalysisReport(
                risk_score=90,
                risk_level=RiskLevel.CRITICAL,
                impersonated_brand="PayPal",
                detected_indicators=["Typosquatting detectado"],
                reasoning="Sitio malicioso de captura de credenciales.",
                recommended_action="Bloquear dominio inmediatamente.",
            ),
        )
    )

    result = runner.invoke(app, ["analyze", "https://paypa1-security.com"])

    assert result.exit_code == 0
    assert "https://paypa1-security.com" in result.output
    assert "55" in result.output or "CRITICAL" in result.output
