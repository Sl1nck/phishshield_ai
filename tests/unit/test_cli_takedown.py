import json
from pathlib import Path
from unittest.mock import AsyncMock, patch

from typer.testing import CliRunner

from phishshield.cli.main import app
from phishshield.core.llm.schemas import RiskLevel, ThreatAnalysisReport
from phishshield.heuristics.engine import HeuristicResult
from phishshield.pipeline import PipelineReport

runner = CliRunner()


def create_mock_pipeline_report(
    risk_score: int = 85, risk_level: RiskLevel = RiskLevel.HIGH
) -> PipelineReport:
    """Crea una estructura Mock de PipelineReport para pruebas deterministas."""
    ai_report = ThreatAnalysisReport(
        risk_score=risk_score,
        risk_level=risk_level,
        impersonated_brand="BancoFalso",
        detected_indicators=[
            "Formulario de login sospechoso",
            "Uso de IP directo",
        ],
        reasoning="Página diseñada para robar credenciales bancarias.",
        recommended_action="Bloquear dominio y notificar al hosting.",
    )

    heuristic_result = HeuristicResult(total_score=risk_score, triggered_rules=[])

    return PipelineReport(
        url="https://phishing-fake-bank.com",
        parsed_dom=None,  # type: ignore
        heuristic_result=heuristic_result,
        ai_report=ai_report,
    )


def test_cli_takedown_success_display():
    """Verifica que el comando 'takedown' ejecute y muestre la salida esperada en pantalla."""
    mock_report = create_mock_pipeline_report(
        risk_score=90, risk_level=RiskLevel.CRITICAL
    )

    with patch(
        "phishshield.cli.main.PhishShieldPipeline.analyze_url_async",
        new_callable=AsyncMock,
    ) as mock_analyze:
        mock_analyze.return_value = mock_report

        result = runner.invoke(
            app,
            [
                "takedown",
                "https://phishing-fake-bank.com",
                "--email",
                "abuse@hosting-provider.com",
            ],
        )

        assert result.exit_code == 0
        assert "SOLICITUD URGENTE DE DESACTIVACIÓN POR PHISHING" in result.stdout
        assert "abuse@hosting-provider.com" in result.stdout
        assert "BancoFalso" in result.stdout
        assert "CRITICAL" in result.stdout


def test_cli_takedown_save_output_file(tmp_path: Path):
    """Verifica que el flag '-o / --output' guarde la carta de takedown en formato Markdown en disco."""
    mock_report = create_mock_pipeline_report(risk_score=75, risk_level=RiskLevel.HIGH)
    output_file = tmp_path / "reports" / "takedown_notice.md"

    with patch(
        "phishshield.cli.main.PhishShieldPipeline.analyze_url_async",
        new_callable=AsyncMock,
    ) as mock_analyze:
        mock_analyze.return_value = mock_report

        result = runner.invoke(
            app,
            [
                "takedown",
                "https://phishing-fake-bank.com",
                "-e",
                "abuse@hosting-provider.com",
                "-o",
                str(output_file),
            ],
        )

        assert result.exit_code == 0
        assert output_file.exists()

        file_content = output_file.read_text(encoding="utf-8")
        assert "# SOLICITUD URGENTE DE DESACTIVACIÓN POR PHISHING" in file_content
        assert "BancoFalso" in file_content
        assert "https://phishing-fake-bank.com" in file_content


def test_cli_takedown_fallback_when_no_brand():
    """Verifica el comportamiento cuando la IA no identifica marca suplantada (None / Valor por defecto)."""
    mock_report = create_mock_pipeline_report(risk_score=20, risk_level=RiskLevel.LOW)
    mock_report.ai_report.impersonated_brand = None

    with patch(
        "phishshield.cli.main.PhishShieldPipeline.analyze_url_async",
        new_callable=AsyncMock,
    ) as mock_analyze:
        mock_analyze.return_value = mock_report

        result = runner.invoke(app, ["takedown", "https://example.com"])

        assert result.exit_code == 0
        assert "Marca no identificada" in result.stdout


def test_cli_takedown_critical_phishing_simulation(tmp_path: Path):
    """Simula una amenaza crítica (Score: 95) con múltiples IOCs y verifica el Markdown generado."""
    ai_report = ThreatAnalysisReport(
        risk_score=95,
        risk_level=RiskLevel.CRITICAL,
        impersonated_brand="BBVA",
        detected_indicators=[
            "Dominio typosquatting registrado hace 2 días (bbva-login-seguro.com)",
            "Formulario de captura de credenciales y SMS token detectado",
            "Certificado SSL gratuito de baja confianza (Let's Encrypt recien emitido)",
            "Uso de iFrames ocultos para redirección de tráfico",
        ],
        reasoning="Página clonada de banca en línea diseñada para el robo masivo de credenciales financieras.",
        recommended_action="Solicitar de inmediato la suspensión del dominio al registrador y bloqueo en DNS resolvers.",
    )

    mock_report = PipelineReport(
        url="https://bbva-login-seguro.com/login",
        parsed_dom=None,  # type: ignore
        heuristic_result=HeuristicResult(total_score=95, triggered_rules=[]),
        ai_report=ai_report,
    )

    output_file = tmp_path / "critical_takedown.md"

    with patch(
        "phishshield.cli.main.PhishShieldPipeline.analyze_url_async",
        new_callable=AsyncMock,
    ) as mock_analyze:
        mock_analyze.return_value = mock_report

        result = runner.invoke(
            app,
            [
                "takedown",
                "https://bbva-login-seguro.com/login",
                "-e",
                "abuse@registrar-sec.com",
                "-o",
                str(output_file),
            ],
        )

        assert result.exit_code == 0
        assert "CRITICAL" in result.stdout

        content = output_file.read_text(encoding="utf-8")
        assert "- **Marca Suplantada:** BBVA" in content
        assert (
            "- **Nivel de Severidad:** CRITICAL (Puntaje de Riesgo: 95/100)" in content
        )
        assert "- Dominio typosquatting registrado hace 2 días" in content
        assert "Página clonada de banca en línea" in content


def test_cli_takedown_format_json_stdout():
    """Verifica que el flag '--format json' imprima una estructura JSON válida en consola."""
    mock_report = create_mock_pipeline_report(
        risk_score=90, risk_level=RiskLevel.CRITICAL
    )

    with patch(
        "phishshield.cli.main.PhishShieldPipeline.analyze_url_async",
        new_callable=AsyncMock,
    ) as mock_analyze:
        mock_analyze.return_value = mock_report

        result = runner.invoke(
            app,
            [
                "takedown",
                "https://phishing-fake-bank.com",
                "--format",
                "json",
            ],
        )

        assert result.exit_code == 0
        assert '"target_url": "https://phishing-fake-bank.com"' in result.stdout
        assert '"severity": "CRITICAL"' in result.stdout
        assert '"impersonated_brand": "BancoFalso"' in result.stdout


def test_cli_takedown_format_json_save_file(tmp_path: Path):
    """Verifica que '-f json -o report.json' guarde la notificación formateada como JSON válido en disco."""
    mock_report = create_mock_pipeline_report(
        risk_score=85, risk_level=RiskLevel.CRITICAL
    )
    output_file = tmp_path / "reports" / "takedown.json"

    with patch(
        "phishshield.cli.main.PhishShieldPipeline.analyze_url_async",
        new_callable=AsyncMock,
    ) as mock_analyze:
        mock_analyze.return_value = mock_report

        result = runner.invoke(
            app,
            [
                "takedown",
                "https://phishing-fake-bank.com",
                "-e",
                "abuse@provider.com",
                "-f",
                "json",
                "-o",
                str(output_file),
            ],
        )

        assert result.exit_code == 0
        assert output_file.exists()

        data = json.loads(output_file.read_text(encoding="utf-8"))
        assert data["target_url"] == "https://phishing-fake-bank.com"
        assert data["abuse_email"] == "abuse@provider.com"
        assert data["severity"] == "CRITICAL"
        assert "notice_body" in data


def test_cli_takedown_format_text_stdout():
    """Verifica que el flag '-f text' genere la notificación en formato plano sin etiquetas Markdown."""
    mock_report = create_mock_pipeline_report(risk_score=80, risk_level=RiskLevel.HIGH)

    with patch(
        "phishshield.cli.main.PhishShieldPipeline.analyze_url_async",
        new_callable=AsyncMock,
    ) as mock_analyze:
        mock_analyze.return_value = mock_report

        result = runner.invoke(
            app,
            [
                "takedown",
                "https://phishing-fake-bank.com",
                "-f",
                "text",
            ],
        )

        assert result.exit_code == 0
        assert "SOLICITUD URGENTE DE DESACTIVACIÓN POR PHISHING" in result.stdout
        assert "https://phishing-fake-bank.com" in result.stdout
        assert "# SOLICITUD" not in result.stdout  # Sin sintaxis Markdown
