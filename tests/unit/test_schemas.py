import pytest
from pydantic import ValidationError

from phishshield.core.llm.schemas import RiskLevel, ThreatAnalysisReport


def test_threat_analysis_report_valid_schema():
    report_data = {
        "risk_score": 95,
        "risk_level": "CRITICAL",
        "impersonated_brand": "Microsoft 365",
        "detected_indicators": [
            "Formulario de login externo sin HTTPS",
            "Suplantación de logotipo oficial",
        ],
        "reasoning": "La página simula ser el portal de login de Office 365 pero envía credenciales a un dominio de terceros.",
        "recommended_action": "Bloquear URL inmediatamente en la red corporal.",
    }

    report = ThreatAnalysisReport(**report_data)

    assert report.risk_score == 95
    assert report.risk_level == RiskLevel.CRITICAL
    assert report.impersonated_brand == "Microsoft 365"
    assert len(report.detected_indicators) == 2


def test_threat_analysis_report_score_out_of_bounds():
    invalid_data = {
        "risk_score": 150,  # Excede el límite de 100
        "risk_level": "CRITICAL",
        "reasoning": "Test invalido",
        "recommended_action": "Ninguna",
    }

    with pytest.raises(ValidationError):
        ThreatAnalysisReport(**invalid_data)
