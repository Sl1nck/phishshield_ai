from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field


class RiskLevel(StrEnum):
    """Nivel de severidad asignado por el motor de análisis."""

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class ThreatAnalysisReport(BaseModel):
    """Dictamen estructurado generado por Gemini para análisis de phishing."""

    model_config = ConfigDict(
        use_enum_values=True,
        str_strip_whitespace=True,
        extra="ignore",
    )

    risk_score: int = Field(
        ge=0,
        le=100,
        description="Puntuación de riesgo global de 0 (Seguro) a 100 (Phishing Confirmado)",
    )
    risk_level: RiskLevel = Field(
        description="Categoría de riesgo asignada según los vectores encontrados"
    )
    impersonated_brand: str | None = Field(
        default=None,
        description="Nombre de la entidad o marca objetivo que intenta suplantar (ej: PayPal, Google)",
    )
    detected_indicators: list[str] = Field(
        default_factory=list,
        description="Lista de IOCs/anomalías clave detectadas en el DOM o la imagen",
    )
    reasoning: str = Field(
        description="Explicación detallada del razonamiento que justifica la puntuación"
    )
    recommended_action: str = Field(
        description="Recomendación defensiva inmediata (ej: Bloquear en Firewall, Notificar SOC)",
    )
