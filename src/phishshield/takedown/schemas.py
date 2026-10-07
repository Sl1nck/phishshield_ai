from enum import StrEnum

from pydantic import BaseModel, Field


class NoticeSeverity(StrEnum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class TakedownNotice(BaseModel):
    """Estructura de la notificación formal de Takedown."""

    target_url: str
    impersonated_brand: str | None = Field(
        default="Marca no identificada",
        description="Marca suplantada identificada o valor por defecto si no se detectó.",
    )
    risk_score: int = Field(default=0, ge=0, le=100)
    severity: NoticeSeverity = NoticeSeverity.LOW
    evidence_indicators: list[str] = Field(default_factory=list)
    technical_reasoning: str = Field(
        default="Se detectaron patrones sospechosos compatibles con recolección ilegítima de datos."
    )
    abuse_email: str = "abuse@registrar-or-hosting.com"
    notice_body: str = Field(
        ...,
        description="Cuerpo redactado de la carta de takedown en formato Markdown/Texto.",
    )
