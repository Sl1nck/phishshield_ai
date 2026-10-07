from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class RuleSeverity(StrEnum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class RuleResult(BaseModel):
    """Resultado individual de la evaluación de una regla heurística."""

    rule_id: str = Field(
        ..., description="Identificador único de la regla (ej. RULE-URL-001)"
    )
    name: str = Field(..., description="Nombre descriptivo de la regla")
    triggered: bool = Field(..., description="Indica si la regla fue activada")
    severity: RuleSeverity = Field(
        default=RuleSeverity.INFO, description="Severidad del hallazgo"
    )
    score_impact: int = Field(
        default=0, ge=0, le=100, description="Puntos de riesgo aportados"
    )
    description: str = Field(
        ..., description="Explicación detallada del motivo de activación"
    )
    details: dict[str, Any] | None = Field(
        default=None, description="Metadatos o evidencia técnica"
    )


class HeuristicAnalysisResult(BaseModel):
    """Resultado global acumulado del motor de reglas heurísticas."""

    total_heuristic_score: int = Field(
        default=0, ge=0, le=100, description="Puntuación acumulada (0-100)"
    )
    highest_severity: RuleSeverity = Field(
        default=RuleSeverity.INFO, description="Severidad máxima detectada"
    )
    triggered_rules: list[RuleResult] = Field(
        default_factory=list, description="Lista de reglas activadas"
    )
    executed_rules_count: int = Field(
        default=0, description="Total de reglas evaluadas"
    )
    should_escalate_to_ai: bool = Field(
        default=True, description="Indica si se requiere análisis multimodal"
    )
