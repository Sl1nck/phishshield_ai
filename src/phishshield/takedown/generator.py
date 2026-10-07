from phishshield.pipeline import PipelineReport
from phishshield.takedown.schemas import NoticeSeverity, TakedownNotice


class TakedownGenerator:
    """Generador de notificaciones formales de desactivación de sitios de phishing."""

    @staticmethod
    def _map_risk_to_severity(score: int) -> NoticeSeverity:
        if score >= 80:
            return NoticeSeverity.CRITICAL
        elif score >= 60:
            return NoticeSeverity.HIGH
        elif score >= 30:
            return NoticeSeverity.MEDIUM
        return NoticeSeverity.LOW

    def to_json(self, notice: TakedownNotice) -> str:
        """Devuelve la notificación formateada como un string JSON estructurado."""
        return notice.model_dump_json(indent=2)

    def to_text(self, notice: TakedownNotice) -> str:
        """Devuelve la notificación en formato texto plano sin formato Markdown."""
        indicators_str = (
            "\n".join([f" - {ind}" for ind in notice.evidence_indicators])
            or " - Patrones sospechosos generales"
        )
        return (
            f"SOLICITUD URGENTE DE DESACTIVACIÓN POR PHISHING (TAKEDOWN NOTICE)\n"
            f"===============================================================\n\n"
            f"Para: {notice.abuse_email}\n"
            f"Asunto: [URGENTE] Notificación de actividad maliciosa / Phishing - {notice.target_url}\n\n"
            f"Marca Suplantada: {notice.impersonated_brand}\n"
            f"Severidad: {notice.severity.value} (Riesgo: {notice.risk_score}/100)\n\n"
            f"EVIDENCIA TÉCNICA:\n{indicators_str}\n\n"
            f"ARGUMENTACIÓN TÉCNICA:\n{notice.technical_reasoning}\n\n"
            f"Atentamente,\nPhishShield AI Engine - Automated Incident Response"
        )

    def generate_notice(
        self, report: PipelineReport, abuse_email: str = "abuse@registrar.com"
    ) -> TakedownNotice:
        """Genera una notificación formal de Takedown basada en el reporte del pipeline."""
        risk_score = (
            report.ai_report.risk_score
            if (report.ai_report and report.ai_report.risk_score is not None)
            else getattr(report.heuristic_result, "total_score", 0)
        )

        # Evaluación segura de la marca para prevenir asignaciones de tipo NoneType
        brand = (
            report.ai_report.impersonated_brand
            if (report.ai_report and report.ai_report.impersonated_brand)
            else "Marca no identificada / Genérica"
        )

        # Extracción segura de indicadores con fallback defensivo
        if report.ai_report and report.ai_report.detected_indicators:
            indicators = report.ai_report.detected_indicators
        else:
            raw_findings = getattr(
                report.heuristic_result,
                "findings",
                getattr(
                    report.heuristic_result,
                    "matched_rules",
                    getattr(report.heuristic_result, "triggered_rules", []),
                ),
            )
            indicators = [
                getattr(f, "rule_name", getattr(f, "name", str(f)))
                for f in raw_findings
            ]

        # Evaluación segura del razonamiento para evitar valores nulos
        reasoning = (
            report.ai_report.reasoning
            if (report.ai_report and report.ai_report.reasoning)
            else "Se detectaron patrones heurísticos sospechosos compatibles con recolección ilegítima de datos."
        )

        severity = self._map_risk_to_severity(risk_score)
        formatted_indicators = (
            "\n".join([f"- {ind}" for ind in indicators])
            or "- Patrones sospechosos generales"
        )

        notice_body = f"""
# SOLICITUD URGENTE DE DESACTIVACIÓN POR PHISHING (TAKEDOWN NOTICE)

**Para:** {abuse_email}
**Asunto:** [URGENTE] Notificación de actividad maliciosa / Phishing - {report.url}

Estimado equipo de Seguridad / Abuse,

Por medio de la presente, solicitamos la desactivación inmediata de la URL maliciosa identificada en su infraestructura:

- **URL Maliciosa:** {report.url}
- **Marca Suplantada:** {brand}
- **Nivel de Severidad:** {severity.value} (Puntaje de Riesgo: {risk_score}/100)

## Evidencia Técnica Detectada
{formatted_indicators}

## Argumentación Técnica
{reasoning}

Agradecemos su pronta intervención para mitigar el impacto sobre los usuarios afectados.

Atentamente,
**PhishShield AI Engine - Automated Incident Response**
"""

        return TakedownNotice(
            target_url=report.url,
            impersonated_brand=brand,
            risk_score=risk_score,
            severity=severity,
            evidence_indicators=indicators,
            technical_reasoning=reasoning,
            abuse_email=abuse_email,
            notice_body=notice_body.strip(),
        )
