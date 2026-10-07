from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from phishshield.core.llm.schemas import ThreatAnalysisReport
from phishshield.heuristics.engine import HeuristicResult

console = Console()


def render_heuristic_report(result: HeuristicResult) -> None:
    """Renderiza los hallazgos del motor heurístico en la terminal usando Rich."""
    table = Table(title="🔍 Hallazgos del Motor Heurístico", expand=True)
    table.add_column("ID", style="cyan", no_wrap=True)
    table.add_column("Regla Activada", style="bold white")
    table.add_column("Impacto", justify="center")
    table.add_column("Detalle", style="dim")

    for rule in result.triggered_rules:
        table.add_row(
            rule.rule_id,
            rule.name,
            f"[bold red]+{rule.score_impact}[/]",
            rule.description,
        )

    score_color = (
        "red"
        if result.total_score >= 50
        else "yellow"
        if result.total_score >= 30
        else "green"
    )

    panel_content = (
        table
        if result.triggered_rules
        else "[bold green]✔ No se activaron reglas heurísticas de riesgo.[/]"
    )

    console.print(
        Panel(
            panel_content,
            title=f"[bold]Puntaje Heurístico Total: [{score_color}]{result.total_score}/100[/{score_color}][/bold]",
            border_style=score_color,
        )
    )


def render_ai_report(ai_report: ThreatAnalysisReport | None) -> None:
    """Renderiza el reporte de inteligencia artificial (Gemini) en la terminal."""
    if not ai_report:
        console.print(
            Panel(
                "[green]✔ El sitio no activó alertas suficientes y no requirió evaluación con IA.[/green]",
                title="🤖 Dictamen de Amenaza - PhishShield AI",
                border_style="green",
            )
        )
        return

    risk_score = ai_report.risk_score
    risk_level_str = (
        ai_report.risk_level.value
        if hasattr(ai_report.risk_level, "value")
        else str(ai_report.risk_level)
    )

    risk_style = (
        "bold red"
        if risk_score >= 70
        else ("bold yellow" if risk_score >= 30 else "bold green")
    )

    panel_content = Text()
    panel_content.append("Puntuación de Riesgo: ", style="bold")
    panel_content.append(f"{risk_score}/100 ({risk_level_str})\n", style=risk_style)

    panel_content.append("Marca Suplantada: ", style="bold")
    panel_content.append(
        f"{ai_report.impersonated_brand or 'N/A'}\n\n", style="bold cyan"
    )

    panel_content.append("Indicadores Clave Detectados:\n", style="bold underline")
    if ai_report.detected_indicators:
        for indicator in ai_report.detected_indicators:
            panel_content.append(f"  • {indicator}\n", style="dim white")
    else:
        panel_content.append("  (Ninguno)\n", style="dim white")

    panel_content.append("\nRazonamiento / Análisis:\n", style="bold underline")
    panel_content.append(f"{ai_report.reasoning}\n\n", style="italic")

    panel_content.append("Acción Recomendada:\n", style="bold underline")
    panel_content.append(f"{ai_report.recommended_action}\n", style="bold yellow")

    console.print(
        Panel(
            panel_content,
            title="🤖 Dictamen de Amenaza - PhishShield AI",
            border_style=risk_style,
            padding=(1, 2),
        )
    )