import asyncio
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated

import typer
from google.genai.errors import APIError, ServerError
from rich.console import Console
from rich.table import Table

from phishshield.cli.ui import render_ai_report, render_heuristic_report
from phishshield.core.llm.factory import LLMFactory
from phishshield.core.llm.gemini_adapter import GeminiAdapter
from phishshield.core.llm.schemas import RiskLevel, ThreatAnalysisReport
from phishshield.heuristics.engine import HeuristicEngine
from phishshield.pipeline import PhishShieldPipeline, PipelineReport
from phishshield.scraper.browser import PlaywrightScraper
from phishshield.scraper.parser import DOMParser
from phishshield.takedown.generator import TakedownGenerator

app = typer.Typer(
    help="PhishShield AI Engine - Herramienta CLI de análisis de phishing",
    add_completion=False,
    context_settings={"help_option_names": ["-h", "--help"]},
)
console = Console()

BANNER = r"""
██████╗ ██╗  ██╗██╗███████╗██╗  ██╗███████╗██╗  ██╗██╗███████╗██╗██████╗ 
██╔══██╗██║  ██║██║██╔════╝██║  ██║██╔════╝██║  ██║██║██╔════╝██║██╔══██╗
██████╔╝███████║██║███████╗███████║███████╗███████║██║█████╗  ██║██║  ██║
██╔═══╝ ██╔══██║██║╚════██║██╔══██║╚════██║██╔══██║██║██╔══╝  ██║██║  ██║
██║     ██║  ██║██║███████╗██║  ██║███████║██║  ██║██║███████╗██║██████╔╝
╚═╝     ╚═╝  ╚═╝╚═╝╚══════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═╝╚══════╝╚═╝╚═════╝ 
"""


def get_risk_color(risk_level: RiskLevel) -> str:
    """Retorna el color Rich según la severidad del riesgo."""
    mapping = {
        RiskLevel.LOW: "green",
        RiskLevel.MEDIUM: "yellow",
        RiskLevel.HIGH: "red",
        RiskLevel.CRITICAL: "bold white on red",
    }
    return mapping.get(risk_level, "white")


def save_json_report(
    output_path: Path,
    artifacts: object,
    parsed_dom: object,
    report: ThreatAnalysisReport,
):
    """Genera y guarda una estructura JSON completa con metadatos del escaneo y el reporte de la IA."""
    payload = {
        "metadata": {
            "scan_timestamp": datetime.now(UTC).isoformat(),
            "requested_url": getattr(artifacts, "url", ""),
            "final_url": getattr(artifacts, "final_url", getattr(artifacts, "url", "")),
            "http_status_code": getattr(artifacts, "status_code", 200),
            "screenshot_size_bytes": len(getattr(artifacts, "screenshot_bytes", b"")),
        },
        "dom_artifacts": {
            "title": getattr(parsed_dom, "title", ""),
            "has_password_field": getattr(parsed_dom, "has_password_field", False),
            "forms_count": len(
                getattr(
                    parsed_dom,
                    "forms",
                    getattr(parsed_dom, "form_actions", []),
                )
            ),
            "external_links_count": len(
                getattr(
                    parsed_dom,
                    "external_links",
                    getattr(parsed_dom, "links", []),
                )
            ),
            "iframes_count": len(getattr(parsed_dom, "iframes", [])),
        },
        "threat_analysis": report.model_dump(mode="json"),
    }

    try:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2, ensure_ascii=False)

        console.print(
            f"[bold green][+] Reporte JSON guardado exitosamente en:[/] {output_path.resolve()}"
        )
    except Exception as e:
        console.print(
            f"[bold red][✘] Error al escribir el archivo JSON ({output_path}):[/] {e}"
        )


def save_screenshot_image(screenshot_path: Path, screenshot_bytes: bytes):
    """Guarda los bytes de la captura de pantalla en la ruta PNG especificada."""
    try:
        screenshot_path.parent.mkdir(parents=True, exist_ok=True)
        with open(screenshot_path, "wb") as f:
            f.write(screenshot_bytes)
        console.print(
            f"[bold green][+] Captura de pantalla PNG guardada en:[/] {screenshot_path.resolve()}"
        )
    except Exception as e:
        console.print(
            f"[bold red][✘] Error al guardar la captura de pantalla ({screenshot_path}):[/] {e}"
        )


async def check_llm_status() -> bool:
    """Verifica la conectividad y el estado del servicio LLM enviando una solicitud de prueba."""
    try:
        adapter = LLMFactory.create_adapter()
        await adapter.analyze_text("PING")
        return True
    except Exception as e:
        console.print(f"[bold red][✘] Error al comprobar estado del LLM:[/] {e}")
        return False


async def run_pipeline(
    url: str,
    output_path: Path | None = None,
    screenshot_path: Path | None = None,
    use_pro: bool = False,
):
    console.print(f"\n[bold blue][*] Iniciando captura y análisis DOM para:[/] {url}")

    # 1. Captura con Playwright
    scraper = PlaywrightScraper()
    artifacts = await scraper.scrape_url(url)

    # 2. Parsing DOM con BeautifulSoup
    parser = DOMParser(artifacts.html_content)
    parsed_dom = parser.parse()

    if screenshot_path:
        save_screenshot_image(screenshot_path, artifacts.screenshot_bytes)

    # 3. Mostrar Artefactos DOM en Consola
    table = Table(
        title="Artefactos Extraídos",
        show_header=True,
        header_style="bold magenta",
    )
    table.add_column("Indicador / Propiedad", style="cyan")
    table.add_column("Valor Detectado", style="green")

    table.add_row("URL Solicitada", artifacts.url)
    table.add_row("URL Final (Redirección)", artifacts.final_url)
    table.add_row("Código de Estado HTTP", str(artifacts.status_code))
    table.add_row("Tamaño HTML DOM", f"{len(artifacts.html_content)} bytes")
    table.add_row(
        "Captura de Pantalla",
        f"{len(artifacts.screenshot_bytes)} bytes (PNG)",
    )
    table.add_row("Título de la Página", getattr(parsed_dom, "title", ""))
    table.add_row(
        "Formularios Encontrados",
        str(
            len(
                getattr(
                    parsed_dom,
                    "forms",
                    getattr(parsed_dom, "form_actions", []),
                )
            )
        ),
    )
    table.add_row(
        "Campo de Contraseña",
        "Sí" if getattr(parsed_dom, "has_password_field", False) else "No",
    )
    table.add_row(
        "Enlaces Externos",
        str(
            len(
                getattr(
                    parsed_dom,
                    "external_links",
                    getattr(parsed_dom, "links", []),
                )
            )
        ),
    )
    table.add_row("iFrames Sospechosos", str(len(getattr(parsed_dom, "iframes", []))))

    console.print(table)
    console.print("[+] Captura y parsing DOM finalizados exitosamente.\n")

    # 4. Análisis con Motor Heurístico Estático
    engine = HeuristicEngine()
    heuristic_result = engine.analyze(parsed_dom, artifacts.final_url)
    render_heuristic_report(heuristic_result)

    # 5. Inferencia Multimodal con Gemini API
    console.print(
        "\n[bold yellow][*] Enviando artefactos y captura PNG a Gemini AI...[/]"
    )
    adapter = GeminiAdapter(use_pro=use_pro)

    try:
        report: ThreatAnalysisReport = await adapter.analyze_phishing_site(
            parsed_dom=parsed_dom,
            screenshot_bytes=artifacts.screenshot_bytes,
            url=artifacts.final_url,
        )
    except ServerError:
        console.print(
            "\n[bold red][✘] Error de Infraestructura (503):[/] La API de Gemini experimenta congestión prolongada."
        )
        console.print("[yellow][!] Por favor reintenta en un par de minutos.[/]\n")
        return
    except APIError as e:
        console.print(
            f"\n[bold red][✘] Error en la API de Gemini ({e.code}):[/] {e.message}\n"
        )
        return
    except Exception as e:
        console.print(
            f"\n[bold red][✘] Error no controlado durante el análisis AI:[/] {e}\n"
        )
        return

    # 6. Renderizado del Reporte de Amenaza
    render_ai_report(report)

    # 7. Exportación a archivo JSON si se proporcionó --output
    if output_path:
        save_json_report(
            output_path=output_path,
            artifacts=artifacts,
            parsed_dom=parsed_dom,
            report=report,
        )


@app.callback(invoke_without_command=True)
def main_callback(
    ctx: typer.Context,
    url: Annotated[
        str | None,
        typer.Option("-u", "--scan-url", help="URL objetivo a analizar directamente"),
    ] = None,
    pro: Annotated[
        bool,
        typer.Option("--pro", help="Usar modelo Pro avanzado de Gemini"),
    ] = False,
    output: Annotated[
        Path | None,
        typer.Option(
            "-o",
            "--output",
            help="Ruta de exportación JSON (ej. -o ./reports/scan.json)",
        ),
    ] = None,
    save_screenshot: Annotated[
        Path | None,
        typer.Option(
            "-s",
            "--save-screenshot",
            help="Ruta para guardar captura PNG (ej. -s ./reports/screenshot.png)",
        ),
    ] = None,
):
    """Callback global para soportar ejecuciones directas con flags (-u / --scan-url) o bienvenido inicial."""
    if ctx.invoked_subcommand is None:
        if url:
            asyncio.run(
                run_pipeline(
                    url=url,
                    output_path=output,
                    screenshot_path=save_screenshot,
                    use_pro=pro,
                )
            )
        else:
            # Renderizado limpio del Banner + Autor + Comandos Básicos
            console.print(f"[bold cyan]{BANNER}[/bold cyan]")
            console.print(
                "  [bold white]🛡️ PhishShield AI Engine v2.0[/bold white] | [dim]Author: [bold green]@Sl1nck[/bold green][/dim]\n"
            )
            console.print("  [bold yellow]Comandos disponibles:[/bold yellow]")
            console.print(
                "   [bold cyan]• analyze[/bold cyan]   Análisis híbrido de URLs (Heurística + Gemini AI)"
            )
            console.print(
                "   [bold cyan]• takedown[/bold cyan]  Generación automática de reportes de abuso"
            )
            console.print(
                "   [bold cyan]• scan-url[/bold cyan]  Escaneo directo de artefactos DOM y capturas PNG\n"
            )
            console.print(
                "  [dim]Ejecuta [bold white]phishshield -h[/bold white] o [bold white]phishshield --help[/bold white] para ver las opciones detalladas.[/dim]\n"
            )


@app.command()
def scan_url(
    url: Annotated[
        str, typer.Option("--scan-url", "-u", help="URL objetivo a analizar")
    ],
    pro: Annotated[
        bool,
        typer.Option("--pro", help="Usar modelo Pro avanzado de Gemini"),
    ] = False,
    output: Annotated[
        Path | None,
        typer.Option(
            "--output",
            "-o",
            help="Ruta de exportación JSON (ej. -o ./reports/scan.json)",
        ),
    ] = None,
    save_screenshot: Annotated[
        Path | None,
        typer.Option(
            "--save-screenshot",
            "-s",
            help="Ruta para guardar captura PNG (ej. -s ./reports/screenshot.png)",
        ),
    ] = None,
):
    """Escanea una URL combinando Playwright, BeautifulSoup, reglas heurísticas y Gemini AI."""
    asyncio.run(
        run_pipeline(
            url=url,
            output_path=output,
            screenshot_path=save_screenshot,
            use_pro=pro,
        )
    )


@app.command()
def analyze(
    url: Annotated[str, typer.Argument(help="URL objetivo a analizar")],
    force_ai: Annotated[
        bool,
        typer.Option(
            "--force-ai",
            "-f",
            help="Forzar el análisis con Gemini AI aunque no se activen alertas heurísticas",
        ),
    ] = False,
    pro: Annotated[
        bool,
        typer.Option(
            "--pro",
            help="Utiliza el modelo Pro de Google Gemini (requiere API Key con plan de pago en Google AI Studio)",
        ),
    ] = False,
    output: Annotated[
        Path | None,
        typer.Option("--output", "-o", help="Ruta de exportación del reporte JSON"),
    ] = None,
):
    """Analiza una URL utilizando el pipeline híbrido (Heurísticas + Inferencia IA)."""
    pipeline = PhishShieldPipeline(use_pro=pro)
    report: PipelineReport = asyncio.run(
        pipeline.analyze_url_async(url, force_ai=force_ai)
    )

    console.print("\n[bold blue]=== PhishShield AI Report ===[/bold blue]")
    console.print(f"[bold]URL Analizada:[/bold] {report.url}\n")

    if getattr(report, "heuristic_result", None):
        render_heuristic_report(report.heuristic_result)

    render_ai_report(getattr(report, "ai_report", None))

    if output and getattr(report, "ai_report", None):
        save_json_report(
            output_path=output,
            artifacts=getattr(report, "parsed_dom", None),
            parsed_dom=getattr(report, "parsed_dom", None),
            report=report.ai_report,
        )


@app.command()
def takedown(
    url: Annotated[str, typer.Argument(help="URL del sitio de phishing a notificar.")],
    abuse_email: Annotated[
        str,
        typer.Option(
            "--email",
            "-e",
            help="Correo de contacto del equipo de Abuse.",
        ),
    ] = "abuse@registrar-or-hosting.com",
    pro: Annotated[
        bool,
        typer.Option("--pro", help="Usar modelo Pro avanzado de Gemini"),
    ] = False,
    output_file: Annotated[
        Path | None,
        typer.Option(
            "--output",
            "-o",
            help="Ruta de archivo para guardar la carta de takedown.",
        ),
    ] = None,
    format: Annotated[
        str,
        typer.Option(
            "--format",
            "-f",
            help="Formato de salida de la notificación (markdown, json, text).",
        ),
    ] = "markdown",
):
    """Genera una carta formal de Takedown para solicitar la baja del sitio malicioso."""
    console.print(
        f"\n[bold yellow][*] Analizando {url} para generar notificación de takedown...[/bold yellow]\n"
    )

    pipeline = PhishShieldPipeline(use_pro=pro)
    report: PipelineReport = asyncio.run(pipeline.analyze_url_async(url))

    generator = TakedownGenerator()
    notice = generator.generate_notice(report, abuse_email=abuse_email)

    fmt = format.lower().strip()
    if fmt == "json":
        content = generator.to_json(notice)
    elif fmt in ("text", "txt", "plain"):
        content = generator.to_text(notice)
    else:
        content = notice.notice_body

    console.print(
        f"[bold green][+] Notificación generada con éxito (Severidad: {notice.severity.value})[/bold green]\n"
    )
    console.print(content)

    if output_file:
        try:
            output_file.parent.mkdir(parents=True, exist_ok=True)
            output_file.write_text(content, encoding="utf-8")
            console.print(
                f"\n[bold blue][+] Carta guardada exitosamente en:[/] {output_file.resolve()}"
            )
        except Exception as e:
            console.print(
                f"\n[bold red][✘] Error al guardar el archivo de takedown ({output_file}):[/] {e}"
            )


def main():
    """Punto de entrada invocado por el script de consola 'phishshield'."""
    app()


if __name__ == "__main__":
    main()