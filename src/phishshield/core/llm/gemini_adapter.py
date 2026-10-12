import json
import os
from typing import Any

from google import genai
from google.genai import types
from google.genai.errors import APIError, ServerError
from pydantic import ValidationError
from rich.console import Console
from tenacity import (
    retry,
    retry_if_exception,
    stop_after_attempt,
    wait_random_exponential,
)

from phishshield.config.settings import settings
from phishshield.core.llm.base import BaseLLMAdapter
from phishshield.core.llm.schemas import ThreatAnalysisReport

console = Console()


def _is_transient_error(exception: BaseException) -> bool:
    """Identifica si el error es de servidor (5xx) o límite de tasa (429) para activar reintentos."""
    if isinstance(exception, ServerError):
        return True
    if isinstance(exception, APIError):
        return getattr(exception, "code", None) in (429, 500, 502, 503, 504)
    return False


class GeminiAdapter(BaseLLMAdapter):
    """Adaptador asíncrono para la API de Google Gemini utilizando el SDK 'google-genai'.
    Incorpora autodetección dinámica de modelos y soporte para perfiles Flash/Pro.
    """

    def __init__(
        self,
        api_key: str | None = None,
        primary_model: str | None = None,
        fallback_model: str | None = None,
        use_pro: bool = False,
    ) -> None:
        self.api_key: str | None = (
            api_key
            or getattr(settings, "GEMINI_API_KEY", None)
            or os.getenv("GEMINI_API_KEY")
        )

        if not self.api_key:
            raise ValueError(
                "No se proporcionó una clave de API válida para Gemini. "
                "Asegúrate de configurar GEMINI_API_KEY en el archivo .env o en las variables de entorno."
            )

        # Inicializar cliente oficial
        self.client = genai.Client(api_key=self.api_key)

        # Resolver modelos dinámicamente o por configuración explícita
        resolved_primary, resolved_fallback = self._resolve_dynamic_models(use_pro=use_pro)

        self.primary_model: str = (
            primary_model
            or getattr(settings, "GEMINI_PRIMARY_MODEL", None)
            or resolved_primary
        )
        self.fallback_model: str | None = (
            fallback_model
            or getattr(settings, "GEMINI_FALLBACK_MODEL", None)
            or resolved_fallback
        )

    def _resolve_dynamic_models(self, use_pro: bool = False) -> tuple[str, str]:
        """Consulta dinámicamente a la API los modelos disponibles según la preferencia (Flash o Pro)."""
        target_keyword = 'pro' if use_pro else 'flash'
        default_primary = 'gemini-3.8-pro' if use_pro else 'gemini-3.8-flash'
        default_fallback = 'gemini-3.5-pro' if use_pro else 'gemini-3.5-flash-lite'

        try:
            models = list(self.client.models.list())
            valid_models = [
                m.name for m in models 
                if hasattr(m, 'supported_generation_methods') 
                and 'generateContent' in m.supported_generation_methods 
                and target_keyword in m.name.lower()
            ]
            if valid_models:
                primary = valid_models[-1]
                remaining = [m for m in valid_models if m != primary]
                fallback = remaining[-1] if remaining else default_fallback
                return primary, fallback
        except Exception:
            # En caso de fallo de red o conectividad inicial, usa los valores seguros de respaldo
            pass

        return default_primary, default_fallback

    @retry(
        retry=retry_if_exception(_is_transient_error),
        wait=wait_random_exponential(min=3, max=15),
        stop=stop_after_attempt(5),
        reraise=True,
    )
    async def _dispatch_call(
        self,
        model: str,
        contents: list[Any],
        config: types.GenerateContentConfig,
    ) -> types.GenerateContentResponse:
        """Ejecuta la llamada asíncrona a la API con reintentos exponenciales automáticos."""
        return await self.client.aio.models.generate_content(
            model=model,
            contents=contents,
            config=config,
        )

    async def analyze_text(
        self,
        prompt: str,
        system_instruction: str | None = None,
        temperature: float = 0.1,
    ) -> str:
        config = types.GenerateContentConfig(
            system_instruction=system_instruction,
            temperature=temperature,
        )
        response = await self._dispatch_call(self.primary_model, [prompt], config)
        response_text = getattr(response, "text", "")
        return str(response_text) if response_text else ""

    async def analyze_multimodal(
        self,
        prompt: str,
        image_bytes: bytes,
        mime_type: str = "image/png",
        system_instruction: str | None = None,
    ) -> str:
        contents: list[Any] = [
            types.Part.from_bytes(data=image_bytes, mime_type=mime_type),
            prompt,
        ]
        config = types.GenerateContentConfig(
            system_instruction=system_instruction,
            temperature=0.1,
        )
        response = await self._dispatch_call(self.primary_model, contents, config)
        response_text = getattr(response, "text", "")
        return str(response_text) if response_text else ""

    async def analyze_structured(
        self,
        prompt: str,
        response_schema: type[Any],
        system_instruction: str | None = None,
        temperature: float = 0.1,
    ) -> Any:
        """Realiza inferencia estructurada inyectando el esquema en el prompt (JSON Mode puro)."""
        schema_json = json.dumps(response_schema.model_json_schema())
        enriched_prompt = (
            f"{prompt}\n\n"
            f"IMPORTANTE: Responde ÚNICAMENTE con un JSON válido que cumpla estrictamente con este esquema:\n"
            f"{schema_json}"
        )

        config = types.GenerateContentConfig(
            system_instruction=system_instruction,
            response_mime_type="application/json",
            temperature=temperature,
        )
        response = await self._dispatch_call(self.primary_model, [enriched_prompt], config)

        if hasattr(response, "parsed") and response.parsed is not None:
            if isinstance(response.parsed, response_schema):
                return response.parsed
            return response_schema.model_validate(response.parsed)

        response_text = getattr(response, "text", None)
        if isinstance(response_text, str) and response_text.strip():
            return response_schema.model_validate_json(response_text)

        raise ValueError("Respuesta nula o inválida al intentar estructurar los datos.")

    async def analyze_phishing_site(
        self,
        parsed_dom: object,
        screenshot_bytes: bytes | None = None,
        url: str = "",
        heuristic_flags: list[dict[str, Any]] | list[str] | None = None,
    ) -> ThreatAnalysisReport:
        """Analiza artefactos, heurísticas activadas y captura de pantalla usando JSON Mode y validación Pydantic."""
        forms = getattr(parsed_dom, "form_actions", getattr(parsed_dom, "forms", []))
        links = getattr(parsed_dom, "links", getattr(parsed_dom, "external_links", []))
        iframes = getattr(parsed_dom, "iframes", [])
        text_content = getattr(
            parsed_dom,
            "clean_text",
            getattr(parsed_dom, "text_content", ""),
        )

        dom_summary = {
            "title": str(getattr(parsed_dom, "title", "") or ""),
            "has_password_field": bool(getattr(parsed_dom, "has_password_field", False)),
            "forms_count": len(forms) if isinstance(forms, (list, tuple)) else 0,
            "external_links_count": len(links) if isinstance(links, (list, tuple)) else 0,
            "iframes_count": len(iframes) if isinstance(iframes, (list, tuple)) else 0,
            "text_snippet": str(text_content or "")[:1500],
        }

        # Convertir de forma segura las alertas a un formato JSON serializable
        serialized_flags = []
        if heuristic_flags:
            for flag in heuristic_flags:
                if hasattr(flag, "model_dump"):
                    serialized_flags.append(flag.model_dump())
                elif hasattr(flag, "dict"):
                    serialized_flags.append(flag.dict())
                elif isinstance(flag, dict):
                    serialized_flags.append(flag)
                else:
                    # Si es un objeto RuleResult o similar, extraemos sus atributos o usamos representación en texto
                    serialized_flags.append(
                        {
                            "id": getattr(flag, "id", "UNKNOWN"),
                            "name": getattr(flag, "name", str(flag)),
                            "impact": getattr(flag, "impact", 0),
                            "description": getattr(flag, "description", ""),
                        }
                    )

        heuristics_str = json.dumps(serialized_flags, indent=2, ensure_ascii=False)

        system_instruction = (
            "Eres PhishShield AI, un analista experto en ciberseguridad especializado en detección de Phishing. "
            "Tu objetivo es evaluar objetivamente si un sitio web es legítimo o una suplantación de identidad (Phishing) "
            "combinando la captura visual, las reglas heurísticas previas y la estructura del DOM técnica."
        )

        schema_json = json.dumps(ThreatAnalysisReport.model_json_schema(), indent=2)

        prompt_text = f"""
--- ARTEFACTOS DETECTADOS ---
- URL Objetivo: 
{url}
- Título de la Página: 
{dom_summary["title"]}
- Formulario con Contraseña: 
{dom_summary["has_password_field"]}
- Cantidad de Formularios: 
{dom_summary["forms_count"]}
- Enlaces Externos: 
{dom_summary["external_links_count"]}
- iFrames Detectados: 
{dom_summary["iframes_count"]}
- Muestra del Texto en Pantalla: 
{dom_summary["text_snippet"]}

--- ALERTAS HEURÍSTICAS DETECTADAS ---
{heuristics_str}

--- INSTRUCCIONES ---
Examina la apariencia visual en la captura adjunta (si está disponible) y la estructura técnica para determinar
si se trata de un sitio legítimo o un intento de suplantación de identidad (Phishing).

IMPORTANTE: Responde ÚNICAMENTE en formato JSON válido que cumpla strictly con el siguiente esquema JSON:
{schema_json}
"""
        contents: list[Any] = [prompt_text]

        if screenshot_bytes:
            contents.insert(
                0,
                types.Part.from_bytes(data=screenshot_bytes, mime_type="image/png"),
            )

        config = types.GenerateContentConfig(
            system_instruction=system_instruction,
            response_mime_type="application/json",
            temperature=0.1,
        )

        models_to_try: list[str] = [self.primary_model]
        if self.fallback_model and self.fallback_model != self.primary_model:
            models_to_try.append(self.fallback_model)

        last_error: Exception | None = None

        for current_model in models_to_try:
            try:
                response = await self._dispatch_call(current_model, contents, config)

                if hasattr(response, "parsed") and response.parsed is not None:
                    if isinstance(response.parsed, ThreatAnalysisReport):
                        return response.parsed
                    return ThreatAnalysisReport.model_validate(response.parsed)

                response_text = getattr(response, "text", None)
                if isinstance(response_text, str) and response_text.strip():
                    return ThreatAnalysisReport.model_validate_json(response_text)

                raise ValueError("Respuesta vacía o sin contenido devuelta por el modelo.")

            except (ServerError, APIError) as e:
                last_error = e
                error_msg = getattr(e, "message", str(e))
                if current_model != models_to_try[-1]:
                    console.print(
                        f"[bold yellow][!] El modelo {current_model} falló. Motivo: {error_msg}[/]"
                    )
                    console.print(
                        f"[bold yellow]Intentando modelo de respaldo {self.fallback_model}...[/]"
                    )
                    continue
                console.print("[bold red][✘] La API de Gemini agotó todos los modelos disponibles.[/]")
                raise e
            except (ValidationError, ValueError) as e:
                console.print(f"[bold red][✘] Error al estructurar la respuesta del modelo {current_model}:[/] {e}")
                raise e

        if last_error:
            raise last_error
        raise RuntimeError("No se pudo completar el análisis con Gemini.")