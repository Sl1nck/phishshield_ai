from phishshield.config.settings import settings
from phishshield.core.llm.base import BaseLLMAdapter
from phishshield.core.llm.gemini_adapter import GeminiAdapter


class LLMFactory:
    """Fábrica centralizada para instanciar adaptadores de LLM."""

    @staticmethod
    def create_adapter(provider: str = "gemini") -> BaseLLMAdapter:
        provider_lower = provider.lower()
        if provider_lower == "gemini":
            api_key: str | None = getattr(settings, "GEMINI_API_KEY", None)
            primary_model: str | None = getattr(
                settings, "DEFAULT_LLM_MODEL", getattr(settings, "GEMINI_PRIMARY_MODEL", None)
            )
            return GeminiAdapter(
                api_key=api_key,
                primary_model=primary_model,
            )
        raise ValueError(f"Proveedor de IA '{provider}' no soportado actualmente.")