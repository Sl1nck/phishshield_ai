from abc import ABC, abstractmethod

from pydantic import BaseModel


class BaseLLMAdapter(ABC):
    """Interfaz abstracta (Patrón Estrategia) para adaptadores de proveedores LLM."""

    @abstractmethod
    async def analyze_text(
        self,
        prompt: str,
        system_instruction: str | None = None,
        temperature: float = 0.1,
    ) -> str:
        """Procesa un prompt de texto y retorna la respuesta en texto plano."""
        pass

    @abstractmethod
    async def analyze_structured(
        self,
        prompt: str,
        response_schema: type[BaseModel],
        system_instruction: str | None = None,
        temperature: float = 0.1,
    ) -> BaseModel:
        """Procesa un prompt y valida la salida JSON contra un modelo Pydantic."""
        pass

    @abstractmethod
    async def analyze_multimodal(
        self,
        prompt: str,
        image_bytes: bytes,
        mime_type: str = "image/png",
        system_instruction: str | None = None,
    ) -> str:
        """Procesa entrada combinada de texto e imagen (capturas de pantalla)."""
        pass
