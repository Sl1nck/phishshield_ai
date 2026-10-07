from dataclasses import dataclass, field
import logging

from bs4 import BeautifulSoup

logger = logging.getLogger(__name__)


@dataclass
class ParsedDOM:
    title: str = ""
    links: list[str] = field(default_factory=list)
    form_actions: list[str] = field(default_factory=list)
    input_fields: list[dict[str, str]] = field(default_factory=list)
    iframes: list[str] = field(default_factory=list)
    clean_text: str = ""

    @property
    def has_password_field(self) -> bool:
        """Indica si el DOM contiene al menos un campo de entrada de tipo password."""
        return any(
            inp.get("type", "").lower() == "password" for inp in self.input_fields
        )

    @property
    def text_content(self) -> str:
        """Alias de compatibilidad para el texto limpio extraído."""
        return self.clean_text


class DOMParser:
    def __init__(self, html_content: str | None) -> None:
        self.html_content = html_content or ""
        try:
            self.soup = BeautifulSoup(self.html_content, "html.parser")
        except Exception as e:
            logger.warning(f"Error al inicializar BeautifulSoup con html_content: {e}")
            self.soup = BeautifulSoup("", "html.parser")

    def _extract_attr(self, tag, attr_name: str) -> str:
        val = tag.get(attr_name)
        if val is None:
            return ""
        if isinstance(val, list):
            return " ".join(val).strip()
        return str(val).strip()

    def parse(self) -> ParsedDOM:
        try:
            # Extracción segura de título (soporta subtags dentro de <title>)
            title = (
                self.soup.title.get_text(strip=True)
                if self.soup and self.soup.title
                else ""
            )

            # Extracción limpia de enlaces
            links: list[str] = []
            for a in self.soup.find_all("a", href=True):
                href = self._extract_attr(a, "href")
                if href:
                    links.append(href)

            # Extracción limpia de acciones de formulario
            form_actions: list[str] = []
            for form in self.soup.find_all("form"):
                action = self._extract_attr(form, "action")
                if action:
                    form_actions.append(action)

            # Extracción limpia de campos de entrada
            input_fields: list[dict[str, str]] = []
            for inp in self.soup.find_all("input"):
                input_fields.append(
                    {
                        "name": self._extract_attr(inp, "name"),
                        "type": self._extract_attr(inp, "type") or "text",
                        "placeholder": self._extract_attr(inp, "placeholder"),
                    }
                )

            # Extracción de fuentes de iFrames
            iframes: list[str] = []
            for iframe in self.soup.find_all("iframe", src=True):
                src = self._extract_attr(iframe, "src")
                if src:
                    iframes.append(src)

            # Copia para extracción de texto limpio
            soup_copy = BeautifulSoup(str(self.soup), "html.parser")
            for tag in soup_copy(["script", "style", "svg", "noscript"]):
                tag.decompose()

            clean_text = soup_copy.get_text(separator=" ", strip=True)

            return ParsedDOM(
                title=title,
                links=links,
                form_actions=form_actions,
                input_fields=input_fields,
                iframes=iframes,
                clean_text=clean_text,
            )
        except Exception as e:
            logger.error(f"Error inesperado al parsear el DOM HTML: {e}")
            return ParsedDOM(
                title="",
                links=[],
                form_actions=[],
                input_fields=[],
                iframes=[],
                clean_text="",
            )