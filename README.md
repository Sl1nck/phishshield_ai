# PhishShield AI Engine 🛡️🤖

**PhishShield AI Engine** es un motor automatizado e híbrido de análisis de phishing y respuesta a incidentes. Combina un scraper en Playwright con hardening anti-ejecución, un parser HTML defensivo con reglas heurísticas estáticas y la API de **Google Gemini** para análisis multimodal (texto + captura de pantalla PNG).

---

## 🚀 Características Principales

- **Scraping Resiliente:** Captura de artefactos DOM y capturas de pantalla PNG con Playwright, timeouts defensivos y manejo automático de popups.
- **Motor Heurístico Local:** Detección de formularios de autenticación, campos de contraseña, iFrames ocultos y desvío de acciones de formulario a IPs o dominios sospechosos.
- **Inferencia Multimodal con Gemini AI:** Clasificación de riesgos, identificación de marca suplantada e indicadores técnicos con generación de reportes estructurados.
- **Generador de Takedowns:** Creación automática de cartas de desactivación (solicitudes de abuso) en formatos **Markdown**, **JSON** y **Texto Plano**.
- **Interfaz CLI Interactiva:** Comandos amigables construidos con `Typer` y renderizado visual mediante `Rich`.

---

## 📦 Instalación

### Requisitos Previos

- Python 3.11 o superior.
- Git.
- WSL (Ubuntu/Linux) o entorno Linux/macOS recomendado.

### Pasos de Instalación

1. **Clonar el repositorio:**
   ```bash
   git clone [https://github.com/Sl1nck/phishshield_ai.git](https://github.com/Sl1nck/phishshield_ai.git)
   cd phishshield_ai