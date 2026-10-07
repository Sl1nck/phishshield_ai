#!/usr/bin/env bash

set -e

GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${CYAN}"
echo "============================================================"
echo "    🛡️  PhishShield AI Engine v2.0 - Installer Script      "
echo "    Author: @Sl1nck                                         "
echo "============================================================"
echo -e "${NC}"

# 1. Verificación de Python 3
if ! command -v python3 &> /dev/null; then
    echo -e "${RED}[✘] Python 3 no está instalado. Por favor instálalo antes de continuar.${NC}"
    exit 1
fi

echo -e "${GREEN}[+] Python 3 detectado: $(python3 --version)${NC}"

# 2. Creación del entorno virtual
if [ ! -d ".venv" ]; then
    echo -e "${YELLOW}[*] Creando entorno virtual .venv...${NC}"
    python3 -m venv .venv
else
    echo -e "${GREEN}[+] Entorno virtual .venv ya existe.${NC}"
fi

# 3. Activación e instalación de dependencias
echo -e "${YELLOW}[*] Activando entorno e instalando paquetes...${NC}"
source .venv/bin/activate

pip install --upgrade pip
pip install -e .

# 4. Instalación de binarios de Playwright
echo -e "${YELLOW}[*] Instalando navegadores de Playwright (Chromium)...${NC}"
playwright install chromium
playwright install-deps chromium 2>/dev/null || true

# 5. Configuración de variables de entorno (.env)
if [ ! -f ".env" ]; then
    if [ -f ".env.example" ]; then
        echo -e "${YELLOW}[*] Creando .env a partir de .env.example...${NC}"
        cp .env.example .env
    else
        echo -e "${YELLOW}[*] Creando archivo .env base...${NC}"
        echo "GEMINI_API_KEY=tu_api_key_aqui" > .env
    fi
    echo -e "${RED}[!] IMPORTANTE: Recuerda configurar tu GEMINI_API_KEY dentro del archivo .env${NC}"
else
    echo -e "${GREEN}[+] Archivo .env detectado.${NC}"
fi

echo -e "\n${GREEN}============================================================${NC}"
echo -e "${GREEN}  ¡Instalación de PhishShield AI completada con éxito!  ${NC}"
echo -e "${GREEN}============================================================${NC}"
echo -e "\nPara comenzar a usar la herramienta, ejecuta:"
echo -e "  ${CYAN}source .venv/bin/activate${NC}"
echo -e "  ${CYAN}phishshield${NC}\n"
