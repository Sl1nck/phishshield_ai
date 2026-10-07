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

# 1. Verificación e Instalación de Dependencias del Sistema (Debian/Ubuntu/Kali)
if command -v apt-get &> /dev/null; then
    echo -e "${YELLOW}[*] Comprobando paquetes del sistema (python3-venv, pip, librerías)...${NC}"
    
    # Comprobar si venv o pip no están disponibles
    if ! python3 -m venv --help &> /dev/null || ! command -v pip3 &> /dev/null; then
        echo -e "${YELLOW}[*] Instalando paquetes del sistema faltantes mediante apt (requiere contraseña sudo)...${NC}"
        sudo apt update
        sudo apt install -y python3-venv python3-pip python3-dev build-essential curl git
    else
        echo -e "${GREEN}[+] Paquetes del sistema base detectados correctamente.${NC}"
    fi
fi

# 2. Verificación de Python 3
if ! command -v python3 &> /dev/null; then
    echo -e "${RED}[✘] Python 3 no está instalado. Por favor instálalo antes de continuar.${NC}"
    exit 1
fi

echo -e "${GREEN}[+] Python 3 detectado: $(python3 --version)${NC}"

# 3. Creación / Limpieza del entorno virtual
if [ -d ".venv" ] && [ ! -f ".venv/bin/activate" ]; then
    echo -e "${YELLOW}[!] Entorno .venv corrupto o incompleto detectado. Eliminando...${NC}"
    rm -rf .venv
fi

if [ ! -d ".venv" ]; then
    echo -e "${YELLOW}[*] Creando entorno virtual .venv...${NC}"
    python3 -m venv .venv
else
    echo -e "${GREEN}[+] Entorno virtual .venv listo.${NC}"
fi

# 4. Activación e instalación de dependencias Python
echo -e "${YELLOW}[*] Activando entorno e instalando paquetes de PhishShield...${NC}"
source .venv/bin/activate

pip install --upgrade pip
pip install -e .

# 5. Instalación de navegadores de Playwright y sus dependencias del sistema
echo -e "${YELLOW}[*] Instalando navegadores de Playwright (Chromium)...${NC}"
playwright install chromium

if command -v apt-get &> /dev/null; then
    echo -e "${YELLOW}[*] Instalando dependencias de sistema para Chromium...${NC}"
    sudo playwright install-deps chromium 2>/dev/null || playwright install-deps chromium 2>/dev/null || true
fi

# 6. Configuración de variables de entorno (.env)
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