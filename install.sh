#!/usr/bin/env bash

set -e

GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${CYAN}"
echo "============================================================"
echo "    🛡️  PhishShield AI Engine v2.0 - Universal Installer   "
echo "    Author: @Sl1nck                                         "
echo "============================================================"
echo -e "${NC}"

# 1. Detección del Gestor de Paquetes e Instalación de Dependencias del Sistema
if command -v apt-get &> /dev/null; then
    echo -e "${YELLOW}[*] Sistema basado en Debian/Ubuntu/Kali detectado (apt).${NC}"
    if ! python3 -c "import ensurepip" &> /dev/null || ! command -v pip3 &> /dev/null; then
        echo -e "${YELLOW}[*] Instalando paquetes faltantes (python3-venv, pip, dependencias)...${NC}"
        sudo apt update
        sudo apt install -y python3-venv python3-pip python3-dev build-essential curl git
    else
        echo -e "${GREEN}[+] Paquetes del sistema base verificados correctamente.${NC}"
    fi
elif command -v pacman &> /dev/null; then
    echo -e "${YELLOW}[*] Sistema basado en Arch Linux detectado (pacman).${NC}"
    if ! python3 -c "import ensurepip" &> /dev/null || ! command -v pip3 &> /dev/null; then
        echo -e "${YELLOW}[*] Instalando paquetes faltantes mediante pacman...${NC}"
        sudo pacman -Sy --needed --noconfirm python python-pip git base-devel curl
    else
        echo -e "${GREEN}[+] Paquetes del sistema base verificados correctamente.${NC}"
    fi
elif command -v dnf &> /dev/null; then
    echo -e "${YELLOW}[*] Sistema basado en Fedora/RHEL detectado (dnf).${NC}"
    if ! python3 -c "import ensurepip" &> /dev/null || ! command -v pip3 &> /dev/null; then
        echo -e "${YELLOW}[*] Instalando paquetes faltantes mediante dnf...${NC}"
        sudo dnf install -y python3-devel python3-pip git gcc curl
    else
        echo -e "${GREEN}[+] Paquetes del sistema base verificados correctamente.${NC}"
    fi
fi

# 2. Verificación de Python 3
if ! command -v python3 &> /dev/null; then
    echo -e "${RED}[✘] Python 3 no está instalado. Por favor instálalo antes de continuar.${NC}"
    exit 1
fi

echo -e "${GREEN}[+] Python 3 detectado: $(python3 --version)${NC}"

# 3. Limpieza y Creación del Entorno Virtual (.venv)
if [ -d ".venv" ] && [ ! -f ".venv/bin/activate" ]; then
    echo -e "${YELLOW}[!] Entorno .venv incompleto detectado. Eliminando para recrear...${NC}"
    rm -rf .venv
fi

if [ ! -d ".venv" ]; then
    echo -e "${YELLOW}[*] Creando entorno virtual .venv...${NC}"
    python3 -m venv .venv
else
    echo -e "${GREEN}[+] Entorno virtual .venv listo.${NC}"
fi

# 4. Activación e Instalación de Dependencias Python
echo -e "${YELLOW}[*] Activando .venv e instalando paquetes de PhishShield...${NC}"
source .venv/bin/activate

pip install --upgrade pip
pip install -e .

# 5. Instalación de Navegadores y Dependencias para Playwright
echo -e "${YELLOW}[*] Instalando Chromium para Playwright...${NC}"
playwright install chromium

echo -e "${YELLOW}[*] Verificando dependencias gráficas/sistema para Chromium...${NC}"
sudo playwright install-deps chromium 2>/dev/null || playwright install-deps chromium 2>/dev/null || true

# 6. Configuración de Variables de Entorno (.env)
if [ ! -f ".env" ]; then
    if [ -f ".env.example" ]; then
        echo -e "${YELLOW}[*] Creando .env a partir de .env.example...${NC}"
        cp .env.example .env
    else
        echo -e "${YELLOW}[*] Creando archivo .env base...${NC}"
        echo "GEMINI_API_KEY=tu_api_key_aqui" > .env
    fi
    echo -e "${RED}[!] IMPORTANTE: Configura tu GEMINI_API_KEY en el archivo .env${NC}"
else
    echo -e "${GREEN}[+] Archivo .env detectado.${NC}"
fi

echo -e "\n${GREEN}============================================================${NC}"
echo -e "${GREEN}  ¡Instalación de PhishShield AI completada con éxito!  ${NC}"
echo -e "${GREEN}============================================================${NC}"
echo -e "\nPara comenzar a usar la herramienta:"
echo -e "  ${CYAN}source .venv/bin/activate${NC}"
echo -e "  ${CYAN}phishshield${NC}\n"