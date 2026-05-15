# CyberKB — Cybersecurity Knowledge Base

> Base de conocimiento de ciberseguridad potenciada por IA (Claude Sonnet). Gestiona notas, comandos, herramientas, CVEs y consultas OSINT desde una interfaz local.

![Python](https://img.shields.io/badge/Python-3.11%2B-blue)
![FastAPI](https://img.shields.io/badge/FastAPI-0.115%2B-009688)
![SQLite](https://img.shields.io/badge/SQLite-local-lightgrey)
![Claude](https://img.shields.io/badge/IA-Claude%20Sonnet-orange)
![License](https://img.shields.io/badge/license-MIT-green)

---

## ¿Qué es CyberKB?

CyberKB es una aplicación **local** de escritorio pensada para profesionales y estudiantes de ciberseguridad. Permite importar documentos (PDF, ODT, TXT, MD) y extraer automáticamente mediante IA:

- **Notas** categorizadas (reconocimiento, explotación, post-explotación, OSINT, forense…)
- **Comandos** con detección de SO (Linux, Windows, PowerShell, Google Dorks)
- **Herramientas** con URL y descripción
- **CVEs** referenciados en el documento
- **Grafo de conocimiento** interactivo: entidades reales de ciberseguridad (técnicas, protocolos, vulnerabilidades…) extraídas del contenido y visualizadas como red de nodos

Además incluye un módulo **OSINT** con 15+ herramientas agrupadas por objetivo (dominio, IP, email, URL/web) y un **chat IA** con contexto de toda la base de conocimiento.

## ¿Qué problema resuelve?
Cuando estudias ciberseguridad acumulas cientos de notas, PDFs, comandos y CVEs dispersos en carpetas, Notion, bloc de notas… CyberKB centraliza todo ese conocimiento en una sola herramienta local: lo organiza automáticamente con IA, lo hace buscable, y lo conecta visualmente mediante un grafo de conocimiento interactivo.

---

## Características

| Módulo | Descripción |
|---|---|
| 📝 **Editor** | Notas con categoría, subcategoría, tags, comandos y CVEs asociados |
| ⚙ **Herramientas** | Catálogo de tools con URL, tipo (software/web) y casos de uso |
| ⌘ **Comandos** | Cheatsheet filtrable por OS: Linux / Windows / PowerShell / Google Dorks |
| ◎ **OSINT** | 15 herramientas: WHOIS, DNS, SSL, Wayback, DMARC/SPF, Reverse DNS, ASN/BGP, email verify, Hunter.io, Shodan, VirusTotal, URLscan… |
| ⬡ **Grafo** | Grafo D3.js de entidades reales: ataques, defensas, herramientas, protocolos, vulnerabilidades, metodologías, conceptos |
| ⚠ **CVEs** | Lista de CVEs con severidad y descripción |
| ✦ **Chat IA** | Pregunta a Claude con contexto de tus notas |
| 📋 **Auditorías** | Checklists de auditoría (web, red, AD…) con progreso guardado |

---

## Requisitos

- Python 3.11 o superior
- API key de Anthropic (Claude) — [obtener aquí](https://console.anthropic.com/)
- Conexión a internet (solo para llamadas a la API y herramientas OSINT)

---

## Instalación

### 1. Clonar el repositorio

```bash
git clone https://github.com/jcuarterosaez/CyberKB.git
cd CyberKB
```

### 2. Crear entorno virtual e instalar dependencias

```bash
python -m venv .venv

# Windows
.venv\Scripts\activate

# Linux / macOS
source .venv/bin/activate

pip install -r requirements.txt
```

### 3. Configurar variables de entorno

```bash
cp .env.example .env
```

Edita `.env` con tu API key:

```env
ANTHROPIC_API_KEY=sk-ant-xxxxxxxxxxxxxxxx   # Obligatoria
```

**APIs opcionales** para módulo OSINT (todas gratuitas salvo Shodan):

```env
VIRUSTOTAL_API_KEY=    # gratis — virustotal.com
HUNTER_API_KEY=        # gratis — hunter.io (25 búsquedas/mes, sin tarjeta)
URLSCAN_API_KEY=       # gratis — urlscan.io (para enviar URLs a escanear)
SHODAN_API_KEY=        # de pago — shodan.io
```

### 4. Iniciar la aplicación

```bash
python main.py
```

Se abre automáticamente en `http://localhost:8000`.

---

## Uso básico

### Importar un documento

1. Pulsa **⊕ Subir doc** en la barra superior
2. Selecciona un PDF, ODT, TXT o MD
3. Activa **Guardar automáticamente** para que la IA extraiga notas, comandos, herramientas y CVEs
4. El grafo de conocimiento se actualiza con las entidades detectadas

### Grafo de conocimiento

- Pestaña **⬡ GRAFO**
- Filtra por tipo de entidad: ⚔ Ataque · 🛡 Defensa · ⚙ Herramienta · 📡 Protocolo · ⚠ Vulnerabilidad · 📋 Metodología · 💡 Concepto
- Clic en un nodo → descripción, notas relacionadas, entidades conectadas
- **⚙ Reindexar todo** para re-extraer entidades de documentos ya importados

### OSINT

1. Pestaña **◎ OSINT**
2. Selecciona herramienta por categoría (Dominio / IP-Red / Email / URL-Web)
3. Introduce la consulta → **▶ Ejecutar**
4. Resultados guardados automáticamente en el historial

---

## Herramientas OSINT incluidas

| Categoría | Herramienta | API necesaria |
|---|---|---|
| **Dominio** | WHOIS | No |
| | DNS Records | No |
| | Subdominios (crt.sh) | No |
| | SSL Certificate | No |
| | Wayback Machine | No |
| | DMARC / SPF / DKIM | No |
| | robots.txt | No |
| **IP / Red** | IP Geolocalización | No |
| | Reverse DNS (PTR) | No |
| | ASN / BGP (bgpview.io) | No |
| | Shodan | Sí (pago) |
| **Email** | Verificar Email (MX) | No |
| | Have I Been Pwned | Sí (pago para emails) |
| | Hunter.io email finder | Sí (gratis) |
| **URL / Web** | HTTP Headers + seguridad | No |
| | URLscan.io search | No |
| | VirusTotal | Sí (gratis) |

---

## Compilar EXE (Windows)

```bash
pip install pyinstaller
python -m PyInstaller cyberkb.spec --noconfirm
# EXE generado en dist/CyberKB.exe
```

---

## Estructura del proyecto

```
CyberKB/
├── main.py              # FastAPI app + todos los endpoints
├── models.py            # Modelos SQLAlchemy (Note, Command, Tool, CVE, GraphEntity…)
├── database.py          # Configuración SQLite
├── claude_service.py    # Integración Claude API
├── osint_tools.py       # 15+ herramientas OSINT asíncronas
├── document_parser.py   # Parser PDF / ODT / TXT / MD
├── index.html           # Frontend completo (vanilla JS + D3.js, single-file)
├── requirements.txt     # Dependencias Python
├── cyberkb.spec         # Spec PyInstaller
├── .env.example         # Plantilla de variables de entorno
├── data/                # Base de datos SQLite (generada al arrancar)
└── uploads/             # Documentos subidos (excluidos de git)
```

---

## Stack tecnológico

- **Backend**: FastAPI · Uvicorn · SQLAlchemy · SQLite
- **IA**: Anthropic Claude Sonnet
- **Frontend**: Vanilla JS · D3.js v7 (grafo fuerza-dirigida)
- **OSINT**: httpx async · dnspython · python-whois · APIs públicas

---

## Licencia

MIT — libre para uso personal y educativo.
Proyecto académico desarrollado durante el Master en Ciberseguridad de [Evolve](https://evolve.es).
