# CyberKB v5.7 — Cybersecurity Knowledge Base

> Base de conocimiento de ciberseguridad potenciada por IA (Claude Sonnet). Gestiona notas, comandos, herramientas, CVEs, consultas OSINT, threat intelligence y análisis forense desde una interfaz local sin depender de servicios externos.

![Python](https://img.shields.io/badge/Python-3.11%2B-blue)
![FastAPI](https://img.shields.io/badge/FastAPI-0.115%2B-009688)
![SQLite](https://img.shields.io/badge/SQLite-local-lightgrey)
![Claude](https://img.shields.io/badge/IA-Claude%20Sonnet-orange)
![License](https://img.shields.io/badge/license-MIT-green)
![Version](https://img.shields.io/badge/version-5.7-purple)

---

## ¿Qué es CyberKB?

CyberKB es una aplicación **local** de escritorio pensada para profesionales y estudiantes de ciberseguridad. Permite importar documentos (PDF, ODT, TXT, MD) y extraer automáticamente mediante IA todo el conocimiento relevante: notas, comandos, herramientas, CVEs, técnicas MITRE ATT&CK y entidades del grafo de conocimiento.

Más allá del gestor de notas, CyberKB integra un flujo ofensivo completo: desde el reconocimiento OSINT, pasando por la enumeración activa, la correlación con threat intelligence en tiempo real, hasta la generación de informes técnicos y ejecutivos para el cliente.

Todo corre **en local**. Tus datos nunca salen de tu máquina salvo las llamadas explícitas a las APIs que tú configures.

## ¿Qué problema resuelve?
Cuando estudias ciberseguridad acumulas cientos de notas, PDFs, comandos y CVEs dispersos en carpetas, Notion, bloc de notas… CyberKB centraliza todo ese conocimiento en una sola herramienta local: lo organiza automáticamente con IA, lo hace buscable, y lo conecta visualmente mediante un grafo de conocimiento interactivo.

---

## Módulos

| Módulo | Descripción |
|---|---|
| 📝 **Editor** | Notas con categoría, subcategoría, tags, análisis IA automático al subir documentos |
| ⚙ **Herramientas** | Catálogo de tools detectadas automáticamente con URL, tipo y casos de uso |
| ⌘ **Comandos** | Cheatsheet filtrable por OS: Linux / Windows / PowerShell / Google Dorks / PrivEsc. Incluye generadores: SQLi, reverse shells, estabilización de shell |
| ◎ **OSINT** | 18+ herramientas agrupadas por objetivo: dominio, IP, email, URL, credenciales filtradas |
| 🗺 **Enumeración** | Módulo ofensivo completo: descubrimiento de red, análisis de servicios por puerto, generador Nmap interactivo, cheatsheet y sección Windows/AD |
| ⬡ **Grafo** | Grafo D3.js de entidades reales: ataques, defensas, herramientas, protocolos, vulnerabilidades, MITRE |
| ⚠ **CVEs** | Lista de CVEs con severidad, descripción y badges Exploit-DB en tiempo real |
| ✓ **Auditorías** | Checklists de auditoría (web, red, AD, móvil) con progreso guardado e informes PDF/MD |
| ⚡ **MITRE ATT&CK** | Técnicas extraídas automáticamente de tus notas, organizadas por táctica con enlace directo |
| 🔬 **Forense** | Pipeline forense automático SHA256: VirusTotal + MalwareBazaar + Any.run → nota IA |
| ✦ **Chat IA** | Claude con contexto de toda tu base de conocimiento |

---

## Novedades v5.7

Bloque de herramientas ofensivas interactivas, todas frontend (sin llamadas externas) y con botón "Guardar en KB" que persiste el comando en la base de datos:

### 💉 Generador de Payloads SQLi
- Modal en el módulo de Comandos con selector de tipo de campo (login usuario/contraseña, buscador, parámetro URL) y objetivo (bypass auth, detección, UNION-based, comentar query)
- Payloads regenerados en tiempo real, cada uno con explicación, copiar y guardar en KB (categoría `SQL Injection`)

### 🪟 Sección Windows / AD en Enumeración
- Nuevo cuarto tab del módulo Enumeración
- SMB (smbclient, enum4linux), MSSQL e Impacket (mssqlclient, secuencia xp_cmdshell completa, comprobación sysadmin), post-explotación (psexec, secretsdump) y tabla de equivalencias Windows vs Linux

### ⚡ Catálogo de técnicas de escalada de privilegios
- Tarjetas de técnica en el filtro PrivEsc: nombre, comando de detección, comando de explotación y campo de referencia editable para notas propias
- 4 técnicas precargadas (PATH Hijacking, SUID interactivo, vi/vim vía sudo, historial PowerShell)
- El usuario puede añadir sus propias técnicas desde la UI; todo persiste en `localStorage`

### 🐚 Estabilización de shell (TTY upgrade)
- Snippet de los 5 pasos copiable de una vez y paso a paso, con aviso de que Ctrl+Z y fg son acciones manuales

### 🔌 Generador de Reverse Shells
- Modal con IP, puerto y técnica (PHP simple, PHP mkfifo, Bash /dev/tcp, PowerShell + nc64.exe)
- Comandos con IP/puerto interpolados y recordatorio dinámico del listener (`nc -lvnp PUERTO`)

### 📰 Checklist de auditoría WordPress
- Nuevo tipo de checklist en Auditorías con 8 ítems (information disclosure en login, enumeración de usuarios, fuerza bruta, plugins/temas vulnerables, file upload, permisos de ficheros sensibles)
- Comandos `wpscan` integrados y progreso guardado igual que el resto de auditorías

---

## Novedades v5.6

### 🗺 Módulo de Enumeración
Nuevo módulo enfocado en el flujo ofensivo real de pentesting, organizado en tres secciones:

- **Descubrimiento de red**: métodos ARP/ICMP con nivel de ruido (silencioso / moderado / ruidoso), tabla de interpretación de TTL por SO, generador de comandos personalizado con rango de red y herramienta seleccionable
- **Análisis de servicios**: metodología de dos fases (descubrimiento rápido → análisis profundo), generador Nmap interactivo en tiempo real con toggles para todos los flags, acordeón con 9 servicios (FTP/SSH/Telnet/SMTP/DNS/HTTP/SMB/RDP/MySQL) con vectores de ataque y comandos copiables, tabla de servicios adicionales
- **Cheatsheet Nmap**: referencia rápida completa organizada por categorías (puertos, tipos de escaneo, velocidad, output, scripts NSE)
- Integración con KB: botón 💾 en cada comando para guardarlo directamente en la base de datos con categoría y OS inferido automáticamente
- Generador Nmap con botón para crear nota con los comandos generados, IP y fecha

### 🔬 Modo Forense
Pipeline automático de análisis de malware por hash SHA256:
1. VirusTotal + MalwareBazaar en paralelo
2. Any.run (si detecciones > 5) para sandbox dinámico
3. Claude sintetiza toda la información → nota estructurada con CVEs, técnicas MITRE y timeline
4. Indicadores de progreso por fase con estados visuales

### 🎯 Threat Intelligence
Integrado en el módulo OSINT:
- **VirusTotal hash lookup**: análisis de ficheros por MD5/SHA1/SHA256 con detecciones por motor AV
- **AbuseIPDB**: reputación de IPs con histórico de abusos reportados
- **MalwareBazaar**: lookup de hashes con metadatos de muestras de malware

### ⚡ MITRE ATT&CK
- Extracción automática de técnicas ATT&CK al analizar documentos con IA
- Tab dedicado con técnicas organizadas por táctica (Reconocimiento → Exfiltración)
- Tarjetas con ID, nombre, táctica y fragmento de contexto
- Búsqueda en tiempo real y enlace directo a attack.mitre.org

### 📄 Generador de Informes
Desde el módulo de Auditorías, con elementos completados:
- **Informe técnico**: detalle de hallazgos con evidencias, comandos y recomendaciones técnicas
- **Informe ejecutivo**: resumen de riesgo, impacto de negocio y plan de acción para dirección
- Exportar en Markdown o imprimir como PDF desde el navegador

### 🔓 Detección de Credenciales Filtradas (LeakRadar)
- Búsqueda por email o dominio en bases de datos de brechas (compatible DeHashed)
- Contraseñas enmascaradas automáticamente para uso responsable
- Disponible en el módulo OSINT → sección Email

### 💥 Exploit-DB en CVEs
- Badge por cada CVE que indica si existe exploit público en Exploit-DB
- Carga lazy (solo cuando se visualiza la lista de CVEs)
- Enlace directo al exploit con detalles del módulo afectado

### ⚡ PrivEsc Cheatsheet
- 19 técnicas de escalada de privilegios pre-cargadas (9 Linux + 10 Windows)
- Filtro dedicado ⚡ PrivEsc en el módulo de Comandos
- Badge amber en cada comando de escalada
- Accesos rápidos a GTFOBins y LOLBAS

### 🔍 OSINT mejorado
- **Subdominios**: fuentes combinadas crt.sh + HackerTarget con deduplicación y badges por fuente
- **HIBP mejorado**: verificación de emails y dominios con HIBP v3, resultados inline
- **Búsqueda de credenciales**: nuevo botón LeakRadar en la sección Email

### 🔧 UX y rendimiento
- Barras de progreso animadas en todas las operaciones largas (upload, análisis IA, forense, reindexado)
- Botón API Keys centrado y destacado visualmente en la barra de navegación
- Fix: botón Reindexar ahora vuelve siempre a su estado original
- Fix: campos de API key con texto-overflow sin scroll lateral
- Versión v5.6 en título y logo

---

## Requisitos

- Python 3.11 o superior
- API key de Anthropic (Claude) — [obtener aquí](https://console.anthropic.com/)
- Conexión a internet (solo para llamadas a APIs configuradas)

---

## Instalación

### 1. Clonar el repositorio

```bash
git clone https://github.com/Xelu94/CyberKB.git
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

Edita `.env` con tus API keys:

```env
# Obligatoria
ANTHROPIC_API_KEY=sk-ant-xxxxxxxxxxxxxxxx

# Opcionales — dejar vacío para deshabilitar esa herramienta
VIRUSTOTAL_API_KEY=       # gratis — virustotal.com
ABUSEIPDB_API_KEY=        # gratis — abuseipdb.com
MALWAREBAZAAR_API_KEY=    # gratis — bazaar.abuse.ch
HUNTER_API_KEY=           # gratis (25/mes) — hunter.io
HIBP_API_KEY=             # ~3.50$/mes — haveibeenpwned.com
LEAKRADAR_API_KEY=        # DeHashed compatible — dehashed.com
ANYRUN_API_KEY=           # gratis (tier limitado) — any.run
SHODAN_API_KEY=           # de pago — shodan.io
URLSCAN_API_KEY=          # gratis — urlscan.io
```

> También puedes configurar todas las keys desde la propia app: botón **🔑 API Keys** en la barra superior. Se guardan en `.env` sin reiniciar el servidor.

### 4. Iniciar la aplicación

```bash
# Windows (doble clic)
start.bat

# O directamente
python main.py
```

Se abre automáticamente en `http://localhost:8000`.

---

## Uso rápido

### Importar un documento

1. Pulsa **⊕ Subir doc** en la barra superior
2. Selecciona un PDF, ODT, TXT o MD
3. Activa **Guardar automáticamente**
4. La IA extrae notas, comandos, herramientas, CVEs y técnicas MITRE automáticamente

### Módulo Enumeración (flujo ofensivo)

1. Pestaña **🗺 ENUMERACIÓN**
2. **Descubrimiento de red**: introduce el rango y genera el comando con la herramienta elegida
3. **Análisis de servicios**: usa el generador Nmap para construir ambas fases, luego consulta el acordeón del servicio que encuentres abierto
4. **Cheatsheet Nmap**: referencia rápida de todos los flags

### Análisis forense

1. Pestaña **🔬 FORENSE**
2. Pega un hash SHA256
3. Pulsa **▶ Analizar** — el pipeline corre en segundo plano y crea una nota automáticamente

### OSINT

1. Pestaña **◎ OSINT**
2. Selecciona herramienta por categoría
3. Introduce la consulta → **▶ Ejecutar**
4. Resultados guardados en historial automáticamente

### Generar informe de auditoría

1. Pestaña **✓ AUDITORÍAS**
2. Selecciona tipo (Web App, Red, AD…)
3. Completa los elementos del checklist
4. Pulsa **📄 Generar Informe** → elige técnico o ejecutivo → descarga MD o imprime PDF

---

## Herramientas OSINT incluidas

| Categoría | Herramienta | API necesaria |
|---|---|---|
| **Dominio** | WHOIS | No |
| | DNS Records | No |
| | Subdominios (crt.sh + HackerTarget) | No |
| | SSL Certificate | No |
| | Wayback Machine | No |
| | DMARC / SPF / DKIM | No |
| | robots.txt | No |
| **IP / Red** | IP Geolocalización | No |
| | Reverse DNS (PTR) | No |
| | ASN / BGP (bgpview.io) | No |
| | Shodan | Sí (pago) |
| | AbuseIPDB | Sí (gratis) |
| | VirusTotal (hash/IP) | Sí (gratis) |
| | MalwareBazaar | Sí (gratis) |
| **Email** | Verificar Email (MX + SMTP) | No |
| | Have I Been Pwned | Sí (dominio gratis, email pago) |
| | Hunter.io email finder | Sí (gratis) |
| | LeakRadar (credenciales filtradas) | Sí (DeHashed) |
| **URL / Web** | HTTP Headers + seguridad | No |
| | URLscan.io | No / Sí (para enviar) |

---

## Compilar EXE (Windows)

```bash
pip install pyinstaller
pyinstaller cyberkb.spec --noconfirm
# EXE generado en dist/CyberKB.exe
```

O usando el script incluido:
```bash
build.bat
```

---

## Estructura del proyecto

```
CyberKB/
├── main.py              # FastAPI app + todos los endpoints
├── models.py            # Modelos SQLAlchemy (Note, Command, Tool, CVE, GraphEntity, MitreTechnique…)
├── database.py          # Configuración SQLite
├── claude_service.py    # Integración Claude API (análisis, extracción, informes, forense)
├── osint_tools.py       # 18+ herramientas OSINT asíncronas
├── document_parser.py   # Parser PDF / ODT / TXT / MD
├── index.html           # Frontend completo (vanilla JS + D3.js, single-file)
├── requirements.txt     # Dependencias Python
├── cyberkb.spec         # Spec PyInstaller
├── start.bat            # Script de inicio (Windows)
├── build.bat            # Script de compilación EXE
├── .env.example         # Plantilla de variables de entorno (sin keys reales)
├── data/                # Base de datos SQLite (generada al arrancar)
└── uploads/             # Documentos subidos (excluidos de git)
```

---

## Stack tecnológico

- **Backend**: FastAPI · Uvicorn · SQLAlchemy · SQLite
- **IA**: Anthropic Claude Sonnet (análisis, extracción de entidades, informes, síntesis forense)
- **Frontend**: Vanilla JS · D3.js v7 (grafo fuerza-dirigida)
- **OSINT**: httpx async · dnspython · python-whois · 10+ APIs públicas y privadas
- **Empaquetado**: PyInstaller (EXE Windows standalone)

---

## Licencia

MIT — libre para uso personal y educativo.
Proyecto académico desarrollado durante el Master en Ciberseguridad de [Evolve](https://evolve.es).
