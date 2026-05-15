import os
import json
import re
from anthropic import Anthropic
from dotenv import load_dotenv

load_dotenv(encoding="utf-8", override=True)

client = Anthropic(api_key=os.getenv("ANTHROPIC_API_KEY", ""))

CATEGORIES = [
    "reconocimiento",   # OSINT, footprinting, scanning
    "enumeracion",      # port/service/user enumeration
    "explotacion",      # exploits, RCE, shellcode
    "post-explotacion", # privesc, persistence, lateral movement
    "web-hacking",      # XSS, SQLi, CSRF, LFI/RFI, SSRF
    "redes",            # protocols, traffic analysis, routing
    "criptografia",     # encryption, hashing, crypto attacks
    "forense",          # digital forensics, incident response
    "malware",          # malware analysis, RE, sandbox
    "osint",            # OSINT techniques and tools
    "ingenieria-social",# phishing, pretexting, vishing
    "herramienta",      # tool documentation/setup
    "comandos",         # commands, scripts, cheatsheets
    "vulnerabilidad",   # CVEs, advisories
    "metodologia",      # frameworks, pentest methodology
    "teoria",           # concepts, definitions, fundamentals
]

# Tools that are websites/platforms, not installable software
WEB_RESOURCES: set[str] = {
    "shodan", "censys", "fofa", "zoomeye", "binaryedge", "dehashed",
    "haveibeenpwned", "hibp", "hunter.io", "phonebook.cz", "intelx",
    "virustotal", "urlscan", "anyrun", "hybrid analysis", "joe sandbox",
    "crt.sh", "dnsdumpster", "exploitdb", "exploit-db", "nvd",
    "hackthebox", "tryhackme", "vulnhub", "picoctf", "ctftime",
    "crackstation", "hashkiller", "osint framework", "grep.app",
    "publicwww", "builtwith", "wappalyzer", "pentest-tools",
    "opensense", "dehashed.com", "shodan.io", "censys.io",
    "maltego", "spiderfoot",
}

# Heuristic OS detection for commands
_WIN_HINTS = {"ipconfig", "netstat /", "net use", "net user", "reg add", "reg query",
              "icacls", "wmic", "schtasks", "mshta", "certutil", "bitsadmin",
              "rundll32", "regsvr32", "cmd /c", "whoami /", "systeminfo",
              "tasklist", "taskkill", "sc query", "sc config", "type c:\\", "dir c:\\"}
_LIN_HINTS  = {"sudo ", "chmod ", "chown ", "grep ", "/bin/", "/etc/", "/usr/",
               "apt ", "yum ", "dnf ", "systemctl ", "service ", "bash ", "sh -",
               "python3 ", "perl ", "ruby ", "awk ", "sed '", "cat /", "ls -",
               "id && ", "uname ", "ps aux", "netstat -", "ss -", "curl -", "wget "}
_GOOGLE_HINTS = {
    "site:", "inurl:", "intitle:", "intext:", "filetype:", "ext:",
    "allinurl:", "allintitle:", "allintext:", "cache:", "related:",
    "-inurl:", "-site:", "inurl:?id=", "inurl:?page=", "inurl:?file=",
    "filetype:sql", "filetype:env", "filetype:log", "filetype:xls",
}
_PS_HINTS   = {"get-childitem", "get-item", "get-process", "get-service", "get-content",
               "set-content", "write-host", "write-output", "$env:", "foreach-object",
               "where-object", "select-object", ".ps1", "param(", "invoke-expression",
               " iex ", "add-type", "import-module", "new-object ", "convertto-",
               "convertfrom-", "out-file", "export-csv", "import-csv",
               "get-wmiobject", "get-ciminstance", "start-process", "stop-process",
               "[system.net", "[convert]", "powershell -e", "powershell.exe",
               "get-acl", "set-acl", "get-localuser", "get-localgroupmember",
               "invoke-webrequest", "invoke-restmethod", "get-netadapter",
               "get-aduser", "get-adgroup", "get-adcomputer", "get-domainuser"}


def detect_command_os(cmd: str) -> str:
    c = cmd.lower()
    goo = sum(1 for h in _GOOGLE_HINTS if h in c)
    ps  = sum(1 for h in _PS_HINTS if h in c)
    win = sum(1 for h in _WIN_HINTS if h in c)
    lin = sum(1 for h in _LIN_HINTS if h in c)
    if goo >= 2:  # at least 2 Google operators = definitely a dork
        return "google"
    if ps > 0 and ps >= win:
        return "powershell"
    if win > lin:
        return "windows"
    if lin > win:
        return "linux"
    return "both"


def detect_tool_type(name: str) -> str:
    return "web" if name.lower() in WEB_RESOURCES else "software"


KNOWN_TOOLS: dict[str, str | None] = {
    "nmap": "https://nmap.org",
    "metasploit": "https://www.metasploit.com",
    "msfconsole": "https://www.metasploit.com",
    "msfvenom": "https://www.metasploit.com",
    "burp suite": "https://portswigger.net/burp",
    "burpsuite": "https://portswigger.net/burp",
    "burp": "https://portswigger.net/burp",
    "wireshark": "https://www.wireshark.org",
    "tshark": "https://www.wireshark.org",
    "sqlmap": "https://sqlmap.org",
    "hydra": "https://github.com/vanhauser-thc/thc-hydra",
    "john": "https://www.openwall.com/john/",
    "john the ripper": "https://www.openwall.com/john/",
    "hashcat": "https://hashcat.net",
    "aircrack-ng": "https://www.aircrack-ng.org",
    "aircrack": "https://www.aircrack-ng.org",
    "nikto": "https://cirt.net/Nikto2",
    "gobuster": "https://github.com/OJ/gobuster",
    "dirb": "https://github.com/v0re/dirb",
    "ffuf": "https://github.com/ffuf/ffuf",
    "feroxbuster": "https://github.com/epi052/feroxbuster",
    "masscan": "https://github.com/robertdavidgraham/masscan",
    "rustscan": "https://github.com/RustScan/RustScan",
    "shodan": "https://www.shodan.io",
    "censys": "https://censys.io",
    "fofa": "https://fofa.info",
    "zoomeye": "https://www.zoomeye.org",
    "binaryedge": "https://www.binaryedge.io",
    "dehashed": "https://dehashed.com",
    "haveibeenpwned": "https://haveibeenpwned.com",
    "hibp": "https://haveibeenpwned.com",
    "maltego": "https://www.maltego.com",
    "recon-ng": "https://github.com/lanmaster53/recon-ng",
    "theharvester": "https://github.com/laramies/theHarvester",
    "spiderfoot": "https://www.spiderfoot.net",
    "bloodhound": "https://github.com/BloodHoundAD/BloodHound",
    "sharphound": "https://github.com/BloodHoundAD/SharpHound",
    "mimikatz": "https://github.com/gentilkiwi/mimikatz",
    "impacket": "https://github.com/fortra/impacket",
    "crackmapexec": "https://github.com/Porchetta-Industries/CrackMapExec",
    "cme": "https://github.com/Porchetta-Industries/CrackMapExec",
    "evil-winrm": "https://github.com/Hackplayers/evil-winrm",
    "netcat": "https://github.com/diegocr/netcat",
    "socat": "https://github.com/3ndG4me/socat",
    "tcpdump": "https://www.tcpdump.org",
    "beef": "https://beefproject.com",
    "owasp zap": "https://www.zaproxy.org",
    "zaproxy": "https://www.zaproxy.org",
    "volatility": "https://www.volatilityfoundation.org",
    "ghidra": "https://ghidra-sre.org",
    "ida pro": "https://hex-rays.com/ida-pro/",
    "radare2": "https://rada.re",
    "x64dbg": "https://x64dbg.com",
    "gdb": "https://www.gnu.org/software/gdb/",
    "pwntools": "https://github.com/Gallopsled/pwntools",
    "nuclei": "https://github.com/projectdiscovery/nuclei",
    "subfinder": "https://github.com/projectdiscovery/subfinder",
    "amass": "https://github.com/owasp-amass/amass",
    "linpeas": "https://github.com/carlospolop/PEASS-ng",
    "winpeas": "https://github.com/carlospolop/PEASS-ng",
    "peass": "https://github.com/carlospolop/PEASS-ng",
    "cyberchef": "https://gchq.github.io/CyberChef/",
    "virustotal": "https://www.virustotal.com",
    "urlscan": "https://urlscan.io",
    "anyrun": "https://any.run",
    "hybrid analysis": "https://www.hybrid-analysis.com",
    "yara": "https://virustotal.github.io/yara/",
    "crt.sh": "https://crt.sh",
    "dnsdumpster": "https://dnsdumpster.com",
    "exploitdb": "https://www.exploit-db.com",
    "exploit-db": "https://www.exploit-db.com",
    "searchsploit": "https://www.exploit-db.com/searchsploit",
    "nvd": "https://nvd.nist.gov",
    "mitre att&ck": "https://attack.mitre.org",
    "mitre attack": "https://attack.mitre.org",
    "hackthebox": "https://www.hackthebox.com",
    "tryhackme": "https://tryhackme.com",
    "vulnhub": "https://www.vulnhub.com",
    "wfuzz": "https://github.com/xmendez/wfuzz",
    "opensense": "https://opensense.com",
    "snort": "https://www.snort.org",
    "suricata": "https://suricata.io",
    "zeek": "https://zeek.org",
    "wazuh": "https://wazuh.com",
    "splunk": "https://www.splunk.com",
    "hunter.io": "https://hunter.io",
    "intelx": "https://intelx.io",
    "phonebook.cz": "https://phonebook.cz",
    "osint framework": "https://osintframework.com",
    "dnstwist": "https://github.com/elceef/dnstwist",
    "wappalyzer": "https://www.wappalyzer.com",
    "crackstation": "https://crackstation.net",
    "hashkiller": "https://hashkiller.io",
    "powerview": "https://github.com/PowerShellMafia/PowerSploit",
    "responder": "https://github.com/lgandx/Responder",
    "enum4linux": "https://github.com/CiscoCXSecurity/enum4linux",
    "smbclient": None,
    "rpcclient": None,
    "ldapsearch": None,
    "netstat": None,
    "curl": None,
    "wget": None,
}


def _call_claude(prompt: str, max_tokens: int = 2048) -> str:
    msg = client.messages.create(
        model="claude-sonnet-4-6",
        max_tokens=max_tokens,
        messages=[{"role": "user", "content": prompt}],
    )
    return msg.content[0].text.strip()


def analyze_content(text: str) -> dict:
    """Full analysis: category, summary, commands, tools, CVEs, tags, gaps."""
    prompt = f"""Eres un experto en ciberseguridad analizando apuntes de clase/documentos de seguridad.
Analiza el siguiente contenido y responde EXCLUSIVAMENTE con JSON válido (sin markdown, sin explicaciones).

CONTENIDO:
---
{text[:6000]}
---

Responde con este JSON exacto:
{{
  "category": "<una de: reconocimiento|enumeracion|explotacion|post-explotacion|web-hacking|redes|criptografia|forense|malware|osint|ingenieria-social|herramienta|comandos|vulnerabilidad|metodologia|teoria>",
  "subcategory": "<tema específico, ej: 'SQL Injection', 'Privilege Escalation Linux', 'Nmap scanning'>",
  "summary": "<resumen técnico de 2-4 frases>",
  "tags": ["tag1", "tag2", "tag3"],
  "commands": [
    {{
      "command": "<comando exacto>",
      "description": "<qué hace>",
      "tool": "<herramienta>",
      "os": "<linux|windows|powershell|google|both>",
      "flags": ["<flag1>", "<flag2>"]
    }}
  ],
  "tools": [
    {{
      "name": "<nombre exacto de la herramienta>",
      "description": "<para qué sirve en contexto del documento>"
    }}
  ],
  "cves": [
    {{
      "id": "CVE-XXXX-XXXXX",
      "description": "<descripción breve>"
    }}
  ],
  "knowledge_gaps": ["<concepto mencionado que podría necesitar más estudio>"]
}}

REGLAS ESTRICTAS:
- category: NO usar "teoria" si el contenido es claramente sobre una técnica específica
- commands: solo si hay comandos reales (con binario ejecutable), máximo 15
- tools: herramientas de seguridad con nombre propio, no comandos genéricos
- cves: solo CVEs con formato CVE-XXXX-XXXXX explícitos en el texto
- JSON puro, sin comentarios, sin markdown"""

    raw = _call_claude(prompt, max_tokens=3000)
    raw = raw.strip()
    if raw.startswith("```"):
        raw = re.sub(r"^```[a-z]*\n?", "", raw)
        raw = re.sub(r"\n?```$", "", raw)
    try:
        data = json.loads(raw)
    except Exception:
        data = {
            "category": "teoria",
            "subcategory": None,
            "summary": "Análisis no disponible.",
            "tags": [],
            "commands": [],
            "tools": [],
            "cves": [],
            "knowledge_gaps": [],
        }
    # Validate category
    if data.get("category") not in CATEGORIES:
        data["category"] = "teoria"
    # Enrich tools with known URLs and type
    for tool in data.get("tools", []):
        name_lower = tool["name"].lower()
        if name_lower in KNOWN_TOOLS and KNOWN_TOOLS[name_lower]:
            tool["url"] = KNOWN_TOOLS[name_lower]
        else:
            tool["url"] = None
        tool["tool_type"] = detect_tool_type(tool["name"])
    # Enrich commands with OS detection fallback
    for cmd in data.get("commands", []):
        if not cmd.get("os") or cmd["os"] not in ("linux", "windows", "both"):
            cmd["os"] = detect_command_os(cmd.get("command", ""))
    return data


VALID_ENTITY_TYPES = {"attack", "defense", "tool", "protocol", "vuln", "methodology", "concept"}


def extract_entities(text: str) -> dict:
    """Extract named cybersecurity entities and their relations from text."""
    prompt = f"""Eres un experto en ciberseguridad analizando apuntes técnicos.
Extrae ENTIDADES REALES de ciberseguridad del texto. Responde SOLO con JSON válido.

TEXTO:
---
{text[:5000]}
---

JSON exacto (sin markdown):
{{
  "entities": [
    {{
      "name": "<nombre canónico, máx 35 chars>",
      "type": "<tipo>",
      "description": "<descripción técnica en 1-2 frases>"
    }}
  ],
  "relations": [
    ["<nombre_entidad_A>", "<nombre_entidad_B>"]
  ]
}}

TIPOS VÁLIDOS:
- attack:      técnicas ofensivas (SQL Injection, XSS, Buffer Overflow, Pass-the-Hash, Kerberoasting, SSRF, RCE, LFI...)
- defense:     técnicas/controles defensivos (WAF, IDS/IPS, MFA, Zero Trust, Patch Management, SIEM, EDR...)
- tool:        herramientas con nombre propio (nmap, Burp Suite, Metasploit, sqlmap, Wireshark, BloodHound...)
- protocol:    protocolos y estándares (TCP/IP, HTTP/S, SMB, DNS, LDAP, Kerberos, TLS, SSH, SNMP...)
- vuln:        CVEs y vulns específicas (CVE-2021-44228, Log4Shell, EternalBlue, BlueKeep, PrintNightmare...)
- methodology: frameworks y metodologías (OWASP Top 10, MITRE ATT&CK, Kill Chain, PTES, NIST, ISO 27001...)
- concept:     conceptos fundamentales (CIA Triad, Zero Trust Architecture, Defense in Depth, AAA, Least Privilege...)

REGLAS ESTRICTAS:
- Máximo 30 entidades por texto
- Solo entidades con NOMBRE PROPIO reconocible en ciberseguridad
- Relaciones solo entre entidades presentes en la lista anterior
- Normaliza nombres: "SQL Injection" no "SQLi", "Cross-Site Scripting" o "XSS" (el más común)
- CVEs en formato CVE-XXXX-XXXXX
- NO incluir: "sistema", "red", "usuario", "servidor", "datos", "ataque genérico"
- Las relaciones indican que las entidades aparecen juntas en contexto técnico"""

    raw = _call_claude(prompt, max_tokens=2000)
    raw = raw.strip()
    if raw.startswith("```"):
        raw = re.sub(r"^```[a-z]*\n?", "", raw)
        raw = re.sub(r"\n?```$", "", raw)
    try:
        data = json.loads(raw)
        # Validate entity types
        for e in data.get("entities", []):
            if e.get("type") not in VALID_ENTITY_TYPES:
                e["type"] = "concept"
        return data
    except Exception:
        return {"entities": [], "relations": []}


def chat_with_context(question: str, context_notes: list[dict]) -> str:
    """Answer a question using stored notes as context."""
    ctx = "\n\n".join(
        f"[{n.get('category','')}] {n.get('title','')}: {n.get('summary') or n.get('content','')[:400]}"
        for n in context_notes[:10]
    )
    prompt = f"""Eres un asistente de ciberseguridad. Responde en español de forma técnica y precisa.

CONTEXTO DE LA BASE DE CONOCIMIENTO DEL ESTUDIANTE:
{ctx}

PREGUNTA: {question}

Responde de forma concisa y técnica. Si el contexto no cubre la pregunta, responde con tu conocimiento general de ciberseguridad."""
    return _call_claude(prompt, max_tokens=1500)


def generate_cheatsheet(tool_name: str, commands: list[dict]) -> str:
    """Generate a formatted cheatsheet for a tool."""
    cmds_text = "\n".join(f"- {c.get('command','')} # {c.get('description','')}" for c in commands[:20])
    prompt = f"""Genera un cheatsheet completo de {tool_name} en formato Markdown.
Incluye los siguientes comandos ya documentados y añade los más importantes que falten:

{cmds_text}

Formato: secciones por caso de uso, comandos con explicación breve, flags importantes.
Responde solo con el Markdown del cheatsheet."""
    return _call_claude(prompt, max_tokens=2000)
