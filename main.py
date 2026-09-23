import os
import sys
import json
from pathlib import Path
from contextlib import asynccontextmanager
from fastapi import FastAPI, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session
from database import get_db, init_db, engine
from models import Note, Command, Tool, CVE


from layers.routers.osint import router as osint_router
from layers.routers.notes import router as notes_router
from layers.routers.analyze import router as analyze_router
from layers.routers.chat import router as chat_router
from layers.routers.settings import router as settings_router
from layers.routers.tools import router as tools_router
from layers.routers.commands import router as commands_router
from layers.routers.cves import router as cves_router
from layers.routers.mitre import router as mitre_router
from layers.routers.graph import router as graph_router
from layers.routers.audits import router as audits_router
from layers.routers.forensic import router as forensic_router


# # ─── Path resolution (works both as script and PyInstaller exe) ───────────────
def _bundle_dir() -> Path:
    """Where bundled files live (index.html etc.)."""
    if getattr(sys, "frozen", False):
        return Path(sys._MEIPASS)   # PyInstaller temp extraction dir
    return Path(__file__).parent


BUNDLE_DIR  = _bundle_dir()


###### No eliminar hasta comprobar que botón de Api Keys funciona correctamente #####

# RUNTIME_DIR = _runtime_dir()

# load_dotenv(dotenv_path=RUNTIME_DIR / ".env", encoding="utf-8", override=True)

# UPLOAD_DIR = RUNTIME_DIR / os.getenv("UPLOAD_DIR", "uploads")
# UPLOAD_DIR.mkdir(exist_ok=True)
# (RUNTIME_DIR / "data").mkdir(exist_ok=True)


def _migrate_db():
    """Add new columns to existing tables without losing data."""
    from sqlalchemy import text
    migrations = [
        "ALTER TABLE commands ADD COLUMN os TEXT DEFAULT 'linux'",
        "ALTER TABLE tools ADD COLUMN tool_type TEXT DEFAULT 'software'",
    ]
    with engine.connect() as conn:
        for sql in migrations:
            try:
                conn.execute(text(sql))
                conn.commit()
            except Exception:
                pass  # column already exists


GOOGLE_DORKS = [
    # ── Directorios expuestos ──────────────────────────────────────────────────
    ("intitle:\"index of\" site:target.com",                            "Directorio raíz expuesto en target.com",                           "Directorios expuestos"),
    ("intitle:\"index of /\" passwords",                                "Directorios con ficheros de passwords",                            "Directorios expuestos"),
    ("intitle:\"Index of\" .env",                                       "Directorio con fichero .env expuesto",                             "Directorios expuestos"),
    ("intitle:\"index of\" \"backup\"",                                 "Directorios con backups",                                          "Directorios expuestos"),
    ("intitle:\"index of\" \".git\"",                                   "Repositorio Git expuesto vía web",                                 "Directorios expuestos"),
    ("intitle:\"index of\" \"wp-content\"",                             "WordPress content directory listing",                             "Directorios expuestos"),
    # ── Ficheros sensibles ─────────────────────────────────────────────────────
    ("site:target.com ext:env OR ext:sql OR ext:bak OR ext:log",        "Ficheros sensibles: .env .sql .bak .log",                          "Ficheros sensibles"),
    ("site:target.com ext:xml intext:\"password\"",                     "XML con passwords en target.com",                                 "Ficheros sensibles"),
    ("site:target.com ext:ini intext:\"password\"",                     "Ficheros .ini con passwords",                                     "Ficheros sensibles"),
    ("site:target.com ext:cfg intext:\"password\"",                     "Ficheros .cfg con passwords",                                     "Ficheros sensibles"),
    ("site:target.com filetype:sql intext:\"INSERT INTO\"",             "Dumps SQL con datos",                                             "Ficheros sensibles"),
    ("site:target.com filetype:log intext:\"error\"",                   "Logs con errores expuestos",                                      "Ficheros sensibles"),
    ("site:target.com filetype:pdf confidential",                       "PDFs marcados como confidencial",                                 "Ficheros sensibles"),
    ("site:target.com filetype:xls OR filetype:xlsx intext:\"password\"","Excel con passwords",                                            "Ficheros sensibles"),
    ("site:target.com inurl:wp-config.php",                             "WordPress config expuesto",                                       "Ficheros sensibles"),
    ("site:target.com inurl:\".htpasswd\"",                             ".htpasswd accesible vía web",                                     "Ficheros sensibles"),
    ("site:target.com inurl:\"config.php\"",                            "config.php expuesto",                                             "Ficheros sensibles"),
    ("site:target.com inurl:\"database.yml\"",                          "Credenciales Rails DB expuestas",                                 "Ficheros sensibles"),
    # ── Paneles de administración ─────────────────────────────────────────────
    ("site:target.com inurl:admin",                                     "Paneles admin en target.com",                                     "Paneles admin"),
    ("site:target.com inurl:login",                                     "Páginas de login",                                                "Paneles admin"),
    ("site:target.com inurl:dashboard",                                 "Dashboards expuestos",                                            "Paneles admin"),
    ("site:target.com inurl:phpmyadmin",                                "phpMyAdmin expuesto",                                             "Paneles admin"),
    ("site:target.com inurl:wp-admin",                                  "WordPress admin",                                                 "Paneles admin"),
    ("site:target.com intitle:\"admin panel\"",                         "Paneles con título admin panel",                                  "Paneles admin"),
    ("site:target.com inurl:administrator",                             "Joomla/otros paneles admin",                                      "Paneles admin"),
    ("site:target.com inurl:cpanel",                                    "cPanel expuesto",                                                 "Paneles admin"),
    ("intitle:\"phpMyAdmin\" inurl:phpmyadmin",                         "phpMyAdmin accesible públicamente",                               "Paneles admin"),
    # ── Credenciales y secretos ───────────────────────────────────────────────
    ("site:target.com intext:\"api_key\"",                              "API keys en páginas de target.com",                              "Credenciales y secretos"),
    ("site:target.com intext:\"api_secret\"",                           "API secrets expuestos",                                           "Credenciales y secretos"),
    ("site:target.com intext:\"secret_key\"",                           "Secret keys en páginas",                                          "Credenciales y secretos"),
    ("site:target.com intext:\"Authorization: Bearer\"",                "Tokens Bearer expuestos en páginas",                              "Credenciales y secretos"),
    ("site:target.com intext:\"aws_access_key_id\"",                    "Credenciales AWS expuestas",                                      "Credenciales y secretos"),
    ("site:target.com intext:\"password\"",                             "Páginas con la palabra password",                                 "Credenciales y secretos"),
    ("site:pastebin.com \"target.com\" \"password\"",                   "Pastes con credenciales de target.com",                           "Credenciales y secretos"),
    ("site:pastebin.com \"target.com\" \"api_key\"",                    "Pastes con API keys de target.com",                               "Credenciales y secretos"),
    # ── GitHub dorks ──────────────────────────────────────────────────────────
    ("site:github.com \"target.com\" password",                         "Repos GitHub con passwords de target",                            "GitHub Leaks"),
    ("site:github.com \"target.com\" api_key",                          "Repos GitHub con API keys de target",                             "GitHub Leaks"),
    ("site:github.com \"target.com\" secret",                           "Repos GitHub con secrets de target",                              "GitHub Leaks"),
    ("site:github.com \"target.com\" token",                            "Repos GitHub con tokens de target",                               "GitHub Leaks"),
    ("site:github.com \"api_key\" language:python",                     "Código Python en GitHub con api_key hardcodeada",                 "GitHub Leaks"),
    ("site:github.com \"private_key\" extension:pem",                   "Claves privadas PEM en GitHub",                                   "GitHub Leaks"),
    ("site:github.com inurl:\"/.env\" \"DB_PASSWORD\"",                 ".env con DB_PASSWORD en GitHub",                                  "GitHub Leaks"),
    # ── Cloud storage ──────────────────────────────────────────────────────────
    ("site:s3.amazonaws.com \"target\"",                                "Buckets S3 públicos de target",                                   "Cloud Storage"),
    ("site:storage.googleapis.com \"target\"",                          "Storage GCP público de target",                                   "Cloud Storage"),
    ("site:blob.core.windows.net \"target\"",                           "Azure Blob Storage público de target",                            "Cloud Storage"),
    ("site:s3.amazonaws.com ext:pdf OR ext:xls OR ext:doc",             "Documentos en buckets S3 públicos",                               "Cloud Storage"),
    # ── Parámetros vulnerables ────────────────────────────────────────────────
    ("site:target.com inurl:\"?id=\"",                                  "Parámetros ?id= posiblemente SQLi",                               "Parámetros vulnerables"),
    ("site:target.com inurl:\"?page=\"",                                "Parámetros ?page= posiblemente LFI",                              "Parámetros vulnerables"),
    ("site:target.com inurl:\"?file=\"",                                "Parámetros ?file= posiblemente LFI/RFI",                          "Parámetros vulnerables"),
    ("site:target.com inurl:\"?redirect=\"",                            "Parámetros redirect= posiblemente Open Redirect",                 "Parámetros vulnerables"),
    ("site:target.com inurl:\"?url=\"",                                 "Parámetros url= posiblemente SSRF/Open Redirect",                 "Parámetros vulnerables"),
    ("site:target.com inurl:\"?q=\"",                                   "Parámetros q= posiblemente XSS/SQLi",                             "Parámetros vulnerables"),
    ("site:target.com inurl:\"?search=\"",                              "Parámetros search= posiblemente XSS",                             "Parámetros vulnerables"),
    ("site:target.com inurl:\"?include=\"",                             "Parámetros include= posiblemente RFI",                            "Parámetros vulnerables"),
    # ── Tecnologías y servicios ───────────────────────────────────────────────
    ("site:target.com inurl:jira",                                      "Jira expuesto en target.com",                                     "Tecnologías expuestas"),
    ("site:target.com inurl:confluence",                                "Confluence expuesto",                                             "Tecnologías expuestas"),
    ("site:target.com inurl:jenkins",                                   "Jenkins CI/CD expuesto",                                          "Tecnologías expuestas"),
    ("site:target.com inurl:gitlab",                                    "GitLab expuesto",                                                 "Tecnologías expuestas"),
    ("site:target.com inurl:kibana",                                    "Kibana (logs) expuesto",                                          "Tecnologías expuestas"),
    ("site:target.com inurl:grafana",                                   "Grafana expuesto",                                                "Tecnologías expuestas"),
    ("site:target.com inurl:portainer",                                 "Portainer Docker expuesto",                                       "Tecnologías expuestas"),
    ("site:target.com inurl:sonarqube",                                 "SonarQube expuesto (código fuente)",                              "Tecnologías expuestas"),
    ("site:target.com inurl:swagger",                                   "Swagger API docs expuesto",                                       "Tecnologías expuestas"),
    ("site:target.com inurl:api/v1 OR inurl:api/v2",                    "Endpoints API expuestos",                                         "Tecnologías expuestas"),
    # ── Servicios expuestos ────────────────────────────────────────────────────
    ("intitle:\"Elasticsearch\" inurl:9200",                            "Elasticsearch expuesto (sin auth)",                               "Servicios expuestos"),
    ("intitle:\"Kibana\" inurl:5601",                                   "Kibana expuesto en puerto 5601",                                  "Servicios expuestos"),
    ("intitle:\"Jenkins\" inurl:8080",                                  "Jenkins expuesto en puerto 8080",                                 "Servicios expuestos"),
    ("intitle:\"Grafana\" inurl:3000",                                  "Grafana expuesto en puerto 3000",                                 "Servicios expuestos"),
    ("intitle:\"Redis\" inurl:6379",                                    "Redis expuesto públicamente",                                     "Servicios expuestos"),
    ("intitle:\"MongoDB\" inurl:27017",                                 "MongoDB expuesto sin auth",                                       "Servicios expuestos"),
    ("intitle:\"RabbitMQ\" inurl:15672",                                "RabbitMQ management expuesto",                                    "Servicios expuestos"),
    # ── Cámaras y IoT ─────────────────────────────────────────────────────────
    ("inurl:\"/cgi-bin/camera\" intitle:\"Live View\"",                 "Cámaras IP accesibles",                                           "Cámaras y IoT"),
    ("intitle:\"webcamXP 5\" inurl:8080",                               "WebcamXP sin autenticación",                                      "Cámaras y IoT"),
    ("inurl:ViewerFrame?Mode=Motion",                                   "Cámaras Axis sin autenticación",                                  "Cámaras y IoT"),
    ("intitle:\"IP Camera\" inurl:\"/view/index.shtml\"",               "Cámaras IP accesibles (Axis)",                                    "Cámaras y IoT"),
    ("intitle:\"Network Camera\" inurl:view",                           "Network cameras sin auth",                                        "Cámaras y IoT"),
    # ── Subdomains y email ────────────────────────────────────────────────────
    ("site:*.target.com -www",                                          "Subdominios de target.com (excluye www)",                         "Reconocimiento"),
    ("\"@target.com\" filetype:xls OR filetype:xlsx",                   "Emails corporativos en Excel",                                    "Reconocimiento"),
    ("\"@target.com\" site:linkedin.com",                               "Empleados de target en LinkedIn",                                 "Reconocimiento"),
    ("\"@target.com\" site:github.com",                                 "Empleados con email corporativo en GitHub",                        "Reconocimiento"),
    ("intext:\"@target.com\" filetype:pdf",                             "PDFs con emails de target.com",                                   "Reconocimiento"),
    # ── Errores y debug ───────────────────────────────────────────────────────
    ("site:target.com intext:\"sql syntax near\"",                      "Errores SQL expuestos (SQLi potencial)",                          "Errores y debug"),
    ("site:target.com intext:\"Warning: mysql_\"",                      "Errores PHP MySQL expuestos",                                     "Errores y debug"),
    ("site:target.com intext:\"Traceback (most recent call last)\"",    "Python stack traces expuestos",                                   "Errores y debug"),
    ("site:target.com intext:\"Exception in thread\"",                  "Java exceptions expuestas",                                       "Errores y debug"),
    ("site:target.com intitle:\"404\" intext:\"nginx\"",                "404 de nginx con info de versión",                                "Errores y debug"),
    ("site:target.com intext:\"Fatal error:\" intext:\"PHP\"",          "Fatal errors PHP expuestos",                                      "Errores y debug"),
]


def _seed_google_dorks(_=None):
    """Insert built-in Google Dorks if not already present."""
    from database import SessionLocal
    db = SessionLocal()
    try:
        from sqlalchemy import func
        existing = db.query(Command).filter(Command.os == "google").count()
        if existing > 0:
            return
        for dork, desc, category in GOOGLE_DORKS:
            c = Command(
                command=dork,
                description=desc,
                tool_name="Google Dorking",
                os="google",
                flags=json.dumps([]),
                tags=json.dumps([category]),
                category=category,
            )
            db.add(c)
        db.commit()
    except Exception as e:
        db.rollback()
        print(f"[seed_dorks] Error: {e}")
    finally:
        db.close()


PRIVESC_COMMANDS = [
    # ── Linux ─────────────────────────────────────────────────────────────────
    ("sudo -l",
     "Ver comandos permitidos con privilegios de root",
     "linux", "Sudo & SUID"),
    ("find / -perm -4000 -type f 2>/dev/null",
     "Buscar binarios con bit SUID activado (posible escalada)",
     "linux", "Sudo & SUID"),
    ("find / -perm -2000 -type f 2>/dev/null",
     "Buscar binarios con bit SGID activado",
     "linux", "Sudo & SUID"),
    ("cat /etc/crontab && ls -la /etc/cron*",
     "Ver tareas programadas del sistema (posible abuso si son escribibles)",
     "linux", "Cron & Scheduled Tasks"),
    ("find /etc/cron* /var/spool/cron -writable -type f 2>/dev/null",
     "Buscar ficheros de cron escribibles por el usuario actual",
     "linux", "Cron & Scheduled Tasks"),
    ("uname -a && cat /proc/version",
     "Versión del kernel Linux — buscar CVEs en exploit-db/searchsploit",
     "linux", "Kernel Exploits"),
    ("find / -writable -type f 2>/dev/null | grep -v proc | grep -v sys",
     "Ficheros escribibles por el usuario actual (excluye /proc y /sys)",
     "linux", "File Permissions"),
    ("cat /etc/passwd | grep -v nologin | grep -v false",
     "Usuarios con shell activa (posibles objetivos de lateral movement)",
     "linux", "Users & Groups"),
    ("cat /etc/shadow 2>/dev/null",
     "Intentar leer /etc/shadow — si accesible, hash de contraseñas",
     "linux", "Users & Groups"),
    ("id && groups",
     "Ver usuario actual, UID, GID y grupos a los que pertenece",
     "linux", "Users & Groups"),
    ("env && cat /proc/self/environ 2>/dev/null",
     "Variables de entorno — buscar credenciales hardcodeadas o rutas interesantes",
     "linux", "Environment"),
    ("history && cat ~/.bash_history 2>/dev/null",
     "Historial de comandos — puede contener contraseñas o comandos sensibles",
     "linux", "Environment"),
    ("ss -antp && netstat -tunlp 2>/dev/null",
     "Puertos abiertos localmente no visibles desde fuera (posibles servicios internos)",
     "linux", "Network"),
    ("ps auxww | grep -v '\\[' | head -30",
     "Procesos en ejecución — buscar procesos root o credenciales en argumentos",
     "linux", "Processes"),
    ("find / -name '*.conf' -readable 2>/dev/null | xargs grep -l 'password\\|passwd\\|secret' 2>/dev/null | head -20",
     "Buscar contraseñas en ficheros de configuración legibles",
     "linux", "Credentials"),
    ("find / -name id_rsa -o -name id_ecdsa -o -name id_ed25519 2>/dev/null",
     "Buscar claves SSH privadas accesibles",
     "linux", "Credentials"),
    ("cat /etc/hosts && arp -a && ip route",
     "Hosts conocidos, vecinos ARP y rutas de red — útil para pivoting",
     "linux", "Network"),
    ("find / -path /proc -prune -o -path /sys -prune -o -name '*.py' -o -name '*.sh' -writable -print 2>/dev/null | head -20",
     "Scripts Python/Bash escribibles — puede inyectarse código si los ejecuta root",
     "linux", "File Permissions"),
    # ── Windows ───────────────────────────────────────────────────────────────
    ("whoami /priv",
     "Ver privilegios del token del usuario actual — buscar SeImpersonatePrivilege, SeDebugPrivilege",
     "windows", "Tokens & Privileges"),
    ("whoami /all",
     "Usuario, SID, grupos y privilegios completos del token",
     "windows", "Tokens & Privileges"),
    ("net user",
     "Listar usuarios locales del sistema",
     "windows", "Users & Groups"),
    ("net localgroup Administrators",
     "Miembros del grupo Administradores locales",
     "windows", "Users & Groups"),
    ("net accounts",
     "Política de contraseñas: longitud mínima, bloqueos, historial",
     "windows", "Users & Groups"),
    ("schtasks /query /fo LIST /v",
     "Ver tareas programadas detalladas — buscar ejecutables en rutas escribibles",
     "windows", "Cron & Scheduled Tasks"),
    ("reg query HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer /v AlwaysInstallElevated",
     "AlwaysInstallElevated — si está a 1, MSI malicioso se ejecuta como SYSTEM",
     "windows", "Registry"),
    ("reg query HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
     "Buscar DefaultPassword en Winlogon — AutoLogon con contraseña en claro",
     "windows", "Registry"),
    ("wmic service get name,startname,pathname,startmode | findstr /i \"auto\"",
     "Servicios en autostart con ruta y usuario que los ejecuta",
     "windows", "Services"),
    ("sc qc <servicio>",
     "Detalles de un servicio específico: binpath, usuario, permisos",
     "windows", "Services"),
    ("icacls \"C:\\Program Files\" /findsid Everyone /t 2>nul | findstr \"(W)\\|(F)\\|(M)\"",
     "Directorios de Program Files escribibles por Everyone (DLL hijacking / binary planting)",
     "windows", "File Permissions"),
    ("systeminfo | findstr /i \"os name\\|os version\\|hotfix\"",
     "Versión exacta del SO y hotfixes instalados — buscar CVEs en exploit-db",
     "windows", "Kernel Exploits"),
    ("dir /s /b C:\\*.config C:\\*.xml C:\\*.ini C:\\*password* 2>nul | findstr /i \"pass\\|cred\\|secret\"",
     "Buscar ficheros con contraseñas hardcodeadas en disco",
     "windows", "Credentials"),
    ("cmdkey /list",
     "Credenciales almacenadas en Windows Credential Manager",
     "windows", "Credentials"),
    ("reg query HKCU\\Software\\SimonTatham\\PuTTY\\Sessions /s",
     "Sesiones PuTTY guardadas — pueden contener contraseñas y claves privadas",
     "windows", "Credentials"),
]


def _seed_privesc(_=None):
    """Insert PrivEsc cheatsheet commands (INSERT OR IGNORE via upsert logic)."""
    from database import SessionLocal
    db = SessionLocal()
    try:
        inserted = 0
        for cmd_text, desc, os_val, category in PRIVESC_COMMANDS:
            existing = db.query(Command).filter(
                Command.command == cmd_text,
                Command.category == "privesc",
            ).first()
            if not existing:
                c = Command(
                    command=cmd_text,
                    description=desc,
                    tool_name="PrivEsc",
                    os=os_val,
                    flags=json.dumps([]),
                    tags=json.dumps(["privesc", category.lower().replace(" & ", "_").replace(" ", "_")]),
                    category="privesc",
                )
                db.add(c)
                inserted += 1
        db.commit()
        if inserted:
            print(f"[seed_privesc] Inserted {inserted} PrivEsc commands")
    except Exception as e:
        db.rollback()
        print(f"[seed_privesc] Error: {e}")
    finally:
        db.close()


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    _migrate_db()
    _seed_google_dorks(None)
    _seed_privesc(None)
    yield


app = FastAPI(title="CyberKB v3", version="3.0.0", lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


# ─── Serve Frontend ────────────────────────────────────────────────────────────

@app.get("/", response_class=FileResponse)
def root():
    return FileResponse(str(BUNDLE_DIR / "index.html"))


# ─── Stats ─────────────────────────────────────────────────────────────────────

@app.get("/api/stats")
def get_stats(db: Session = Depends(get_db)):
    from sqlalchemy import func
    cats = db.query(Note.category, func.count(Note.id)).group_by(Note.category).all()
    return {
        "total_notes": db.query(Note).count(),
        "total_commands": db.query(Command).count(),
        "total_tools": db.query(Tool).count(),
        "total_cves": db.query(CVE).count(),
        "categories": {c: n for c, n in cats},
    }


# ─── Notes ─────────────────────────────────────────────────────────────────────

app.include_router(notes_router)

# ─── Analyze & Upload ──────────────────────────────────────────────────────────

app.include_router(analyze_router)

# ─── Tools ─────────────────────────────────────────────────────────────────────

app.include_router(tools_router)

# ─── Commands ──────────────────────────────────────────────────────────────────
# ─── Commands OS filter ────────────────────────────────────────────────────────

app.include_router(commands_router)

# ─── Graph Entities ────────────────────────────────────────────────────────────

app.include_router(graph_router)

# ─── CVEs ──────────────────────────────────────────────────────────────────────

app.include_router(cves_router)

# ─── Chat ──────────────────────────────────────────────────────────────────────
# ─── Search ────────────────────────────────────────────────────────────────────
# ─── Export / Import ──────────────────────────────────────────────────────────

app.include_router(chat_router)

# ─── OSINT ─────────────────────────────────────────────────────────────────────

app.include_router(osint_router)

# ─── Settings (API Keys) ──────────────────────────────────────────────────────

app.include_router(settings_router)

# ─── Run ───────────────────────────────────────────────────────────────────────

# ─── Audit Progress ────────────────────────────────────────────────────────────

app.include_router(audits_router)

# ─── MITRE ATT&CK ─────────────────────────────────────────────────────────────

app.include_router(mitre_router)

# ─── Forensic Mode ────────────────────────────────────────────────────────────

app.include_router(forensic_router)

if __name__ == "__main__":
    import multiprocessing
    multiprocessing.freeze_support()   # required for PyInstaller + any subprocess use

    import uvicorn
    import threading
    import webbrowser
    import time

    port = int(os.getenv("PORT", 8000))

    def open_browser():
        time.sleep(2.5)
        webbrowser.open(f"http://localhost:{port}")

    threading.Thread(target=open_browser, daemon=True).start()

    uvicorn.run(
        app,
        host="0.0.0.0",
        port=port,
        reload=False,
        log_level="info",
    )
