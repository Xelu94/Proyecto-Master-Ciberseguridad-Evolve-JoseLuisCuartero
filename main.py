import os
import re
import sys
import json
import shutil
import uuid
from datetime import datetime
from pathlib import Path
from typing import Optional

from contextlib import asynccontextmanager
from fastapi import FastAPI, Depends, HTTPException, UploadFile, File, Form
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from sqlalchemy.orm import Session
from dotenv import load_dotenv

from layers.routers.osint import router as osint_router

# ─── Path resolution (works both as script and PyInstaller exe) ───────────────
def _bundle_dir() -> Path:
    """Where bundled files live (index.html etc.)."""
    if getattr(sys, "frozen", False):
        return Path(sys._MEIPASS)   # PyInstaller temp extraction dir
    return Path(__file__).parent

def _runtime_dir() -> Path:
    """Where user data lives (.env, data/, uploads/) — always next to exe/script."""
    if getattr(sys, "frozen", False):
        return Path(sys.executable).parent
    return Path(__file__).parent

BUNDLE_DIR  = _bundle_dir()
RUNTIME_DIR = _runtime_dir()

load_dotenv(dotenv_path=RUNTIME_DIR / ".env", encoding="utf-8", override=True)

from database import get_db, init_db, engine
from models import Note, Command, Tool, CVE, OsintResult, GraphEntity, EntityRelation, entity_note_map, MitreTechnique
import claude_service as ai
import document_parser as parser
import osint_tools as osint

UPLOAD_DIR = RUNTIME_DIR / os.getenv("UPLOAD_DIR", "uploads")
UPLOAD_DIR.mkdir(exist_ok=True)
(RUNTIME_DIR / "data").mkdir(exist_ok=True)


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

class NoteIn(BaseModel):
    title: str
    content: str
    category: str = "teoria"
    subcategory: Optional[str] = None
    summary: Optional[str] = None
    tags: Optional[list[str]] = None
    source_file: Optional[str] = None


@app.get("/api/notes")
def list_notes(
    search: Optional[str] = None,
    category: Optional[str] = None,
    skip: int = 0,
    limit: int = 200,
    db: Session = Depends(get_db),
):
    q = db.query(Note)
    if category and category != "all":
        q = q.filter(Note.category == category)
    if search:
        q = q.filter(
            Note.title.ilike(f"%{search}%") | Note.content.ilike(f"%{search}%")
        )
    notes = q.order_by(Note.updated_at.desc()).offset(skip).limit(limit).all()
    return [_note_dict(n) for n in notes]


@app.get("/api/notes/{note_id}")
def get_note(note_id: int, db: Session = Depends(get_db)):
    n = db.query(Note).filter(Note.id == note_id).first()
    if not n:
        raise HTTPException(404, "Note not found")
    return _note_dict(n, full=True)


@app.post("/api/notes", status_code=201)
def create_note(data: NoteIn, db: Session = Depends(get_db)):
    n = Note(
        title=data.title,
        content=data.content,
        category=data.category,
        subcategory=data.subcategory,
        summary=data.summary,
        tags=json.dumps(data.tags or []),
        source_file=data.source_file,
    )
    db.add(n)
    db.commit()
    db.refresh(n)
    return _note_dict(n)


@app.put("/api/notes/{note_id}")
def update_note(note_id: int, data: NoteIn, db: Session = Depends(get_db)):
    n = db.query(Note).filter(Note.id == note_id).first()
    if not n:
        raise HTTPException(404, "Note not found")
    n.title = data.title
    n.content = data.content
    n.category = data.category
    n.subcategory = data.subcategory
    n.summary = data.summary
    n.tags = json.dumps(data.tags or [])
    n.updated_at = datetime.utcnow()
    db.commit()
    db.refresh(n)
    return _note_dict(n)


@app.delete("/api/notes/all", status_code=204)
def delete_all_notes(db: Session = Depends(get_db)):
    """Wipe all notes, commands, CVEs, tool-note associations and graph data."""
    from sqlalchemy import text
    db.execute(text("DELETE FROM tool_notes"))
    db.execute(text("DELETE FROM entity_note_map"))
    db.execute(text("DELETE FROM entity_relations"))
    db.execute(text("DELETE FROM graph_entities"))
    db.query(MitreTechnique).delete()
    db.query(CVE).delete()
    db.query(Command).delete()
    db.query(Note).delete()
    db.commit()


@app.delete("/api/notes/{note_id}", status_code=204)
def delete_note(note_id: int, db: Session = Depends(get_db)):
    n = db.query(Note).filter(Note.id == note_id).first()
    if not n:
        raise HTTPException(404, "Note not found")
    db.delete(n)
    db.commit()


def _note_dict(n: Note, full: bool = False) -> dict:
    d = {
        "id": n.id,
        "title": n.title,
        "category": n.category,
        "subcategory": n.subcategory,
        "summary": n.summary,
        "tags": json.loads(n.tags or "[]"),
        "source_file": n.source_file,
        "created_at": n.created_at.isoformat() if n.created_at else None,
        "updated_at": n.updated_at.isoformat() if n.updated_at else None,
    }
    if full:
        d["content"] = n.content
        d["commands"] = [_cmd_dict(c) for c in n.commands]
        d["cves"] = [_cve_dict(c) for c in n.cves]
        d["tools"] = [_tool_dict(t) for t in n.tools]
    return d


# ─── Analyze & Upload ──────────────────────────────────────────────────────────

class AnalyzeIn(BaseModel):
    text: str
    title: Optional[str] = None


@app.post("/api/analyze")
def analyze_text(data: AnalyzeIn, db: Session = Depends(get_db)):
    result = ai.analyze_content(data.text)
    # Persist tools discovered
    _persist_tools(result.get("tools", []), db)
    return result


@app.post("/api/upload")
async def upload_document(
    file: UploadFile = File(...),
    auto_save: bool = Form(False),
    db: Session = Depends(get_db),
):
    ext = Path(file.filename).suffix.lower()
    if ext not in (".pdf", ".odt", ".txt", ".md", ".log"):
        raise HTTPException(400, f"Unsupported file type: {ext}")

    dest = UPLOAD_DIR / f"{uuid.uuid4()}{ext}"
    with open(dest, "wb") as f:
        shutil.copyfileobj(file.file, f)

    text = parser.parse_file(str(dest), file.filename)
    if not text.strip():
        raise HTTPException(422, "No text could be extracted from the file.")

    analysis = ai.analyze_content(text)
    tools = _persist_tools(analysis.get("tools", []), db)

    note_id = None
    if auto_save:
        n = Note(
            title=Path(file.filename).stem,
            content=text[:20000],
            category=analysis.get("category", "teoria"),
            subcategory=analysis.get("subcategory"),
            summary=analysis.get("summary"),
            tags=json.dumps(analysis.get("tags", [])),
            source_file=file.filename,
        )
        db.add(n)
        db.commit()
        db.refresh(n)
        _persist_commands(analysis.get("commands", []), n, db)
        _persist_cves(analysis.get("cves", []), n, db)
        _persist_mitre(analysis.get("mitre_techniques", []), n, db)
        for t in tools:
            if t not in n.tools:
                n.tools.append(t)
        db.commit()
        # Extract graph entities asynchronously (best-effort)
        try:
            ent_result = ai.extract_entities(text[:6000])
            _persist_entities(ent_result.get("entities", []), ent_result.get("relations", []), n, db)
        except Exception as _e:
            pass  # entity extraction failure must not break upload
        note_id = n.id

    return {
        "filename": file.filename,
        "text_length": len(text),
        "analysis": analysis,
        "note_id": note_id,
    }


def _persist_tools(tools_data: list, db: Session) -> list:
    result = []
    for td in tools_data:
        name = td.get("name", "").strip()
        if not name:
            continue
        t = db.query(Tool).filter(Tool.name.ilike(name)).first()
        if t:
            t.mention_count = (t.mention_count or 0) + 1
            if not t.url and td.get("url"):
                t.url = td["url"]
            if not t.description and td.get("description"):
                t.description = td["description"]
        else:
            url = td.get("url")
            if not url:
                name_lower = name.lower()
                url = ai.KNOWN_TOOLS.get(name_lower)
            t = Tool(
                name=name,
                url=url,
                description=td.get("description"),
                tool_type=td.get("tool_type", ai.detect_tool_type(name)),
                mention_count=1,
            )
            db.add(t)
        db.commit()
        db.refresh(t)
        result.append(t)
    return result


def _persist_commands(cmds: list, note: Note, db: Session):
    for cd in cmds:
        cmd_str = cd.get("command", "").strip()
        if not cmd_str:
            continue
        detected_os = cd.get("os") or ai.detect_command_os(cmd_str)
        c = Command(
            command=cmd_str,
            description=cd.get("description"),
            tool_name=cd.get("tool"),
            os=detected_os,
            flags=json.dumps(cd.get("flags", [])),
            note_id=note.id,
        )
        db.add(c)
    db.commit()


def _persist_cves(cves: list, note: Note, db: Session):
    for cd in cves:
        cve_id = cd.get("id", "").strip()
        if not cve_id:
            continue
        existing = db.query(CVE).filter(CVE.cve_id == cve_id).first()
        if not existing:
            c = CVE(
                cve_id=cve_id,
                description=cd.get("description"),
                note_id=note.id,
            )
            db.add(c)
    db.commit()


def _persist_mitre(techniques: list, note: Note, db: Session):
    """Upsert MITRE ATT&CK techniques extracted from a note."""
    for td in techniques:
        tid = td.get("id", "").strip()
        if not tid:
            continue
        existing = db.query(MitreTechnique).filter(
            MitreTechnique.technique_id == tid,
            MitreTechnique.note_id == note.id
        ).first()
        if not existing:
            mt = MitreTechnique(
                note_id=note.id,
                technique_id=tid,
                technique_name=td.get("name"),
                tactic=td.get("tactic"),
                context_snippet=td.get("snippet"),
            )
            db.add(mt)
    db.commit()


# ─── Tools ─────────────────────────────────────────────────────────────────────

@app.get("/api/tools")
def list_tools(db: Session = Depends(get_db)):
    tools = db.query(Tool).order_by(Tool.mention_count.desc()).all()
    return [_tool_dict(t) for t in tools]


@app.get("/api/tools/{tool_id}")
def get_tool(tool_id: int, db: Session = Depends(get_db)):
    t = db.query(Tool).filter(Tool.id == tool_id).first()
    if not t:
        raise HTTPException(404, "Tool not found")
    d = _tool_dict(t)
    d["notes"] = [{"id": n.id, "title": n.title, "category": n.category} for n in t.notes]
    d["commands"] = [_cmd_dict(c) for c in db.query(Command).filter(Command.tool_name.ilike(t.name)).all()]
    return d


class ToolUpdate(BaseModel):
    url: Optional[str] = None
    description: Optional[str] = None
    category: Optional[str] = None
    use_cases: Optional[list[str]] = None
    requires_api: Optional[bool] = None
    api_info: Optional[str] = None


@app.put("/api/tools/{tool_id}")
def update_tool(tool_id: int, data: ToolUpdate, db: Session = Depends(get_db)):
    t = db.query(Tool).filter(Tool.id == tool_id).first()
    if not t:
        raise HTTPException(404, "Tool not found")
    if data.url is not None:
        t.url = data.url
    if data.description is not None:
        t.description = data.description
    if data.category is not None:
        t.category = data.category
    if data.use_cases is not None:
        t.use_cases = json.dumps(data.use_cases)
    if data.requires_api is not None:
        t.requires_api = data.requires_api
    if data.api_info is not None:
        t.api_info = data.api_info
    db.commit()
    db.refresh(t)
    return _tool_dict(t)


def _tool_dict(t: Tool) -> dict:
    return {
        "id": t.id,
        "name": t.name,
        "url": t.url,
        "description": t.description,
        "category": t.category,
        "tool_type": t.tool_type or "software",
        "use_cases": json.loads(t.use_cases or "[]"),
        "tags": json.loads(t.tags or "[]"),
        "requires_api": t.requires_api,
        "api_info": t.api_info,
        "mention_count": t.mention_count,
        "created_at": t.created_at.isoformat() if t.created_at else None,
    }


# ─── Commands ──────────────────────────────────────────────────────────────────

@app.post("/api/commands/cheatsheet")
def gen_cheatsheet(tool_name: str, db: Session = Depends(get_db)):
    cmds = db.query(Command).filter(Command.tool_name.ilike(f"%{tool_name}%")).all()
    result = ai.generate_cheatsheet(tool_name, [_cmd_dict(c) for c in cmds])
    return {"tool": tool_name, "cheatsheet": result}


def _cmd_dict(c: Command) -> dict:
    return {
        "id": c.id,
        "command": c.command,
        "description": c.description,
        "tool_name": c.tool_name,
        "os": c.os or "linux",
        "flags": json.loads(c.flags or "[]"),
        "examples": json.loads(c.examples or "[]"),
        "tags": json.loads(c.tags or "[]"),
        "category": c.category,
        "note_id": c.note_id,
    }


# ─── Graph Entities ────────────────────────────────────────────────────────────

def _persist_entities(entities_data: list, relations_data: list, note: Note, db: Session):
    """Upsert extracted entities into DB and link them to a note."""
    from sqlalchemy import text as sqlt, select as sqsel

    entity_map: dict[str, GraphEntity] = {}  # normalized_name -> obj

    for ed in entities_data:
        name = ed.get("name", "").strip()[:200]
        if not name:
            continue
        etype = ed.get("type", "concept")
        if etype not in ai.VALID_ENTITY_TYPES:
            etype = "concept"

        existing = db.query(GraphEntity).filter(
            GraphEntity.name.ilike(name)
        ).first()
        if existing:
            existing.frequency = (existing.frequency or 1) + 1
            if not existing.description and ed.get("description"):
                existing.description = ed["description"]
            obj = existing
        else:
            obj = GraphEntity(
                name=name,
                entity_type=etype,
                description=ed.get("description"),
                frequency=1,
            )
            db.add(obj)

        db.flush()

        # Link to note (ignore duplicate)
        try:
            db.execute(sqlt(
                "INSERT OR IGNORE INTO entity_note_map (entity_id, note_id) VALUES (:eid, :nid)"
            ), {"eid": obj.id, "nid": note.id})
        except Exception:
            pass

        entity_map[name.lower()] = obj

    db.commit()

    # Persist co-occurrence relations
    for pair in relations_data:
        if len(pair) != 2:
            continue
        obj_a = entity_map.get(pair[0].strip().lower())
        obj_b = entity_map.get(pair[1].strip().lower())
        if not obj_a or not obj_b or obj_a.id == obj_b.id:
            continue
        id_a, id_b = min(obj_a.id, obj_b.id), max(obj_a.id, obj_b.id)
        try:
            db.execute(sqlt("""
                INSERT INTO entity_relations (entity_a_id, entity_b_id, weight)
                VALUES (:a, :b, 1)
                ON CONFLICT(entity_a_id, entity_b_id) DO UPDATE SET weight = weight + 1
            """), {"a": id_a, "b": id_b})
        except Exception:
            pass
    db.commit()


@app.get("/api/graph")
def get_graph(db: Session = Depends(get_db)):
    from sqlalchemy import select as sqsel

    entities = (
        db.query(GraphEntity)
        .order_by(GraphEntity.frequency.desc())
        .limit(120)
        .all()
    )
    if not entities:
        return {"nodes": [], "edges": []}

    entity_ids = [e.id for e in entities]

    # Bulk-fetch entity→note mappings
    enm_rows = db.execute(
        sqsel(entity_note_map).where(entity_note_map.c.entity_id.in_(entity_ids))
    ).fetchall()
    note_map: dict[int, list[int]] = {}
    for row in enm_rows:
        note_map.setdefault(row.entity_id, []).append(row.note_id)

    # Fetch note titles
    all_note_ids = list({nid for nids in note_map.values() for nid in nids})
    note_titles: dict[int, str] = {}
    if all_note_ids:
        for n in db.query(Note.id, Note.title).filter(Note.id.in_(all_note_ids)).all():
            note_titles[n.id] = n.title

    nodes = []
    for e in entities:
        note_ids = note_map.get(e.id, [])
        nodes.append({
            "id": e.id,
            "name": e.name,
            "type": e.entity_type,
            "description": e.description,
            "frequency": e.frequency,
            "notes": [{"id": nid, "title": note_titles.get(nid, "?")} for nid in note_ids],
        })

    rels = db.query(EntityRelation).filter(
        EntityRelation.entity_a_id.in_(entity_ids),
        EntityRelation.entity_b_id.in_(entity_ids),
    ).all()

    return {
        "nodes": nodes,
        "edges": [{"a": r.entity_a_id, "b": r.entity_b_id, "weight": r.weight} for r in rels],
    }


@app.post("/api/notes/{note_id}/extract")
def extract_note_entities(note_id: int, db: Session = Depends(get_db)):
    """Re-extract graph entities from an existing note."""
    n = db.query(Note).filter(Note.id == note_id).first()
    if not n:
        raise HTTPException(404, "Note not found")
    result = ai.extract_entities(n.content[:6000])
    _persist_entities(result.get("entities", []), result.get("relations", []), n, db)
    return {"extracted": len(result.get("entities", []))}


@app.post("/api/graph/reindex-all")
def reindex_all_entities(db: Session = Depends(get_db)):
    """Clear all graph data and re-extract entities from every note using Claude AI."""
    from sqlalchemy import text
    # Wipe existing graph data
    db.execute(text("DELETE FROM entity_note_map"))
    db.execute(text("DELETE FROM entity_relations"))
    db.execute(text("DELETE FROM graph_entities"))
    db.commit()

    notes = db.query(Note).all()
    total_entities = 0
    errors = 0
    for n in notes:
        try:
            result = ai.extract_entities(n.content[:6000])
            entities = result.get("entities", [])
            _persist_entities(entities, result.get("relations", []), n, db)
            total_entities += len(entities)
        except Exception as e:
            errors += 1
            print(f"[reindex] Note {n.id} failed: {e}")

    return {"notes_processed": len(notes), "entities_extracted": total_entities, "errors": errors}


# ─── CVEs ──────────────────────────────────────────────────────────────────────

@app.get("/api/cves")
def list_cves(db: Session = Depends(get_db)):
    cves = db.query(CVE).order_by(CVE.created_at.desc()).all()
    return [_cve_dict(c) for c in cves]


@app.get("/api/cves/{cve_id}/exploits")
async def cve_exploits(cve_id: str):
    """Query Exploit-DB for public exploits for a given CVE."""
    import httpx
    # Strip 'CVE-' prefix for the search query
    cve_num = re.sub(r"^CVE-", "", cve_id.strip(), flags=re.IGNORECASE)
    try:
        headers = {
            "User-Agent": "CyberKB/3.0",
            "X-Requested-With": "XMLHttpRequest",
            "Accept": "application/json, text/javascript, */*; q=0.01",
            "Referer": "https://www.exploit-db.com/search",
        }
        async with httpx.AsyncClient(timeout=15, headers=headers) as client:
            r = await client.get(
                "https://www.exploit-db.com/search",
                params={
                    "action": "search",
                    "cve": cve_num,
                    "draw": "1",
                    "columns[0][data]": "id",
                    "columns[1][data]": "date_published",
                    "columns[2][data]": "title",
                    "columns[3][data]": "type",
                    "columns[4][data]": "platform",
                    "columns[5][data]": "verified",
                    "order[0][column]": "1",
                    "order[0][dir]": "desc",
                    "start": "0",
                    "length": "10",
                },
            )
        if r.status_code != 200:
            return {"cve_id": cve_id, "count": 0, "exploits": [], "error": f"EDB HTTP {r.status_code}"}
        data = r.json()
        rows = data.get("data", [])
        exploits = []
        for row in rows[:10]:
            eid = row.get("id", "")
            exploits.append({
                "id":       eid,
                "title":    row.get("description_cut", row.get("title", "")),
                "date":     row.get("date_published", row.get("date", ""))[:10] if row.get("date_published") or row.get("date") else "",
                "type":     row.get("type", {}).get("name", "") if isinstance(row.get("type"), dict) else str(row.get("type", "")),
                "platform": row.get("platform", {}).get("name", "") if isinstance(row.get("platform"), dict) else str(row.get("platform", "")),
                "url":      f"https://www.exploit-db.com/exploits/{eid}" if eid else "",
                "verified": bool(row.get("verified")),
            })
        return {"cve_id": cve_id, "count": len(exploits), "exploits": exploits}
    except Exception as e:
        return {"cve_id": cve_id, "count": 0, "exploits": [], "error": str(e)}


def _cve_dict(c: CVE) -> dict:
    return {
        "id": c.id,
        "cve_id": c.cve_id,
        "title": c.title,
        "description": c.description,
        "severity": c.severity,
        "cvss": c.cvss,
        "note_id": c.note_id,
    }


# ─── Chat ──────────────────────────────────────────────────────────────────────

class ChatIn(BaseModel):
    question: str


@app.post("/api/chat")
def chat(data: ChatIn, db: Session = Depends(get_db)):
    from sqlalchemy import func
    notes = db.query(Note).order_by(Note.updated_at.desc()).limit(20).all()
    answer = ai.chat_with_context(data.question, [_note_dict(n) for n in notes])
    return {"answer": answer}


# ─── Search ────────────────────────────────────────────────────────────────────

@app.get("/api/search")
def global_search(q: str, db: Session = Depends(get_db)):
    notes = db.query(Note).filter(
        Note.title.ilike(f"%{q}%") | Note.content.ilike(f"%{q}%")
    ).limit(20).all()
    cmds = db.query(Command).filter(
        Command.command.ilike(f"%{q}%") | Command.description.ilike(f"%{q}%")
    ).limit(10).all()
    tools = db.query(Tool).filter(Tool.name.ilike(f"%{q}%")).limit(10).all()
    return {
        "notes": [_note_dict(n) for n in notes],
        "commands": [_cmd_dict(c) for c in cmds],
        "tools": [_tool_dict(t) for t in tools],
    }


# ─── Export / Import ──────────────────────────────────────────────────────────

@app.get("/api/export")
def export_all(db: Session = Depends(get_db)):
    notes = db.query(Note).all()
    tools = db.query(Tool).all()
    commands = db.query(Command).all()
    cves = db.query(CVE).all()
    return {
        "export_date": datetime.utcnow().isoformat(),
        "version": "3.0",
        "notes": [_note_dict(n, full=True) for n in notes],
        "tools": [_tool_dict(t) for t in tools],
        "commands": [_cmd_dict(c) for c in commands],
        "cves": [_cve_dict(c) for c in cves],
    }


# ─── OSINT ─────────────────────────────────────────────────────────────────────

app.include_router(osint_router)

# ─── Settings (API Keys) ──────────────────────────────────────────────────────

SETTINGS_KEYS = [
    "ANTHROPIC_API_KEY",
    "VIRUSTOTAL_API_KEY",
    "ABUSEIPDB_API_KEY",
    "MALWAREBAZAAR_API_KEY",
    "HUNTER_API_KEY",
    "SHODAN_API_KEY",
    "URLSCAN_API_KEY",
    "HIBP_API_KEY",
    "LEAKRADAR_API_KEY",
    "ANYRUN_API_KEY",
]


def _mask(val: str) -> str:
    if not val:
        return ""
    if len(val) <= 8:
        return "*" * len(val)
    return val[:4] + "*" * (len(val) - 8) + val[-4:]


def _read_env_file() -> dict:
    env_path = RUNTIME_DIR / ".env"
    pairs = {}
    if env_path.exists():
        for line in env_path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, _, v = line.partition("=")
                pairs[k.strip()] = v.strip()
    return pairs


def _write_env_file(pairs: dict):
    env_path = RUNTIME_DIR / ".env"
    # Read existing lines to preserve comments/order
    existing_lines = []
    if env_path.exists():
        existing_lines = env_path.read_text(encoding="utf-8").splitlines()

    written = set()
    new_lines = []
    for line in existing_lines:
        stripped = line.strip()
        if stripped and not stripped.startswith("#") and "=" in stripped:
            k = stripped.partition("=")[0].strip()
            if k in pairs:
                new_lines.append(f"{k}={pairs[k]}")
                written.add(k)
                continue
        new_lines.append(line)

    # Append any new keys not already in file
    for k, v in pairs.items():
        if k not in written:
            new_lines.append(f"{k}={v}")

    env_path.write_text("\n".join(new_lines) + "\n", encoding="utf-8")


@app.get("/api/settings")
def get_settings():
    pairs = _read_env_file()
    result = {}
    for k in SETTINGS_KEYS:
        val = pairs.get(k, "")
        result[k] = {"masked": _mask(val), "set": bool(val)}
    return result


class SettingsIn(BaseModel):
    keys: dict[str, str]


@app.post("/api/settings")
def save_settings(data: SettingsIn):
    # Only allow whitelisted keys
    filtered = {k: v for k, v in data.keys.items() if k in SETTINGS_KEYS}
    if not filtered:
        raise HTTPException(400, "No valid keys provided")

    _write_env_file(filtered)

    # Reload into current process environment + dependent modules
    load_dotenv(dotenv_path=RUNTIME_DIR / ".env", encoding="utf-8", override=True)
    import claude_service as _ai
    import osint_tools as _osint
    _ai.client = None  # force re-init on next call
    # Reload API keys in osint module
    for k in filtered:
        val = os.getenv(k, "")
        if k == "SHODAN_API_KEY":
            _osint.SHODAN_KEY = val
        elif k == "VIRUSTOTAL_API_KEY":
            _osint.VT_KEY = val
        elif k == "HUNTER_API_KEY":
            _osint.HUNTER_KEY = val
        elif k == "URLSCAN_API_KEY":
            _osint.URLSCAN_KEY = val
        elif k == "ABUSEIPDB_API_KEY":
            _osint.ABUSEIPDB_KEY = val
        elif k == "MALWAREBAZAAR_API_KEY":
            _osint.MALWAREBAZAAR_KEY = val
        elif k == "HIBP_API_KEY":
            _osint.HIBP_KEY = val
        elif k == "LEAKRADAR_API_KEY":
            _osint.LEAKRADAR_KEY = val
        elif k == "ANYRUN_API_KEY":
            _osint.ANYRUN_KEY = val

    return {"saved": list(filtered.keys())}


# ─── Run ───────────────────────────────────────────────────────────────────────

# ─── Audit Progress ────────────────────────────────────────────────────────────

from models import AuditProgress


@app.get("/api/audit/{audit_type}/progress")
def get_audit_progress(audit_type: str, db: Session = Depends(get_db)):
    rows = db.query(AuditProgress).filter(AuditProgress.audit_type == audit_type).all()
    return {r.item_id: {"done": r.done, "notes": r.notes} for r in rows}


class AuditItemIn(BaseModel):
    done: bool
    notes: Optional[str] = None


@app.post("/api/audit/{audit_type}/item/{item_id}")
def set_audit_item(audit_type: str, item_id: str, data: AuditItemIn, db: Session = Depends(get_db)):
    row = db.query(AuditProgress).filter(
        AuditProgress.audit_type == audit_type,
        AuditProgress.item_id == item_id,
    ).first()
    if row:
        row.done = data.done
        row.notes = data.notes
        row.updated_at = datetime.utcnow()
    else:
        row = AuditProgress(audit_type=audit_type, item_id=item_id, done=data.done, notes=data.notes)
        db.add(row)
    db.commit()
    return {"ok": True}


@app.delete("/api/audit/{audit_type}/reset")
def reset_audit(audit_type: str, db: Session = Depends(get_db)):
    db.query(AuditProgress).filter(AuditProgress.audit_type == audit_type).delete()
    db.commit()
    return {"ok": True}


@app.get("/api/audit/all/summary")
def audit_summary(db: Session = Depends(get_db)):
    from sqlalchemy import func
    from sqlalchemy import Integer as SAInt
    rows = db.query(AuditProgress.audit_type, func.count(AuditProgress.id), func.sum(AuditProgress.done.cast(SAInt))).group_by(AuditProgress.audit_type).all()
    return {r[0]: {"total_done": int(r[2] or 0), "total_checked": r[1]} for r in rows}


class ReportItem(BaseModel):
    id: str
    text: str
    done: bool
    notes: Optional[str] = None
    severity: Optional[str] = None


class ReportRequest(BaseModel):
    audit_type: str
    audit_name: str
    items: list[ReportItem]
    progress: int


@app.post("/api/audit/generate-report")
async def generate_report(req: ReportRequest):
    if not req.items:
        raise HTTPException(400, "No items provided")
    result = ai.generate_audit_report(
        audit_type=req.audit_name,
        items=[i.model_dump() for i in req.items],
        progress=req.progress,
    )
    return result


# ─── Commands OS filter ────────────────────────────────────────────────────────

class CommandIn(BaseModel):
    command: str
    description: Optional[str] = None
    tool_name: Optional[str] = None
    os: str = "linux"
    category: Optional[str] = None
    tags: Optional[list[str]] = None


@app.post("/api/commands", status_code=201)
def create_command(data: CommandIn, db: Session = Depends(get_db)):
    """Create a single command directly (e.g. from Enum/WebVuln 'Save to KB' button).

    INSERT OR IGNORE semantics: if an identical command already exists in the same
    category, return it instead of creating a duplicate.
    """
    existing = (
        db.query(Command)
        .filter(Command.command == data.command, Command.category == data.category)
        .first()
    )
    if existing:
        return _cmd_dict(existing)

    c = Command(
        command=data.command,
        description=data.description,
        tool_name=data.tool_name,
        os=data.os,
        category=data.category,
        tags=json.dumps(data.tags or []),
        flags="[]",
        examples="[]",
    )
    db.add(c)
    db.commit()
    db.refresh(c)
    return _cmd_dict(c)


@app.get("/api/commands")
def list_commands(
    search: Optional[str] = None,
    tool: Optional[str] = None,
    os: Optional[str] = None,
    db: Session = Depends(get_db),
):
    q = db.query(Command)
    if tool:
        q = q.filter(Command.tool_name.ilike(f"%{tool}%"))
    if os and os != "all":
        q = q.filter((Command.os == os) | (Command.os == "both"))
    if search:
        q = q.filter(Command.command.ilike(f"%{search}%") | Command.description.ilike(f"%{search}%"))
    cmds = q.order_by(Command.created_at.desc()).limit(500).all()
    return [_cmd_dict(c) for c in cmds]


# ─── MITRE ATT&CK ─────────────────────────────────────────────────────────────

@app.get("/api/mitre")
def list_mitre(db: Session = Depends(get_db)):
    """Return all MITRE techniques grouped by tactic."""
    rows = db.query(MitreTechnique).order_by(MitreTechnique.tactic, MitreTechnique.technique_id).all()
    grouped: dict = {}
    for r in rows:
        tactic = r.tactic or "Uncategorized"
        grouped.setdefault(tactic, []).append({
            "id": r.id,
            "technique_id": r.technique_id,
            "technique_name": r.technique_name,
            "tactic": r.tactic,
            "context_snippet": r.context_snippet,
            "note_id": r.note_id,
        })
    return {"tactics": grouped, "total": len(rows)}


@app.get("/api/mitre/search")
def search_mitre(q: str = "", db: Session = Depends(get_db)):
    """Search MITRE techniques by ID, name or tactic."""
    query = db.query(MitreTechnique)
    if q:
        like = f"%{q}%"
        query = query.filter(
            MitreTechnique.technique_id.ilike(like) |
            MitreTechnique.technique_name.ilike(like) |
            MitreTechnique.tactic.ilike(like) |
            MitreTechnique.context_snippet.ilike(like)
        )
    rows = query.order_by(MitreTechnique.tactic, MitreTechnique.technique_id).limit(200).all()
    return [
        {
            "id": r.id,
            "technique_id": r.technique_id,
            "technique_name": r.technique_name,
            "tactic": r.tactic,
            "context_snippet": r.context_snippet,
            "note_id": r.note_id,
        }
        for r in rows
    ]


# ─── Forensic Mode ────────────────────────────────────────────────────────────

@app.post("/api/forensic/analyze")
async def forensic_analyze(hash: str, db: Session = Depends(get_db)):
    """Full forensic pipeline: VT + MalwareBazaar (parallel) → Any.run (conditional) → AI note."""
    import asyncio

    hash_str = hash.strip().lower()
    if len(hash_str) != 64 or not re.match(r"^[0-9a-f]{64}$", hash_str):
        raise HTTPException(400, "Se requiere hash SHA256 (64 caracteres hexadecimales)")

    # ── Step 1+2: VT + MalwareBazaar in parallel ──────────────────────────────
    vt_task  = osint.hash_vt(hash_str)
    mb_task  = osint.hash_malwarebazaar(hash_str)
    vt_data, mb_data = await asyncio.gather(vt_task, mb_task)

    # ── Step 3: Any.run if VT detections > 5 ─────────────────────────────────
    anyrun_data: dict = {"note": "No consultado (score VT ≤ 5 o error)"}
    vt_detected = vt_data.get("detected", 0) if not vt_data.get("error") else 0
    if vt_detected > 5:
        anyrun_data = await osint.anyrun_lookup(hash_str)

    # ── Step 4: AI synthesis ──────────────────────────────────────────────────
    note_data = ai.generate_forensic_note(hash_str, vt_data, mb_data, anyrun_data)

    # ── Step 5: Persist note ──────────────────────────────────────────────────
    from datetime import date as _date
    title = note_data.get("title") or f"Análisis forense — {hash_str[:16]}"
    content_body = note_data.get("content", "")

    # Prepend timeline block to content
    tl = note_data.get("timeline", {})
    tl_items = [
        ("Creación malware",   tl.get("created", "")),
        ("Primera subida VT",  tl.get("first_submission", "")),
        ("Primera vez in-wild",tl.get("first_seen_itw", "")),
        ("Último análisis",    tl.get("last_analysis", "")),
    ]
    tl_md = "\n".join(f"- **{label}**: {val}" for label, val in tl_items if val)
    if tl_md:
        content_body = f"## Timeline\n{tl_md}\n\n" + content_body

    # Include raw hash at top
    content_body = f"**SHA256**: `{hash_str}`\n\n" + content_body

    tags = note_data.get("tags", [])
    tags_json = json.dumps(list(set(["forense", "malware"] + tags)))

    n = Note(
        title=title,
        content=content_body[:20000],
        category="forense",
        subcategory="malware-analysis",
        summary=note_data.get("summary") or title,
        tags=tags_json,
        source_file=f"forensic:{hash_str[:16]}",
    )
    db.add(n)
    db.commit()
    db.refresh(n)

    # Persist CVEs
    for cve_item in note_data.get("cves", []):
        cve_id = cve_item.get("id", "").strip()
        if not cve_id:
            continue
        if not db.query(CVE).filter(CVE.cve_id == cve_id).first():
            db.add(CVE(cve_id=cve_id, description=cve_item.get("description"), note_id=n.id))
    db.commit()

    # Persist MITRE techniques
    _persist_mitre(note_data.get("mitre_techniques", []), n, db)

    # Persist graph entities (best-effort)
    try:
        ent = ai.extract_entities(content_body[:6000])
        _persist_entities(ent.get("entities", []), ent.get("relations", []), n, db)
    except Exception:
        pass

    return {
        "note_id":    n.id,
        "title":      title,
        "vt":         vt_data,
        "mb":         mb_data,
        "anyrun":     anyrun_data,
        "timeline":   tl,
        "cves_found": len(note_data.get("cves", [])),
        "mitre_found":len(note_data.get("mitre_techniques", [])),
        "tags":       tags,
    }


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
