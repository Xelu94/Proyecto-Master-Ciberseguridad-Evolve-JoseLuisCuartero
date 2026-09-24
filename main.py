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
    # La relación Tool→Notes en el modelo se llama `tools` (no `notes`); usar el
    # nombre correcto — antes daba 500 al abrir el detalle de cualquier herramienta.
    d["notes"] = [{"id": n.id, "title": n.title, "category": n.category} for n in t.tools]
    d["commands"] = [_cmd_dict(c) for c in db.query(Command).filter(Command.tool_name.ilike(t.name)).all()]
    return d


class ToolUpdate(BaseModel):
    url: Optional[str] = None
    description: Optional[str] = None
    category: Optional[str] = None
    tool_type: Optional[str] = None
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
    if data.tool_type is not None:
        t.tool_type = data.tool_type
    if data.use_cases is not None:
        t.use_cases = json.dumps(data.use_cases)
    if data.requires_api is not None:
        t.requires_api = data.requires_api
    if data.api_info is not None:
        t.api_info = data.api_info
    db.commit()
    db.refresh(t)
    return _tool_dict(t)


# ─── [Módulo Herramientas] Crear / borrar / sembrar catálogo ──────────────────
class ToolCreate(BaseModel):
    name: str
    url: Optional[str] = None
    description: Optional[str] = None
    category: Optional[str] = None
    tool_type: Optional[str] = "software"
    requires_api: Optional[bool] = False
    api_info: Optional[str] = None


@app.post("/api/tools", status_code=201)
def create_tool(data: ToolCreate, db: Session = Depends(get_db)):
    """Crea una herramienta a mano. Si ya existe una con ese nombre, sube su
    contador de menciones en vez de duplicarla (upsert por nombre)."""
    name = (data.name or "").strip()
    if not name:
        raise HTTPException(400, "El nombre es obligatorio")
    existing = db.query(Tool).filter(Tool.name.ilike(name)).first()
    if existing:
        existing.mention_count = (existing.mention_count or 0) + 1
        db.commit()
        db.refresh(existing)
        return {"created": False, **_tool_dict(existing)}
    t = Tool(
        name=name,
        url=data.url or None,
        description=data.description or None,
        category=data.category or None,
        tool_type=data.tool_type or "software",
        requires_api=bool(data.requires_api),
        api_info=data.api_info or None,
        mention_count=1,
    )
    db.add(t)
    db.commit()
    db.refresh(t)
    return {"created": True, **_tool_dict(t)}


@app.delete("/api/tools/{tool_id}", status_code=204)
def delete_tool(tool_id: int, db: Session = Depends(get_db)):
    """Borra una herramienta (p. ej. un falso positivo del análisis por IA)."""
    t = db.query(Tool).filter(Tool.id == tool_id).first()
    if not t:
        raise HTTPException(404, "Tool not found")
    db.delete(t)
    db.commit()
    return


# Catálogo base: herramientas de pentest que aparecen en los módulos de la app.
_TOOLS_SEED = [
    {"name": "nmap",        "category": "enumeracion",      "url": "https://nmap.org",                                   "description": "Escáner de red y puertos: descubre hosts, servicios y versiones."},
    {"name": "netdiscover", "category": "enumeracion",      "url": "https://github.com/netdiscover-scanner/netdiscover", "description": "Descubrimiento de hosts en la red local por ARP."},
    {"name": "arp-scan",    "category": "enumeracion",      "url": "https://github.com/royhills/arp-scan",               "description": "Descubrimiento de hosts por ARP, rápido y directo."},
    {"name": "enum4linux",  "category": "enumeracion",      "url": "https://github.com/CiscoCXSecurity/enum4linux",      "description": "Enumeración de SMB/NetBIOS: usuarios, grupos, recursos compartidos."},
    {"name": "smbclient",   "category": "enumeracion",      "url": "https://www.samba.org",                              "description": "Cliente SMB para listar y acceder a recursos compartidos de Windows."},
    {"name": "dig",         "category": "reconocimiento",   "url": "https://linux.die.net/man/1/dig",                    "description": "Consultas DNS; útil para transferencias de zona (AXFR)."},
    {"name": "dnsrecon",    "category": "reconocimiento",   "url": "https://github.com/darkoperator/dnsrecon",           "description": "Reconocimiento DNS: registros, subdominios y AXFR."},
    {"name": "curl",        "category": "reconocimiento",   "url": "https://curl.se",                                    "description": "Cliente HTTP de línea de comandos; ver cabeceras y probar endpoints."},
    {"name": "hydra",       "category": "explotacion",      "url": "https://github.com/vanhauser-thc/thc-hydra",         "description": "Fuerza bruta de credenciales sobre múltiples protocolos (SSH, RDP, HTTP...)."},
    {"name": "searchsploit","category": "explotacion",      "url": "https://gitlab.com/exploit-database/exploitdb",      "description": "Búsqueda local de exploits de Exploit-DB por producto y versión."},
    {"name": "Metasploit",  "category": "explotacion",      "url": "https://www.metasploit.com",                         "description": "Framework de explotación con módulos de exploits, auxiliares y payloads."},
    {"name": "ffuf",        "category": "web-hacking",      "url": "https://github.com/ffuf/ffuf",                       "description": "Fuzzing web rápido de directorios, ficheros y parámetros."},
    {"name": "gobuster",    "category": "web-hacking",      "url": "https://github.com/OJ/gobuster",                     "description": "Fuerza bruta de directorios, DNS y vhosts."},
    {"name": "nikto",       "category": "web-hacking",      "url": "https://github.com/sullo/nikto",                     "description": "Escáner de vulnerabilidades y malas configuraciones en servidores web."},
    {"name": "sqlmap",      "category": "web-hacking",      "url": "https://sqlmap.org",                                 "description": "Detección y explotación automática de inyección SQL."},
    {"name": "Burp Suite",  "category": "web-hacking",      "url": "https://portswigger.net/burp",                       "description": "Proxy de interceptación para pruebas de aplicaciones web (Repeater, Intruder)."},
    {"name": "Impacket",    "category": "post-explotacion", "url": "https://github.com/fortra/impacket",                 "description": "Herramientas Python para protocolos Windows (psexec, secretsdump, mssqlclient)."},
    {"name": "xfreerdp",    "category": "post-explotacion", "url": "https://www.freerdp.com",                            "description": "Cliente RDP para Linux; conexión a escritorios remotos de Windows."},
]


@app.post("/api/tools/seed")
def toggle_seed_tools(db: Session = Depends(get_db)):
    """Toggle del catálogo base de pentest:
      - si NO está cargado → añade las herramientas del catálogo (etiquetadas
        con 'catalogo-base' para poder distinguirlas luego).
      - si YA está cargado → borra solo esas (las que llevan la etiqueta).
    Las herramientas metidas a mano o detectadas en notas NO se tocan, porque
    no llevan la etiqueta 'catalogo-base'. Devuelve action='added'|'removed'.
    """
    seeded = [t for t in db.query(Tool).all()
              if "catalogo-base" in json.loads(t.tags or "[]")]
    if seeded:
        for t in seeded:
            db.delete(t)
        db.commit()
        return {"action": "removed", "count": len(seeded)}

    added = 0
    for td in _TOOLS_SEED:
        # No pisamos una que ya exista con ese nombre (manual o de nota)
        if db.query(Tool).filter(Tool.name.ilike(td["name"])).first():
            continue
        db.add(Tool(
            name=td["name"], url=td.get("url"), description=td.get("description"),
            category=td.get("category"), tool_type=td.get("tool_type", "software"),
            requires_api=False, mention_count=1,
            tags=json.dumps(["catalogo-base"]),
        ))
        added += 1
    db.commit()
    return {"action": "added", "count": added}


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


# ─── Exploit-DB (compartido por módulos CVEs y Enumeración) ───────────────────
_EDB_HEADERS = {
    "User-Agent": "CyberKB/3.0",
    "X-Requested-With": "XMLHttpRequest",
    "Accept": "application/json, text/javascript, */*; q=0.01",
    "Referer": "https://www.exploit-db.com/search",
}


async def _edb_search(extra_params: dict, limit: int = 15):
    """Consulta la búsqueda JSON (formato DataTables) de Exploit-DB y devuelve
    (exploits, error). Lo usan tanto el buscador por CVE (módulo CVEs) como el
    buscador por versión (módulo Enumeración); solo cambian los `extra_params`
    ('cve' o 'q'). El mapeo de la fila cruda de EDB es común a los dos.
    """
    import httpx
    import asyncio
    params = {
        "action": "search", "draw": "1",
        "columns[0][data]": "id", "columns[1][data]": "date_published",
        "columns[2][data]": "title", "columns[3][data]": "type",
        "columns[4][data]": "platform", "columns[5][data]": "verified",
        "order[0][column]": "1", "order[0][dir]": "desc",
        "start": "0", "length": str(limit),
        **extra_params,
    }
    # Exploit-DB va detrás de Cloudflare y responde lento/intermitente (502, 429,
    # timeouts). Un reintento absorbe la mayoría de los fallos transitorios.
    last_err = None
    for attempt in range(2):
        try:
            async with httpx.AsyncClient(timeout=20, headers=_EDB_HEADERS) as client:
                r = await client.get("https://www.exploit-db.com/search", params=params)
            if r.status_code == 200:
                return _edb_map(r.json().get("data", []), limit), None
            last_err = f"Exploit-DB devolvió HTTP {r.status_code}"
        except Exception as e:
            last_err = str(e)
        if attempt == 0:
            await asyncio.sleep(1.2)
    return [], last_err


def _edb_map(rows: list, limit: int) -> list:
    """Normaliza las filas crudas de Exploit-DB al objeto que devolvemos.

    El JSON de EDB usa nombres de campo poco intuitivos (viene de un DataTables):
      - el título está en description[1]  (description = ["id", "título"])
      - la plataforma en platform_id      (o platform.platform si es dict)
      - el tipo en type_id                (o type.name)
      - el CVE, dentro de la lista code[]  (y a veces trae códigos que NO son CVE)
    Por eso el mapeo tiene tantos .get() con alternativas.
    """
    exploits = []
    for row in rows[:limit]:
        eid = row.get("id", "")
        desc = row.get("description")
        title = desc[1] if isinstance(desc, list) and len(desc) > 1 else (row.get("title") or "")
        platform = row.get("platform_id") or (
            row.get("platform", {}).get("platform", "") if isinstance(row.get("platform"), dict) else "")
        typ = row.get("type_id") or (
            row.get("type", {}).get("name", "") if isinstance(row.get("type"), dict) else "")
        cve = ""
        code = row.get("code")
        if isinstance(code, list) and code and isinstance(code[0], dict):
            c0 = code[0].get("code", "")
            # Solo lo tratamos como CVE si tiene forma AAAA-NNNN (el campo también
            # trae otros identificadores, p. ej. de Metasploit)
            if re.match(r"^\d{4}-\d{3,}$", c0):
                cve = "CVE-" + c0
        exploits.append({
            "id": eid, "title": title, "date": (row.get("date_published") or "")[:10],
            "type": typ, "platform": platform, "cve": cve,
            "url": f"https://www.exploit-db.com/exploits/{eid}" if eid else "",
            "verified": bool(row.get("verified")),
        })
    return exploits


@app.get("/api/cves/{cve_id}/exploits")
async def cve_exploits(cve_id: str):
    """Exploits públicos en Exploit-DB para un CVE concreto (búsqueda por ID)."""
    cve_num = re.sub(r"^CVE-", "", cve_id.strip(), flags=re.IGNORECASE)
    exploits, error = await _edb_search({"cve": cve_num}, limit=10)
    res = {"cve_id": cve_id, "count": len(exploits), "exploits": exploits}
    if error:
        res["error"] = error
    return res


@app.get("/api/exploit-search")
async def exploit_search(q: str):
    """[Módulo de Enumeración] Busca exploits públicos por producto + versión.

    Da servicio al buscador «Versión → ¿exploit conocido?» de la pestaña ③
    Enumerar servicios: resuelve el paso "tengo una versión detectada en el
    escaneo, ¿existe exploit público?". Consulta en vivo la búsqueda de
    Exploit-DB (exploit-db.com, sin API key) y devuelve, por cada resultado,
    título, tipo, plataforma, fecha, CVE (si lo tiene) y enlace. Es el gemelo
    por texto de GET /api/cves/{cve_id}/exploits, que busca lo mismo por CVE.
    """
    query = (q or "").strip()
    if not query:
        return {"query": q, "count": 0, "exploits": []}
    exploits, error = await _edb_search({"q": query}, limit=15)
    res = {"query": query, "count": len(exploits), "exploits": exploits}
    if error:
        res["error"] = error
    return res


# ─── NVD (National Vulnerability Database, NIST) — ficha oficial de un CVE ─────
async def _nvd_lookup(cve_id: str) -> dict:
    """Consulta la API pública de NVD (NIST) por un CVE y devuelve su ficha
    oficial: descripción, CVSS/severidad, CWE, fechas y referencias.

    NVD es la fuente autoritativa "qué es este CVE y cómo de grave es". No hace
    falta API key (hay límite de tasa, de sobra para uso interactivo).

    Siempre devuelve un dict con la clave 'found' (True/False) para que quien lo
    llame no tenga que capturar excepciones: si algo falla, found=False + 'error'.
    """
    import httpx
    try:
        # La API v2.0 filtra por un CVE concreto con el parámetro cveId
        async with httpx.AsyncClient(timeout=15, headers={"User-Agent": "CyberKB/3.0"}) as client:
            r = await client.get(
                "https://services.nvd.nist.gov/rest/json/cves/2.0",
                params={"cveId": cve_id},
            )
        if r.status_code != 200:
            return {"found": False, "cve_id": cve_id, "error": f"NVD HTTP {r.status_code}"}
        # La respuesta trae una lista 'vulnerabilities'; cada elemento tiene un 'cve'
        vulns = r.json().get("vulnerabilities", [])
        if not vulns:
            return {"found": False, "cve_id": cve_id}
        cve = vulns[0].get("cve", {})

        # Descripción: NVD la da en varios idiomas; cogemos la inglesa
        desc = next((d.get("value", "") for d in cve.get("descriptions", []) if d.get("lang") == "en"), "")

        # CVSS: un CVE puede traer métricas en varias versiones del estándar.
        # Preferimos la más nueva disponible (3.1 > 3.0 > 2.0) y paramos en la 1ª.
        cvss = severity = vector = None
        metrics = cve.get("metrics", {})
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if metrics.get(key):
                m = metrics[key][0]
                cdata = m.get("cvssData", {})
                cvss = cdata.get("baseScore")          # p. ej. 10.0
                severity = cdata.get("baseSeverity") or m.get("baseSeverity")  # p. ej. CRITICAL
                vector = cdata.get("vectorString")     # cadena CVSS (AV:N/AC:L/...)
                break

        # CWE = tipo de fallo (p. ej. CWE-89 = SQLi). Está anidado en 'weaknesses'.
        cwes = []
        for w in cve.get("weaknesses", []):
            for d in w.get("description", []):
                v = d.get("value", "")
                if v.startswith("CWE-") and v not in cwes:
                    cwes.append(v)

        # Referencias (advisories, parches...): nos quedamos con las 6 primeras
        refs = [ref.get("url", "") for ref in cve.get("references", []) if ref.get("url")][:6]

        return {
            "found": True,
            "cve_id": cve.get("id", cve_id),
            "description": desc,
            "cvss": cvss,
            "severity": (severity or "").capitalize() or None,  # CRITICAL -> Critical
            "vector": vector,
            "cwe": cwes,
            "published": (cve.get("published") or "")[:10],       # solo la fecha (YYYY-MM-DD)
            "modified": (cve.get("lastModified") or "")[:10],
            "references": refs,
        }
    except Exception as e:
        return {"found": False, "cve_id": cve_id, "error": str(e)}


@app.get("/api/cve-lookup")
async def cve_lookup(id: str):
    """[Módulo CVEs] Busca cualquier CVE por su ID en NVD (ficha oficial).

    Lo llama el frontend cuando escribes un ID (CVE-AAAA-NNNN) que no tienes en
    la KB y pulsas "Buscar en NVD". Validamos el formato aquí para no gastar una
    petición a NVD con basura.
    """
    cid = (id or "").strip().upper()
    if not re.match(r"^CVE-\d{4}-\d{4,}$", cid):
        raise HTTPException(400, "Formato de CVE inválido (esperado CVE-AAAA-NNNN)")
    return await _nvd_lookup(cid)


# Cuerpo (JSON) que acepta POST /api/cves. Solo cve_id es obligatorio; el resto
# se rellena con lo que traiga la ficha de NVD al guardar.
class CVECreate(BaseModel):
    cve_id: str
    description: Optional[str] = None
    severity: Optional[str] = None
    cvss: Optional[float] = None
    title: Optional[str] = None


@app.post("/api/cves")
def create_cve(data: CVECreate, db: Session = Depends(get_db)):
    """[Módulo CVEs] Guarda un CVE en la KB (botón "Guardar" tras buscar en NVD).

    Va a la misma tabla `cves` que los CVEs que la IA detecta en documentos.
    Es un upsert: si el CVE ya existe, actualiza sus campos en vez de duplicarlo;
    devuelve created=True/False para que el frontend sepa qué pasó.
    """
    cid = data.cve_id.strip().upper()
    if not re.match(r"^CVE-\d{4}-\d{4,}$", cid):
        raise HTTPException(400, "Formato de CVE inválido")
    row = db.query(CVE).filter(CVE.cve_id == cid).first()
    if row:
        # Ya existe → solo sobreescribimos los campos que llegan con valor
        if data.description:
            row.description = data.description
        if data.severity:
            row.severity = data.severity
        if data.cvss is not None:
            row.cvss = data.cvss
        if data.title:
            row.title = data.title
        db.commit()
        db.refresh(row)
        return {"created": False, **_cve_dict(row)}
    # No existe → fila nueva
    row = CVE(cve_id=cid, description=data.description, severity=data.severity,
              cvss=data.cvss, title=data.title)
    db.add(row)
    db.commit()
    db.refresh(row)
    return {"created": True, **_cve_dict(row)}


@app.delete("/api/cves/{cid}", status_code=204)
def delete_cve(cid: int, db: Session = Depends(get_db)):
    """[Módulo CVEs] Borra un CVE de la KB (botón 🗑 de la tarjeta).

    Da simetría con Herramientas, que ya tenía borrado. Antes un CVE guardado a
    mano (sin nota asociada) no se podía quitar por ninguna vía. Se borra por id
    numérico (PK), igual que DELETE /api/tools/{id}.
    """
    row = db.query(CVE).filter(CVE.id == cid).first()
    if not row:
        raise HTTPException(404, "CVE no encontrado en la base de datos")
    db.delete(row)
    db.commit()
    return


@app.post("/api/cves/{cve_id}/enrich")
async def enrich_cve(cve_id: str, db: Session = Depends(get_db)):
    """[Módulo CVEs] Rellena CVSS/severidad/descripción oficiales de un CVE que
    YA está en la KB, consultando NVD (botón "↻ Enriquecer").

    Útil porque los CVEs detectados por la IA a veces traen esos campos vacíos o
    imprecisos; aquí los sustituimos por los datos autoritativos de NVD.
    """
    row = db.query(CVE).filter(CVE.cve_id == cve_id).first()
    if not row:
        raise HTTPException(404, "CVE no encontrado en la base de datos")
    nvd = await _nvd_lookup(cve_id)
    if not nvd.get("found"):
        return {"updated": False, "error": nvd.get("error") or "no encontrado en NVD"}
    if nvd.get("cvss") is not None:
        row.cvss = nvd["cvss"]
    if nvd.get("severity"):
        row.severity = nvd["severity"]
    if nvd.get("description"):
        row.description = nvd["description"]
    db.commit()
    db.refresh(row)
    return {"updated": True, **_cve_dict(row)}


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

@app.post("/api/osint/whois")
async def api_whois(domain: str, db: Session = Depends(get_db)):
    result = await osint.whois_lookup(domain)
    _save_osint(domain, "whois", result, db)
    return result


@app.post("/api/osint/dns")
async def api_dns(domain: str, db: Session = Depends(get_db)):
    result = await osint.dns_lookup(domain)
    _save_osint(domain, "dns", result, db)
    return result


@app.post("/api/osint/ip")
async def api_ip(ip: str, db: Session = Depends(get_db)):
    result = await osint.ip_geolocate(ip)
    _save_osint(ip, "ip", result, db)
    return result


@app.post("/api/osint/subdomains")
async def api_subdomains(domain: str, db: Session = Depends(get_db)):
    result = await osint.subdomains_combined(domain)
    _save_osint(domain, "subdomains", result, db)
    return result


@app.post("/api/osint/ssl")
async def api_ssl(domain: str, db: Session = Depends(get_db)):
    result = await osint.ssl_cert(domain)
    _save_osint(domain, "ssl", result, db)
    return result


@app.post("/api/osint/wayback")
async def api_wayback(url: str, db: Session = Depends(get_db)):
    result = await osint.wayback(url)
    _save_osint(url, "wayback", result, db)
    return result


@app.post("/api/osint/dmarc")
async def api_dmarc(domain: str, db: Session = Depends(get_db)):
    result = await osint.dmarc_spf(domain)
    _save_osint(domain, "dmarc", result, db)
    return result


@app.post("/api/osint/robots")
async def api_robots(domain: str, db: Session = Depends(get_db)):
    result = await osint.robots_txt(domain)
    _save_osint(domain, "robots", result, db)
    return result


@app.post("/api/osint/reverse-dns")
async def api_rdns(ip: str, db: Session = Depends(get_db)):
    result = await osint.reverse_dns(ip)
    _save_osint(ip, "reverse-dns", result, db)
    return result


@app.post("/api/osint/hibp")
async def api_hibp(target: str, db: Session = Depends(get_db)):
    result = await osint.hibp_check(target)
    _save_osint(target, "hibp", result, db)
    return result


@app.post("/api/osint/email-verify")
async def api_email_verify(email: str, db: Session = Depends(get_db)):
    import asyncio
    verify_task = osint.email_verify(email)
    hibp_task   = osint.hibp_check(email)
    result, hibp_result = await asyncio.gather(verify_task, hibp_task)
    result["hibp"] = hibp_result
    _save_osint(email, "email-verify", result, db)
    return result


@app.post("/api/osint/hunter")
async def api_hunter(domain: str, db: Session = Depends(get_db)):
    result = await osint.hunter_io(domain)
    _save_osint(domain, "hunter", result, db)
    return result


@app.post("/api/osint/shodan")
async def api_shodan(query: str, db: Session = Depends(get_db)):
    result = await osint.shodan_lookup(query)
    _save_osint(query, "shodan", result, db)
    return result


@app.post("/api/osint/urlscan")
async def api_urlscan(query: str, db: Session = Depends(get_db)):
    result = await osint.urlscan_search(query)
    _save_osint(query, "urlscan", result, db)
    return result


@app.post("/api/osint/virustotal")
async def api_vt(target: str, db: Session = Depends(get_db)):
    result = await osint.virustotal_lookup(target)
    _save_osint(target, "virustotal", result, db)
    return result


@app.post("/api/osint/headers")
async def api_headers(url: str, db: Session = Depends(get_db)):
    result = await osint.http_headers(url)
    _save_osint(url, "headers", result, db)
    return result


# ─── Threat Intelligence ───────────────────────────────────────────────────────

@app.post("/api/osint/hash-vt")
async def api_hash_vt(hash: str, db: Session = Depends(get_db)):
    result = await osint.hash_vt(hash)
    _save_osint(hash, "hash-vt", result, db)
    return result


@app.post("/api/osint/abuseipdb")
async def api_abuseipdb(ip: str, db: Session = Depends(get_db)):
    result = await osint.ip_abuseipdb(ip)
    _save_osint(ip, "abuseipdb", result, db)
    return result


@app.post("/api/osint/malwarebazaar")
async def api_malwarebazaar(hash: str, db: Session = Depends(get_db)):
    result = await osint.hash_malwarebazaar(hash)
    _save_osint(hash, "malwarebazaar", result, db)
    return result


@app.post("/api/osint/leakradar")
async def api_leakradar(query: str, db: Session = Depends(get_db)):
    result = await osint.leakradar_search(query)
    _save_osint(query, "leakradar", result, db)
    return result


@app.get("/api/osint/history")
def osint_history(db: Session = Depends(get_db)):
    rows = db.query(OsintResult).order_by(OsintResult.created_at.desc()).limit(50).all()
    return [
        {
            "id": r.id,
            "query": r.query,
            "type": r.query_type,
            "created_at": r.created_at.isoformat() if r.created_at else None,
        }
        for r in rows
    ]


@app.get("/api/osint/history/{result_id}")
def osint_result(result_id: int, db: Session = Depends(get_db)):
    r = db.query(OsintResult).filter(OsintResult.id == result_id).first()
    if not r:
        raise HTTPException(404, "Not found")
    return json.loads(r.result or "{}")


def _save_osint(query: str, qtype: str, result: dict, db: Session):
    r = OsintResult(query=query, query_type=qtype, result=json.dumps(result))
    db.add(r)
    db.commit()


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
