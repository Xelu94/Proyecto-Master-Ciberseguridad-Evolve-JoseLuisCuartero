import os
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
from models import Note, Command, Tool, CVE, OsintResult, GraphEntity, EntityRelation, entity_note_map
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


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    _migrate_db()
    _seed_google_dorks(None)
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
    result = await osint.subdomains_crtsh(domain)
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


@app.post("/api/osint/asn")
async def api_asn(query: str, db: Session = Depends(get_db)):
    result = await osint.asn_lookup(query)
    _save_osint(query, "asn", result, db)
    return result


@app.post("/api/osint/hibp")
async def api_hibp(target: str, db: Session = Depends(get_db)):
    result = await osint.hibp_check(target)
    _save_osint(target, "hibp", result, db)
    return result


@app.post("/api/osint/email-verify")
async def api_email_verify(email: str, db: Session = Depends(get_db)):
    result = await osint.email_verify(email)
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


# ─── Commands OS filter ────────────────────────────────────────────────────────

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
