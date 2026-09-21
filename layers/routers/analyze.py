from fastapi import APIRouter, Depends, UploadFile, File, Form, HTTPException
from pydantic import BaseModel
from typing import Optional
from sqlalchemy.orm import Session
from database import get_db
import claude_service as ai
from models import Tool, GraphEntity
from pathlib import Path
from models import Note, Command, CVE, MitreTechnique
import json
import sys
import os
import uuid
import shutil
import document_parser as parser


class AnalyzeIn(BaseModel):
    text: str
    title: Optional[str] = None


router = APIRouter()


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


def _runtime_dir() -> Path:
    """Where user data lives (.env, data/, uploads/) — always next to exe/script."""
    if getattr(sys, "frozen", False):
        return Path(sys.executable).parent
    return Path(__file__).parent


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


RUNTIME_DIR = _runtime_dir()
UPLOAD_DIR = RUNTIME_DIR / os.getenv("UPLOAD_DIR", "uploads")
UPLOAD_DIR.mkdir(exist_ok=True)

@router.post("/api/analyze")
def analyze_text(data: AnalyzeIn, db: Session = Depends(get_db)):
    result = ai.analyze_content(data.text)
    # Persist tools discovered
    _persist_tools(result.get("tools", []), db)
    return result


@router.post("/api/upload")
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