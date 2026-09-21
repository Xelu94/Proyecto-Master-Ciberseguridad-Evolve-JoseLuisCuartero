from typing import Optional
from sqlalchemy.orm import Session
from fastapi import APIRouter, Depends, HTTPException
from database import get_db
from models import Note, Command, CVE, Tool, MitreTechnique
import json
from pydantic import BaseModel
from datetime import datetime


class NoteIn(BaseModel):
    title: str
    content: str
    category: str = "teoria"
    subcategory: Optional[str] = None
    summary: Optional[str] = None
    tags: Optional[list[str]] = None
    source_file: Optional[str] = None


router = APIRouter()


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


@router.get("/api/notes")
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


@router.get("/api/notes/{note_id}")
def get_note(note_id: int, db: Session = Depends(get_db)):
    n = db.query(Note).filter(Note.id == note_id).first()
    if not n:
        raise HTTPException(404, "Note not found")
    return _note_dict(n, full=True)


@router.post("/api/notes", status_code=201)
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


@router.put("/api/notes/{note_id}")
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


@router.delete("/api/notes/all", status_code=204)
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


@router.delete("/api/notes/{note_id}", status_code=204)
def delete_note(note_id: int, db: Session = Depends(get_db)):
    n = db.query(Note).filter(Note.id == note_id).first()
    if not n:
        raise HTTPException(404, "Note not found")
    db.delete(n)
    db.commit()