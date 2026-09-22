from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from database import get_db
from pydantic import BaseModel
from models import Note, Tool, Command, CVE
import claude_service as ai
from datetime import datetime

from layers.routers_functions import _note_dict, _tool_dict, _cmd_dict, _cve_dict, ChatIn


router = APIRouter()


@router.post("/api/chat")
def chat(data: ChatIn, db: Session = Depends(get_db)):
    notes = db.query(Note).order_by(Note.updated_at.desc()).limit(20).all()
    answer = ai.chat_with_context(data.question, [_note_dict(n) for n in notes])
    return {"answer": answer}


@router.get("/api/search")
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


@router.get("/api/export")
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
