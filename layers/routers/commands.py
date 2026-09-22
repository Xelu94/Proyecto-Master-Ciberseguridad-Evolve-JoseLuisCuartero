from fastapi import APIRouter, Depends
from models import Command
from sqlalchemy.orm import Session
from database import get_db
import claude_service as ai
from layers.routers_functions import _cmd_dict, CommandIn
import json
from typing import Optional


router = APIRouter()


@router.post("/api/commands/cheatsheet")
def gen_cheatsheet(tool_name: str, db: Session = Depends(get_db)):
    cmds = db.query(Command).filter(Command.tool_name.ilike(f"%{tool_name}%")).all()
    result = ai.generate_cheatsheet(tool_name, [_cmd_dict(c) for c in cmds])
    return {"tool": tool_name, "cheatsheet": result}


@router.post("/api/commands", status_code=201)
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


@router.get("/api/commands")
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