from fastapi import APIRouter, Depends, UploadFile, File, Form, HTTPException
from sqlalchemy.orm import Session
from database import get_db
import claude_service as ai
from pathlib import Path
from models import Note
import json
import os
import uuid
import shutil
import document_parser as parser

from layers.routers_functions import (
    AnalyzeIn, 
    _persist_tools, 
    _persist_commands, 
    _persist_cves,
    _persist_mitre, 
    _persist_entities,
    _runtime_dir                   
)


router = APIRouter()


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