from fastapi import APIRouter, Depends
from database import get_db
from sqlalchemy.orm import Session
from models import MitreTechnique


router = APIRouter()


@router.get("/api/mitre")
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


@router.get("/api/mitre/search")
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