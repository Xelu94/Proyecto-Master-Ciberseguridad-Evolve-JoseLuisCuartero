from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from database import get_db
from models import GraphEntity, EntityRelation, entity_note_map, Note
import claude_service as ai


from layers.routers_functions import _persist_entities


router = APIRouter()


@router.get("/api/graph")
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


@router.post("/api/notes/{note_id}/extract")
def extract_note_entities(note_id: int, db: Session = Depends(get_db)):
    """Re-extract graph entities from an existing note."""
    n = db.query(Note).filter(Note.id == note_id).first()
    if not n:
        raise HTTPException(404, "Note not found")
    result = ai.extract_entities(n.content[:6000])
    _persist_entities(result.get("entities", []), result.get("relations", []), n, db)
    return {"extracted": len(result.get("entities", []))}


@router.post("/api/graph/reindex-all")
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