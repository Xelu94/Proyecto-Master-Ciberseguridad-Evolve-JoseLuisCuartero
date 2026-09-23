from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from database import get_db
from models import AuditProgress
from datetime import datetime
import claude_service as ai


from layers.routers_functions import AuditItemIn, ReportRequest


router = APIRouter()


@router.get("/api/audit/{audit_type}/progress")
def get_audit_progress(audit_type: str, db: Session = Depends(get_db)):
    rows = db.query(AuditProgress).filter(AuditProgress.audit_type == audit_type).all()
    return {r.item_id: {"done": r.done, "notes": r.notes} for r in rows}


@router.post("/api/audit/{audit_type}/item/{item_id}")
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


@router.delete("/api/audit/{audit_type}/reset")
def reset_audit(audit_type: str, db: Session = Depends(get_db)):
    db.query(AuditProgress).filter(AuditProgress.audit_type == audit_type).delete()
    db.commit()
    return {"ok": True}


@router.get("/api/audit/all/summary")
def audit_summary(db: Session = Depends(get_db)):
    from sqlalchemy import func
    from sqlalchemy import Integer as SAInt
    rows = db.query(AuditProgress.audit_type, func.count(AuditProgress.id), func.sum(AuditProgress.done.cast(SAInt))).group_by(AuditProgress.audit_type).all()
    return {r[0]: {"total_done": int(r[2] or 0), "total_checked": r[1]} for r in rows}


@router.post("/api/audit/generate-report")
async def generate_report(req: ReportRequest):
    if not req.items:
        raise HTTPException(400, "No items provided")
    result = ai.generate_audit_report(
        audit_type=req.audit_name,
        items=[i.model_dump() for i in req.items],
        progress=req.progress,
    )
    return result