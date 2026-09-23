from fastapi import APIRouter, Depends, HTTPException
from database import get_db
from sqlalchemy.orm import Session
import osint_tools as osint
import claude_service as ai
import json
from models import Note, CVE
import re


from layers.routers_functions import _persist_mitre, _persist_entities


router = APIRouter()


@router.post("/api/forensic/analyze")
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