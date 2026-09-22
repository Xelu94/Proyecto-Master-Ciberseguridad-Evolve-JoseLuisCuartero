from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from database import get_db
from models import CVE
import re


from layers.routers_functions import _cve_dict


router = APIRouter()


@router.get("/api/cves")
def list_cves(db: Session = Depends(get_db)):
    cves = db.query(CVE).order_by(CVE.created_at.desc()).all()
    return [_cve_dict(c) for c in cves]


@router.get("/api/cves/{cve_id}/exploits")
async def cve_exploits(cve_id: str):
    """Query Exploit-DB for public exploits for a given CVE."""
    import httpx
    # Strip 'CVE-' prefix for the search query
    cve_num = re.sub(r"^CVE-", "", cve_id.strip(), flags=re.IGNORECASE)
    try:
        headers = {
            "User-Agent": "CyberKB/3.0",
            "X-Requested-With": "XMLHttpRequest",
            "Accept": "application/json, text/javascript, */*; q=0.01",
            "Referer": "https://www.exploit-db.com/search",
        }
        async with httpx.AsyncClient(timeout=15, headers=headers) as client:
            r = await client.get(
                "https://www.exploit-db.com/search",
                params={
                    "action": "search",
                    "cve": cve_num,
                    "draw": "1",
                    "columns[0][data]": "id",
                    "columns[1][data]": "date_published",
                    "columns[2][data]": "title",
                    "columns[3][data]": "type",
                    "columns[4][data]": "platform",
                    "columns[5][data]": "verified",
                    "order[0][column]": "1",
                    "order[0][dir]": "desc",
                    "start": "0",
                    "length": "10",
                },
            )
        if r.status_code != 200:
            return {"cve_id": cve_id, "count": 0, "exploits": [], "error": f"EDB HTTP {r.status_code}"}
        data = r.json()
        rows = data.get("data", [])
        exploits = []
        for row in rows[:10]:
            eid = row.get("id", "")
            exploits.append({
                "id":       eid,
                "title":    row.get("description_cut", row.get("title", "")),
                "date":     row.get("date_published", row.get("date", ""))[:10] if row.get("date_published") or row.get("date") else "",
                "type":     row.get("type", {}).get("name", "") if isinstance(row.get("type"), dict) else str(row.get("type", "")),
                "platform": row.get("platform", {}).get("name", "") if isinstance(row.get("platform"), dict) else str(row.get("platform", "")),
                "url":      f"https://www.exploit-db.com/exploits/{eid}" if eid else "",
                "verified": bool(row.get("verified")),
            })
        return {"cve_id": cve_id, "count": len(exploits), "exploits": exploits}
    except Exception as e:
        return {"cve_id": cve_id, "count": 0, "exploits": [], "error": str(e)}