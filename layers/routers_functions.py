import json
from models import OsintResult
from sqlalchemy.orm import Session
from typing import Optional
from pydantic import BaseModel
from models import CVE, Command, Tool, Note, MitreTechnique, GraphEntity
import claude_service as ai
from pathlib import Path
import sys
from dotenv import load_dotenv


# OSINT

def _save_osint(query: str, qtype: str, result: dict, db: Session):
    r = OsintResult(query=query, query_type=qtype, result=json.dumps(result))
    db.add(r)
    db.commit()


# NOTES

class NoteIn(BaseModel):
    title: str
    content: str
    category: str = "teoria"
    subcategory: Optional[str] = None
    summary: Optional[str] = None
    tags: Optional[list[str]] = None
    source_file: Optional[str] = None


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


# ANALYZE

class AnalyzeIn(BaseModel):
    text: str
    title: Optional[str] = None


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


# CHAT

class ChatIn(BaseModel):
    question: str


# SETTINGS

class SettingsIn(BaseModel):
    keys: dict[str, str]

RUNTIME_DIR = _runtime_dir()

load_dotenv(dotenv_path=RUNTIME_DIR / ".env", encoding="utf-8", override=True)
(RUNTIME_DIR / "data").mkdir(exist_ok=True)

def _read_env_file() -> dict:
    env_path = RUNTIME_DIR / ".env"
    pairs = {}
    if env_path.exists():
        for line in env_path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, _, v = line.partition("=")
                pairs[k.strip()] = v.strip()
    return pairs


def _mask(val: str) -> str:
    if not val:
        return ""
    if len(val) <= 8:
        return "*" * len(val)
    return val[:4] + "*" * (len(val) - 8) + val[-4:]


def _write_env_file(pairs: dict):
    env_path = RUNTIME_DIR / ".env"
    # Read existing lines to preserve comments/order
    existing_lines = []
    if env_path.exists():
        existing_lines = env_path.read_text(encoding="utf-8").splitlines()

    written = set()
    new_lines = []
    for line in existing_lines:
        stripped = line.strip()
        if stripped and not stripped.startswith("#") and "=" in stripped:
            k = stripped.partition("=")[0].strip()
            if k in pairs:
                new_lines.append(f"{k}={pairs[k]}")
                written.add(k)
                continue
        new_lines.append(line)

    # Append any new keys not already in file
    for k, v in pairs.items():
        if k not in written:
            new_lines.append(f"{k}={v}")

    env_path.write_text("\n".join(new_lines) + "\n", encoding="utf-8")