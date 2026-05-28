from sqlalchemy import Column, Integer, String, Text, Boolean, Float, DateTime, ForeignKey, Table, UniqueConstraint
from sqlalchemy.orm import relationship
from datetime import datetime
from database import Base

# ── Graph entity tables ────────────────────────────────────────────────────────
entity_note_map = Table(
    "entity_note_map",
    Base.metadata,
    Column("entity_id", Integer, ForeignKey("graph_entities.id")),
    Column("note_id",   Integer, ForeignKey("notes.id")),
    UniqueConstraint("entity_id", "note_id"),
)

tool_note = Table(
    "tool_notes",
    Base.metadata,
    Column("tool_id", Integer, ForeignKey("tools.id")),
    Column("note_id", Integer, ForeignKey("notes.id")),
)


class Note(Base):
    __tablename__ = "notes"

    id = Column(Integer, primary_key=True, autoincrement=True)
    title = Column(String(500), nullable=False)
    content = Column(Text, nullable=False)
    category = Column(String(100), nullable=False, default="teoria")
    subcategory = Column(String(100), nullable=True)
    summary = Column(Text, nullable=True)
    tags = Column(Text, nullable=True)
    source_file = Column(String(500), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    commands         = relationship("Command",        back_populates="note", cascade="all, delete-orphan")
    cves             = relationship("CVE",            back_populates="note", cascade="all, delete-orphan")
    tools            = relationship("Tool",           secondary=tool_note,  back_populates="tools")
    mitre_techniques = relationship("MitreTechnique", back_populates="note", cascade="all, delete-orphan")


class Command(Base):
    __tablename__ = "commands"

    id = Column(Integer, primary_key=True, autoincrement=True)
    command = Column(Text, nullable=False)
    description = Column(Text, nullable=True)
    tool_name = Column(String(200), nullable=True)
    os = Column(String(20), nullable=True, default="linux")  # linux | windows | both
    flags = Column(Text, nullable=True)
    examples = Column(Text, nullable=True)
    tags = Column(Text, nullable=True)
    category = Column(String(100), nullable=True)
    note_id = Column(Integer, ForeignKey("notes.id"), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    note = relationship("Note", back_populates="commands")


class Tool(Base):
    __tablename__ = "tools"

    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(200), unique=True, nullable=False)
    url = Column(String(500), nullable=True)
    description = Column(Text, nullable=True)
    category = Column(String(100), nullable=True)
    tool_type = Column(String(20), nullable=True, default="software")  # software | web
    use_cases = Column(Text, nullable=True)
    tags = Column(Text, nullable=True)
    requires_api = Column(Boolean, default=False)
    api_info = Column(Text, nullable=True)
    mention_count = Column(Integer, default=1)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    tools = relationship("Note", secondary=tool_note, back_populates="tools")


class CVE(Base):
    __tablename__ = "cves"

    id = Column(Integer, primary_key=True, autoincrement=True)
    cve_id = Column(String(50), unique=True, nullable=False)
    title = Column(String(500), nullable=True)
    description = Column(Text, nullable=True)
    severity = Column(String(20), nullable=True)
    cvss = Column(Float, nullable=True)
    affected = Column(Text, nullable=True)
    note_id = Column(Integer, ForeignKey("notes.id"), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    note = relationship("Note", back_populates="cves")


class GraphEntity(Base):
    """A named cybersecurity entity extracted from notes (technique, tool, protocol…)."""
    __tablename__ = "graph_entities"

    id          = Column(Integer, primary_key=True, autoincrement=True)
    name        = Column(String(200), unique=True, nullable=False)
    entity_type = Column(String(50),  nullable=False)   # attack|defense|tool|protocol|vuln|methodology|concept
    description = Column(Text,        nullable=True)
    frequency   = Column(Integer,     default=1)
    created_at  = Column(DateTime,    default=datetime.utcnow)


class EntityRelation(Base):
    """Co-occurrence relation between two GraphEntity nodes."""
    __tablename__ = "entity_relations"
    __table_args__ = (UniqueConstraint("entity_a_id", "entity_b_id"),)

    id           = Column(Integer, primary_key=True, autoincrement=True)
    entity_a_id  = Column(Integer, ForeignKey("graph_entities.id"), nullable=False)
    entity_b_id  = Column(Integer, ForeignKey("graph_entities.id"), nullable=False)
    weight       = Column(Integer, default=1)


class OsintResult(Base):
    __tablename__ = "osint_results"

    id = Column(Integer, primary_key=True, autoincrement=True)
    query = Column(String(500), nullable=False)
    query_type = Column(String(50), nullable=False)
    result = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)


class MitreTechnique(Base):
    """MITRE ATT&CK technique extracted from a note."""
    __tablename__ = "mitre_techniques"

    id             = Column(Integer,     primary_key=True, autoincrement=True)
    note_id        = Column(Integer,     ForeignKey("notes.id"), nullable=True)
    technique_id   = Column(String(20),  nullable=False)   # e.g. T1055, T1555.003
    technique_name = Column(String(300), nullable=True)
    tactic         = Column(String(100), nullable=True)    # Persistence, Credential Access…
    context_snippet= Column(Text,        nullable=True)
    created_at     = Column(DateTime,    default=datetime.utcnow)

    note = relationship("Note", back_populates="mitre_techniques")


class AuditProgress(Base):
    __tablename__ = "audit_progress"
    __table_args__ = (UniqueConstraint("audit_type", "item_id"),)

    id = Column(Integer, primary_key=True, autoincrement=True)
    audit_type = Column(String(50), nullable=False)
    item_id = Column(String(50), nullable=False)
    done = Column(Boolean, default=False)
    notes = Column(Text, nullable=True)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
