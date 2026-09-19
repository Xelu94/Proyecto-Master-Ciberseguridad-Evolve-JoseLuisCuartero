"""Agente-BBDD de CyberKB.

Recibe la agrupacion del agente Agrupador y la reparte entre las tablas de la
aplicacion: notas, herramientas, comandos, CVEs, tecnicas ATT&CK y grafo de
entidades. Todo ocurre en una sola transaccion: o entra entero o no entra nada.

Para engancharlo en main.py. El repositorio de agentes es hermano del de la app y su
nombre lleva guion, asi que no se puede importar como paquete:

    import sys
    from pathlib import Path
    sys.path.insert(0, str(
        Path(__file__).resolve().parent.parent / "Agentes-CyberKB" / "Editor" / "Agente-BBDD"
    ))
    from agente_bbdd import router as bbdd_router
    app.include_router(bbdd_router)
"""

from __future__ import annotations

import json
from pathlib import Path

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session

# Modulos de la aplicacion. Estan en sys.path porque main.py los carga primero,
# igual que el agente Escritor importa document_parser.
import claude_service as ai
from database import SessionLocal
from models import (
    CVE,
    Command,
    EntityRelation,
    GraphEntity,
    MitreTechnique,
    Note,
    Tool,
    entity_note_map,
)

BASE_DIR = Path(__file__).resolve().parent
CFG = json.loads((BASE_DIR / "config.json").read_text(encoding="utf-8"))

LONGITUDES = CFG["longitudes"]
INCREMENTAR = CFG["comportamiento"]["incrementar_contadores"]
CONSERVAR = CFG["comportamiento"]["conservar_valor_si_el_nuevo_esta_vacio"]
ERRORES = CFG["errores"]

router = APIRouter(prefix="/api/bbdd", tags=["bbdd"])


class Agrupacion(BaseModel):
    """Lo que envia el Agrupador."""

    id_resumen: str
    titulo: str
    resumen: str
    category: str = "teoria"
    subcategory: str | None = None
    tags: list[str] = []
    archivo_original: str | None = None
    source: str | None = None
    timestamp: str | None = None
    tools: list[dict] = []
    commands: list[dict] = []
    cves: list[dict] = []
    mitre: list[dict] = []
    entities: list[dict] = []
    relations: list[list[str]] = []


# ------------------------------------------------------------------- utilidades


def _texto(valor, limite: int | None = None) -> str:
    limpio = str(valor or "").strip()
    return limpio[:limite] if limite else limpio


def _fusionar(fila, campo: str, valor) -> None:
    """Escribe el valor nuevo sobre la fila existente.

    Un valor nuevo vacio no borra lo que ya habia: un documento que menciona una
    herramienta de pasada no debe vaciar la descripcion que aporto otro mejor.
    """
    if valor in (None, "", []) and CONSERVAR:
        return
    setattr(fila, campo, valor)


# ----------------------------------------------------------------------- tablas


def _nota(db: Session, datos: Agrupacion) -> Note:
    """Crea o actualiza la nota. Es la fila de la que cuelga todo lo demas."""
    titulo = _texto(datos.titulo, LONGITUDES["note_title"]) or "Sin titulo"
    fichero = _texto(datos.archivo_original, 500) or None
    etiquetas = json.dumps(datos.tags, ensure_ascii=False)

    # notes no tiene restriccion UNIQUE, asi que la identidad se reconstruye con
    # titulo y fichero de origen: es lo que hace idempotente un reintento.
    fila = db.execute(
        select(Note).where(Note.title == titulo, Note.source_file == fichero)
    ).scalars().first()

    if fila is None:
        fila = Note(
            title=titulo,
            content=datos.resumen,
            category=_texto(datos.category, LONGITUDES["note_category"]) or "teoria",
            subcategory=_texto(datos.subcategory, LONGITUDES["note_subcategory"]) or None,
            summary=datos.resumen,
            tags=etiquetas,
            source_file=fichero,
        )
        db.add(fila)
    else:
        _fusionar(fila, "content", datos.resumen)
        _fusionar(fila, "summary", datos.resumen)
        _fusionar(fila, "category", _texto(datos.category, LONGITUDES["note_category"]))
        _fusionar(fila, "subcategory", _texto(datos.subcategory, LONGITUDES["note_subcategory"]))
        _fusionar(fila, "tags", etiquetas)

    db.flush()
    return fila


def _catalogo(nombre: str, tipo_propuesto: str) -> tuple[str | None, str]:
    """Consulta el catalogo curado de la app: URL y tipo de una herramienta conocida.

    La URL nunca la propone el Agrupador. Pedirle enlaces a un modelo produce
    direcciones verosimiles e inexistentes, y aqui hay 96 verificadas a mano.
    El tipo si acepta lo que diga el Agrupador cuando el catalogo no conoce la
    herramienta, porque ahi su criterio alcanza mas que una lista cerrada.
    """
    clave = nombre.lower()
    url = _texto(ai.KNOWN_TOOLS.get(clave), LONGITUDES["tool_url"]) or None
    if clave in ai.WEB_RESOURCES:
        return url, "web"
    return url, "web" if tipo_propuesto == "web" else "software"


def _herramientas(db: Session, nota: Note, datos: Agrupacion) -> int:
    """tools.name es UNIQUE: hay que buscar sin distinguir mayusculas."""
    tocadas = 0
    for bruto in datos.tools:
        nombre = _texto(bruto.get("name"), LONGITUDES["tool_name"])
        if not nombre:
            continue

        url, tipo = _catalogo(nombre, _texto(bruto.get("tool_type")))

        fila = db.execute(
            select(Tool).where(Tool.name.ilike(nombre))
        ).scalars().first()

        if fila is None:
            fila = Tool(
                name=nombre,
                url=url,
                description=_texto(bruto.get("description")) or None,
                tool_type=tipo,
                use_cases=_texto(bruto.get("use_cases")) or None,
                requires_api=bool(bruto.get("requires_api")),
                category=_texto(datos.category, LONGITUDES["tool_category"]) or None,
                mention_count=1,
            )
            db.add(fila)
        else:
            # url va por _fusionar: si el catalogo no la conoce devuelve None y
            # no debe borrar la que ya hubiera.
            _fusionar(fila, "url", url)
            _fusionar(fila, "description", _texto(bruto.get("description")))
            _fusionar(fila, "use_cases", _texto(bruto.get("use_cases")))
            if bruto.get("requires_api"):
                fila.requires_api = True
            if INCREMENTAR:
                fila.mention_count = (fila.mention_count or 0) + 1

        db.flush()
        if fila not in nota.tools:
            nota.tools.append(fila)
        tocadas += 1
    return tocadas


def _comandos(db: Session, nota: Note, datos: Agrupacion) -> int:
    """commands no tiene UNIQUE: sin este filtro, cada reintento duplicaria filas."""
    categoria = _texto(datos.category, LONGITUDES["command_category"]) or None
    etiquetas = json.dumps(datos.tags, ensure_ascii=False)
    tocados = 0

    for bruto in datos.commands:
        linea = _texto(bruto.get("command"))
        if not linea:
            continue

        fila = db.execute(
            select(Command).where(Command.command == linea, Command.note_id == nota.id)
        ).scalars().first()

        banderas = json.dumps(bruto.get("flags") or [], ensure_ascii=False)

        if fila is None:
            db.add(Command(
                command=linea,
                description=_texto(bruto.get("description")) or None,
                tool_name=_texto(bruto.get("tool_name"), LONGITUDES["command_tool_name"]) or None,
                os=_texto(bruto.get("os"), LONGITUDES["command_os"]) or "linux",
                flags=banderas,
                tags=etiquetas,
                category=categoria,
                note_id=nota.id,
            ))
        else:
            _fusionar(fila, "description", _texto(bruto.get("description")))
            _fusionar(fila, "tool_name", _texto(bruto.get("tool_name"), LONGITUDES["command_tool_name"]))
            _fusionar(fila, "os", _texto(bruto.get("os"), LONGITUDES["command_os"]))
            _fusionar(fila, "flags", banderas)
        tocados += 1

    db.flush()
    return tocados


def _cves(db: Session, nota: Note, datos: Agrupacion) -> int:
    """cves.cve_id es UNIQUE y global: el mismo CVE lo citan varios documentos."""
    tocados = 0
    for bruto in datos.cves:
        identificador = _texto(bruto.get("cve_id"), LONGITUDES["cve_id"]).upper()
        if not identificador:
            continue

        puntos = bruto.get("cvss")
        puntos = puntos if isinstance(puntos, (int, float)) and 0 <= puntos <= 10 else None

        fila = db.execute(
            select(CVE).where(CVE.cve_id == identificador)
        ).scalars().first()

        if fila is None:
            db.add(CVE(
                cve_id=identificador,
                title=_texto(bruto.get("title"), LONGITUDES["cve_title"]) or None,
                description=_texto(bruto.get("description")) or None,
                severity=_texto(bruto.get("severity"), LONGITUDES["cve_severity"]) or None,
                cvss=puntos,
                affected=_texto(bruto.get("affected")) or None,
                note_id=nota.id,
            ))
        else:
            _fusionar(fila, "title", _texto(bruto.get("title"), LONGITUDES["cve_title"]))
            _fusionar(fila, "description", _texto(bruto.get("description")))
            _fusionar(fila, "severity", _texto(bruto.get("severity"), LONGITUDES["cve_severity"]))
            _fusionar(fila, "cvss", puntos)
            _fusionar(fila, "affected", _texto(bruto.get("affected")))
            # Un CVE huerfano se adopta: sin esto queda atado solo al primer
            # documento que lo cito y los demas lo pierden de vista.
            if fila.note_id is None:
                fila.note_id = nota.id
        tocados += 1

    db.flush()
    return tocados


def _mitre(db: Session, nota: Note, datos: Agrupacion) -> int:
    tocadas = 0
    for bruto in datos.mitre:
        identificador = _texto(bruto.get("technique_id"), LONGITUDES["mitre_technique_id"]).upper()
        if not identificador:
            continue

        fila = db.execute(
            select(MitreTechnique).where(
                MitreTechnique.technique_id == identificador,
                MitreTechnique.note_id == nota.id,
            )
        ).scalars().first()

        nombre = _texto(bruto.get("technique_name"), LONGITUDES["mitre_technique_name"])
        tactica = _texto(bruto.get("tactic"), 100)
        contexto = _texto(bruto.get("context_snippet"))

        if fila is None:
            db.add(MitreTechnique(
                note_id=nota.id,
                technique_id=identificador,
                technique_name=nombre or None,
                tactic=tactica or None,
                context_snippet=contexto or None,
            ))
        else:
            _fusionar(fila, "technique_name", nombre)
            _fusionar(fila, "tactic", tactica)
            _fusionar(fila, "context_snippet", contexto)
        tocadas += 1

    db.flush()
    return tocadas


def _entidades(db: Session, nota: Note, datos: Agrupacion) -> dict[str, GraphEntity]:
    """graph_entities.name es UNIQUE. Devuelve el mapa que necesitan las relaciones."""
    mapa: dict[str, GraphEntity] = {}

    for bruto in datos.entities:
        nombre = _texto(bruto.get("name"), LONGITUDES["entity_name"])
        if not nombre:
            continue

        fila = db.execute(
            select(GraphEntity).where(GraphEntity.name.ilike(nombre))
        ).scalars().first()

        if fila is None:
            fila = GraphEntity(
                name=nombre,
                entity_type=_texto(bruto.get("type"), LONGITUDES["entity_type"]) or "concept",
                description=_texto(bruto.get("description")) or None,
                frequency=1,
            )
            db.add(fila)
        else:
            _fusionar(fila, "description", _texto(bruto.get("description")))
            _fusionar(fila, "entity_type", _texto(bruto.get("type"), LONGITUDES["entity_type"]))
            if INCREMENTAR:
                fila.frequency = (fila.frequency or 0) + 1

        db.flush()

        vinculo = db.execute(
            select(entity_note_map).where(
                entity_note_map.c.entity_id == fila.id,
                entity_note_map.c.note_id == nota.id,
            )
        ).first()
        if vinculo is None:
            db.execute(entity_note_map.insert().values(entity_id=fila.id, note_id=nota.id))

        mapa[nombre.lower()] = fila

    return mapa


def _relaciones(db: Session, mapa: dict[str, GraphEntity], pares: list[list[str]]) -> int:
    """El UNIQUE es (entity_a_id, entity_b_id), que no es simetrico: hay que
    ordenar el par por id o la misma arista entra dos veces del reves."""
    tocadas = 0
    # Un par ya tratado en esta misma llamada no esta aun en la base (falta el
    # flush), asi que el select no lo ve y se intentaria insertar dos veces.
    vistos: set[tuple[int, int]] = set()

    for par in pares:
        if not isinstance(par, list) or len(par) != 2:
            continue
        a = mapa.get(_texto(par[0]).lower())
        b = mapa.get(_texto(par[1]).lower())
        if a is None or b is None or a.id == b.id:
            continue

        menor, mayor = min(a.id, b.id), max(a.id, b.id)
        if (menor, mayor) in vistos:
            continue
        vistos.add((menor, mayor))

        fila = db.execute(
            select(EntityRelation).where(
                EntityRelation.entity_a_id == menor,
                EntityRelation.entity_b_id == mayor,
            )
        ).scalars().first()

        if fila is None:
            db.add(EntityRelation(entity_a_id=menor, entity_b_id=mayor, weight=1))
        elif INCREMENTAR:
            fila.weight = (fila.weight or 0) + 1
        tocadas += 1

    db.flush()
    return tocadas


# ----------------------------------------------------------------- orquestacion


def _procesar(datos: Agrupacion) -> dict:
    db = SessionLocal()
    try:
        nota = _nota(db, datos)
        recuento = {
            "nota_id": nota.id,
            "herramientas": _herramientas(db, nota, datos),
            "comandos": _comandos(db, nota, datos),
            "cves": _cves(db, nota, datos),
            "mitre": _mitre(db, nota, datos),
        }
        mapa = _entidades(db, nota, datos)
        recuento["entidades"] = len(mapa)
        recuento["relaciones"] = _relaciones(db, mapa, datos.relations)

        db.commit()
    except Exception:
        # Una escritura a medias deja la base incoherente y el reintento no
        # tendria forma de saber por donde se quedo.
        db.rollback()
        raise HTTPException(500, ERRORES["generico"])
    finally:
        db.close()

    return {"id_resumen": datos.id_resumen, "guardado": True, **recuento}


@router.post("/ingesta")
async def ingesta(datos: Agrupacion):
    """Entrada del Agrupador: la agrupacion lista para repartir entre tablas."""
    return _procesar(datos)
