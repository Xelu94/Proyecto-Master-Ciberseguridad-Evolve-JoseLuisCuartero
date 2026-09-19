"""Agente Agrupador de CyberKB.

Recibe el resumen que produce el agente Escritor, lo descompone en fichas
estructuradas —herramientas, comandos, CVEs, tecnicas ATT&CK y entidades del grafo—
y entrega el resultado al Agente-BBDD y al agente Obsi.

Para engancharlo en main.py. El repositorio de agentes es hermano del de la app y su
nombre lleva guion, asi que no se puede importar como paquete:

    import sys
    from pathlib import Path
    sys.path.insert(0, str(
        Path(__file__).resolve().parent.parent / "Agentes-CyberKB" / "Editor" / "Agrupador"
    ))
    from agrupador import router as agrupador_router
    app.include_router(agrupador_router)
"""

from __future__ import annotations

import json
import os
import re
import unicodedata
from datetime import datetime, timezone
from pathlib import Path

import anthropic
import httpx
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

BASE_DIR = Path(__file__).resolve().parent
CFG = json.loads((BASE_DIR / "config.json").read_text(encoding="utf-8"))

MODELO = CFG["modelo"]
CATEGORIAS = set(CFG["categorias"])
TIPOS_ENTIDAD = set(CFG["tipos_entidad"])
TACTICAS = {t.lower(): t for t in CFG["tacticas_mitre"]}
SISTEMAS = set(CFG["sistemas_comando"])
LIMITES = CFG["limites"]
ERRORES = CFG["errores"]

# Cuelga de la carpeta del agente, no del directorio desde el que se arranque el
# proceso: asi las agrupaciones viven siempre junto al Agrupador.
SALIDA_DIR = Path(
    os.getenv("AGRUPADOR_OUTPUT_DIR") or BASE_DIR / CFG["salida"]["directorio"]
).resolve()
SALIDA_DIR.mkdir(parents=True, exist_ok=True)

BBDD_URL = os.getenv("BBDD_URL", CFG["bbdd"]["url"])
OBSI_URL = os.getenv("OBSI_URL", CFG["obsi"]["url"])

RE_CVE = re.compile(r"^CVE-\d{4}-\d{4,7}$", re.IGNORECASE)
RE_MITRE = re.compile(r"^T\d{4}(\.\d{3})?$", re.IGNORECASE)

router = APIRouter(prefix="/api/agrupador", tags=["agrupador"])


class ResumenEscritor(BaseModel):
    """Lo que envia el Escritor. Solo el nucleo es obligatorio: asi un reintento
    manual desde la app puede repetir la peticion con lo minimo."""

    id: str
    titulo: str
    resumen: str
    temas: list[str] = []
    timestamp: str | None = None
    source: str | None = None
    archivo_original: str | None = None


def _objeto(propiedades: dict) -> dict:
    return {
        "type": "object",
        "properties": propiedades,
        "required": list(propiedades),
        "additionalProperties": False,
    }


def _lista(propiedades: dict) -> dict:
    return {"type": "array", "items": _objeto(propiedades)}


TEXTO = {"type": "string"}

ESQUEMA = _objeto({
    "category": TEXTO,
    "subcategory": TEXTO,
    "tags": {"type": "array", "items": TEXTO},
    "tools": _lista({
        "name": TEXTO,
        "description": TEXTO,
        "tool_type": TEXTO,
        "use_cases": TEXTO,
        "requires_api": {"type": "boolean"},
    }),
    "commands": _lista({
        "command": TEXTO,
        "description": TEXTO,
        "tool_name": TEXTO,
        "os": TEXTO,
        "flags": {"type": "array", "items": TEXTO},
    }),
    "cves": _lista({
        "cve_id": TEXTO,
        "title": TEXTO,
        "description": TEXTO,
        "severity": TEXTO,
        "cvss": {"type": ["number", "null"]},
        "affected": TEXTO,
    }),
    "mitre": _lista({
        "technique_id": TEXTO,
        "technique_name": TEXTO,
        "tactic": TEXTO,
        "context_snippet": TEXTO,
    }),
    "entities": _lista({
        "name": TEXTO,
        "type": TEXTO,
        "description": TEXTO,
    }),
    "relations": {
        "type": "array",
        "items": {"type": "array", "items": TEXTO, "minItems": 2, "maxItems": 2},
    },
})


# ------------------------------------------------------------------------- claude


def _clasificar(resumen: ResumenEscritor) -> dict:
    api_key = os.getenv("ANTHROPIC_API_KEY")
    if not api_key:
        raise RuntimeError("ANTHROPIC_API_KEY no configurada")

    cuerpo = (
        f"TITULO: {resumen.titulo}\n"
        f"TEMAS DETECTADOS: {', '.join(resumen.temas) or 'ninguno'}\n\n"
        f"RESUMEN:\n{resumen.resumen[:LIMITES['recorte_resumen']]}"
    )

    respuesta = anthropic.Anthropic(api_key=api_key).beta.messages.create(
        model=MODELO["principal"],
        max_tokens=MODELO["max_tokens"],
        system=(BASE_DIR / "prompt.md").read_text(encoding="utf-8"),
        messages=[{"role": "user", "content": cuerpo}],
        thinking={"type": "adaptive"},
        output_config={
            "effort": MODELO["effort"],
            "format": {"type": "json_schema", "schema": ESQUEMA},
        },
        # Un corpus de amenazas puede activar el clasificador de seguridad;
        # el reintento en el modelo de respaldo evita perder el documento.
        betas=["server-side-fallback-2026-06-01"],
        fallbacks=[{"model": MODELO["respaldo"]}],
    )

    if respuesta.stop_reason == "refusal":
        raise RuntimeError("el modelo declino agrupar el documento")

    return json.loads(next(b.text for b in respuesta.content if b.type == "text"))


# -------------------------------------------------------------------- validacion


def _visibles(texto: str) -> int:
    """Cuenta solo caracteres con contenido.

    Descarta separadores (Z*) y caracteres de control o invisibles (C*), que
    suman longitud sin aportar nada que se pueda agrupar.
    """
    return sum(1 for c in texto if unicodedata.category(c)[0] not in "ZC")


def _texto(valor, limite: int | None = None) -> str:
    limpio = str(valor or "").strip()
    return limpio[:limite] if limite else limpio


def _unicos(filas: list[dict], clave: str, tope: int) -> list[dict]:
    """Deduplica por clave sin distinguir mayusculas. La columna es UNIQUE en la
    base de datos, asi que un duplicado aqui es una insercion perdida alli."""
    vistos: set[str] = set()
    salida: list[dict] = []
    for fila in filas:
        marca = fila[clave].lower()
        if marca not in vistos:
            vistos.add(marca)
            salida.append(fila)
    return salida[:tope]


def _validar(bruto: dict) -> dict:
    categoria = _texto(bruto.get("category")).lower()

    herramientas = [
        {
            "name": _texto(t.get("name"), 200),
            "description": _texto(t.get("description")),
            "tool_type": "web" if _texto(t.get("tool_type")).lower() == "web" else "software",
            "use_cases": _texto(t.get("use_cases")),
            "requires_api": bool(t.get("requires_api")),
        }
        for t in bruto.get("tools") or []
        if _texto(t.get("name"))
    ]

    comandos = [
        {
            "command": _texto(c.get("command")),
            "description": _texto(c.get("description")),
            "tool_name": _texto(c.get("tool_name"), 200),
            "os": sistema if (sistema := _texto(c.get("os")).lower()) in SISTEMAS else "linux",
            "flags": [_texto(f) for f in (c.get("flags") or []) if _texto(f)],
        }
        for c in bruto.get("commands") or []
        if _texto(c.get("command"))
    ]

    cves = [
        {
            "cve_id": _texto(v.get("cve_id")).upper(),
            "title": _texto(v.get("title"), 500),
            "description": _texto(v.get("description")),
            "severity": _texto(v.get("severity")).lower() or None,
            "cvss": puntos if isinstance(puntos := v.get("cvss"), (int, float)) and 0 <= puntos <= 10 else None,
            "affected": _texto(v.get("affected")),
        }
        for v in bruto.get("cves") or []
        if RE_CVE.match(_texto(v.get("cve_id")))
    ]

    mitre = [
        {
            "technique_id": _texto(m.get("technique_id")).upper(),
            "technique_name": _texto(m.get("technique_name"), 300),
            "tactic": TACTICAS.get(_texto(m.get("tactic")).lower(), ""),
            "context_snippet": _texto(m.get("context_snippet"), 200),
        }
        for m in bruto.get("mitre") or []
        if RE_MITRE.match(_texto(m.get("technique_id")))
    ]

    entidades = [
        {
            "name": _texto(e.get("name"), LIMITES["longitud_nombre_entidad"]),
            "type": tipo if (tipo := _texto(e.get("type")).lower()) in TIPOS_ENTIDAD else "concept",
            "description": _texto(e.get("description")),
        }
        for e in bruto.get("entities") or []
        if _texto(e.get("name"))
    ]

    herramientas = _unicos(herramientas, "name", LIMITES["max_herramientas"])
    cves = _unicos(cves, "cve_id", LIMITES["max_cves"])
    mitre = _unicos(mitre, "technique_id", LIMITES["max_mitre"])
    entidades = _unicos(entidades, "name", LIMITES["max_entidades"])

    # Una relacion hacia una entidad que no existe deja un nodo huerfano en el grafo.
    nombres = {e["name"].lower(): e["name"] for e in entidades}
    relaciones: list[list[str]] = []
    for par in bruto.get("relations") or []:
        if not isinstance(par, list) or len(par) != 2:
            continue
        a, b = nombres.get(_texto(par[0]).lower()), nombres.get(_texto(par[1]).lower())
        if a and b and a != b and [a, b] not in relaciones and [b, a] not in relaciones:
            relaciones.append([a, b])

    return {
        "category": categoria if categoria in CATEGORIAS else "teoria",
        "subcategory": _texto(bruto.get("subcategory"), 100) or None,
        "tags": [_texto(t).lower() for t in (bruto.get("tags") or []) if _texto(t)][
            : LIMITES["max_etiquetas"]
        ],
        "tools": herramientas,
        "commands": comandos[: LIMITES["max_comandos"]],
        "cves": cves,
        "mitre": mitre,
        "entities": entidades,
        "relations": relaciones[: LIMITES["max_relaciones"]],
    }


# ---------------------------------------------------------------------- entrega


def _entregar(url: str, timeout: float, payload: dict) -> bool:
    if not url:
        return False
    try:
        respuesta = httpx.post(url, json=payload, timeout=timeout)
        respuesta.raise_for_status()
        return True
    except httpx.HTTPError:
        # La agrupacion ya esta escrita en disco: que el destino este caido no
        # invalida el trabajo hecho ni obliga a repetir la llamada al modelo.
        return False


# ----------------------------------------------------------------- orquestacion


def _procesar(resumen: ResumenEscritor) -> dict:
    # No es un fallo al agrupar, sino material insuficiente: lleva mensaje propio
    # porque reintentar con el mismo texto no puede arreglarlo.
    if _visibles(resumen.resumen) < LIMITES["caracteres_minimos"]:
        raise HTTPException(422, ERRORES["resumen_corto"])

    try:
        agrupacion = _validar(_clasificar(resumen))
    except Exception:
        raise HTTPException(500, ERRORES["generico"])

    payload = {
        "id_resumen": resumen.id,
        "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "source": resumen.source or "escritor",
        "titulo": resumen.titulo,
        "archivo_original": resumen.archivo_original,
        # Viaja entero y sin recortar: es el cuerpo de la nota en ambos destinos
        # —notes.content no admite nulo— y el recorte de arriba solo afecta a lo
        # que se le manda al modelo.
        "resumen": resumen.resumen,
        **agrupacion,
    }

    try:
        # El nombre es el id del resumen: reintentar sobrescribe en vez de acumular.
        (SALIDA_DIR / f"{resumen.id}.json").write_text(
            json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8"
        )
    except OSError:
        raise HTTPException(500, ERRORES["generico"])

    return {
        **payload,
        "bbdd_entregado": _entregar(BBDD_URL, CFG["bbdd"]["timeout_segundos"], payload),
        "obsi_entregado": _entregar(OBSI_URL, CFG["obsi"]["timeout_segundos"], payload),
    }


@router.post("/agrupar")
async def agrupar(resumen: ResumenEscritor):
    """Entrada del Escritor: el resumen ya validado como ciberseguridad."""
    return _procesar(resumen)
