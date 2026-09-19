"""Agente Escritor de CyberKB.

Filtra y resume documentos de ciberseguridad. Expone dos entradas: una para ficheros
subidos desde la app y otra para texto enviado por el agente Cinefilo. El endpoint por
el que entra la peticion determina el origen.

Para engancharlo en main.py. El repositorio de agentes es hermano del de la app y su
nombre lleva guion, asi que no se puede importar como paquete:

    import sys
    from pathlib import Path
    sys.path.insert(0, str(
        Path(__file__).resolve().parent.parent / "Agentes-CyberKB" / "Editor" / "Escritor"
    ))
    from escritor import router as escritor_router
    app.include_router(escritor_router)
"""

from __future__ import annotations

import json
import os
import shutil
import unicodedata
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal
from xml.sax.saxutils import escape

import anthropic
import httpx
from fastapi import APIRouter, File, Form, HTTPException, UploadFile
from fastapi.responses import FileResponse
from pydantic import BaseModel
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer

import document_parser as parser

BASE_DIR = Path(__file__).resolve().parent
CFG = json.loads((BASE_DIR / "config.json").read_text(encoding="utf-8"))

MODELO = CFG["modelo"]
LIMITES = CFG["limites"]
MENSAJES = CFG["mensajes"]

MIN_CARACTERES = LIMITES["min_caracteres_entrada"]
EXTENSIONES = tuple(LIMITES["extensiones"])
MSG_MIN_CARACTERES = MENSAJES["min_caracteres"]
MSG_ERROR = MENSAJES["error"]
# Cuelga de la carpeta del agente, no del directorio desde el que se arranque el
# proceso: asi los resumenes viven siempre junto al Escritor.
SALIDA_DIR = Path(os.getenv("ESCRITOR_OUTPUT_DIR") or BASE_DIR / "resumenes").resolve()
SALIDA_DIR.mkdir(parents=True, exist_ok=True)

AGRUPADOR_URL = os.getenv("AGRUPADOR_URL", "")

router = APIRouter(prefix="/api/escritor", tags=["escritor"])


class TextoAgente(BaseModel):
    texto: str
    titulo: str | None = None
    origen_id: str | None = None


ESQUEMA_RESUMEN = {
    "type": "object",
    "properties": {
        "titulo": {"type": "string"},
        "resumen": {"type": "string"},
        "temas": {"type": "array", "items": {"type": "string"}},
        "es_ciberseguridad": {"type": "boolean"},
    },
    "required": ["titulo", "resumen", "temas", "es_ciberseguridad"],
    "additionalProperties": False,
}


def _visibles(texto: str) -> int:
    """Cuenta solo caracteres con contenido.

    Descarta separadores (Z*) y caracteres de control o invisibles (C*): un PDF
    escaneado o mal extraido llega con miles de saltos de linea, marcas BOM o
    espacios de ancho cero que suman longitud sin decir nada, y bastaban para
    superar el minimo y pagar una llamada al modelo.
    """
    return sum(1 for c in texto if unicodedata.category(c)[0] not in "ZC")


def _prompt_sistema() -> str:
    return (BASE_DIR / "prompt.md").read_text(encoding="utf-8")


def _cliente() -> anthropic.Anthropic:
    # Se construye por peticion: la app permite cambiar la clave en caliente
    # desde POST /api/settings.
    api_key = os.getenv("ANTHROPIC_API_KEY")
    if not api_key:
        raise RuntimeError("ANTHROPIC_API_KEY no configurada")
    return anthropic.Anthropic(api_key=api_key)


def _resumir(texto: str) -> dict:
    respuesta = _cliente().beta.messages.create(
        model=MODELO["id"],
        max_tokens=MODELO["max_tokens"],
        system=_prompt_sistema(),
        messages=[{"role": "user", "content": texto}],
        thinking={"type": "adaptive"},
        output_config={
            "effort": MODELO["effort"],
            "format": {"type": "json_schema", "schema": ESQUEMA_RESUMEN},
        },
        # Un corpus de ciberseguridad puede activar el clasificador de seguridad;
        # el reintento en el modelo de respaldo evita perder el documento.
        betas=["server-side-fallback-2026-06-01"],
        fallbacks=[{"model": MODELO["respaldo"]}],
    )

    if respuesta.stop_reason == "refusal":
        raise RuntimeError("el modelo declino resumir el documento")

    bruto = next(b.text for b in respuesta.content if b.type == "text")
    return json.loads(bruto)


def _a_pdf(destino: Path, titulo: str, resumen: str, origen: str, fecha: str) -> None:
    hojas = getSampleStyleSheet()
    cuerpo = ParagraphStyle("cuerpo", parent=hojas["BodyText"], leading=15, spaceAfter=7)
    epigrafe = ParagraphStyle(
        "epigrafe", parent=hojas["Heading2"], fontSize=13, spaceBefore=12, spaceAfter=5
    )
    vineta = ParagraphStyle("vineta", parent=cuerpo, leftIndent=12, bulletIndent=4)

    doc = SimpleDocTemplate(
        str(destino),
        pagesize=A4,
        title=titulo,
        author="CyberKB - Agente Escritor",
        leftMargin=22 * mm,
        rightMargin=22 * mm,
        topMargin=20 * mm,
        bottomMargin=20 * mm,
    )

    piezas = [
        Paragraph(escape(titulo), hojas["Title"]),
        Paragraph(f"Origen: {escape(origen)} &nbsp;|&nbsp; {escape(fecha)}", hojas["Italic"]),
        Spacer(1, 8 * mm),
    ]

    for linea in resumen.splitlines():
        linea = linea.strip()
        if not linea:
            continue
        if linea.startswith("#"):
            piezas.append(Paragraph(escape(linea.lstrip("# ").strip()), epigrafe))
        elif linea.startswith(("- ", "* ")):
            piezas.append(Paragraph(escape(linea[2:].strip()), vineta, bulletText="•"))
        else:
            piezas.append(Paragraph(escape(linea), cuerpo))

    doc.build(piezas)


def _enviar_a_agrupador(payload: dict) -> bool:
    if not AGRUPADOR_URL:
        return False
    try:
        respuesta = httpx.post(
            AGRUPADOR_URL, json=payload, timeout=LIMITES["timeout_agrupador_segundos"]
        )
        respuesta.raise_for_status()
        return True
    except httpx.HTTPError:
        # El resumen ya existe y el PDF es descargable: que el Agrupador este caido
        # no invalida el trabajo hecho.
        return False


def _procesar(texto: str, origen: Literal["app", "cinefilo"], nombre: str) -> dict:
    # El recuento va sobre el texto sin espacios: un PDF que solo tiene saltos de
    # linea suma miles de caracteres y llegaria a pagar una llamada al modelo.
    if _visibles(texto) < MIN_CARACTERES:
        raise HTTPException(422, MSG_MIN_CARACTERES)

    try:
        analisis = _resumir(texto)
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(500, MSG_ERROR)

    if not analisis["es_ciberseguridad"] or _visibles(analisis["resumen"]) < MIN_CARACTERES // 8:
        raise HTTPException(422, MSG_MIN_CARACTERES)

    resumen_id = uuid.uuid4().hex
    fecha = datetime.now(timezone.utc).isoformat(timespec="seconds")

    try:
        (SALIDA_DIR / f"{resumen_id}.txt").write_text(
            f"{analisis['titulo']}\n\n{analisis['resumen']}\n", encoding="utf-8"
        )
        _a_pdf(
            SALIDA_DIR / f"{resumen_id}.pdf",
            analisis["titulo"],
            analisis["resumen"],
            origen,
            fecha,
        )
    except Exception:
        raise HTTPException(500, MSG_ERROR)

    payload = {
        "id": resumen_id,
        "timestamp": fecha,
        "source": origen,
        "archivo_original": nombre,
        "titulo": analisis["titulo"],
        "resumen": analisis["resumen"],
        "temas": analisis["temas"],
        "caracteres_originales": len(texto),
        "caracteres_resumen": len(analisis["resumen"]),
    }
    (SALIDA_DIR / f"{resumen_id}.json").write_text(
        json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8"
    )

    return {
        **payload,
        "pdf_url": f"/api/escritor/pdf/{resumen_id}",
        "agrupador_entregado": _enviar_a_agrupador(payload),
    }


@router.post("/resumen")
async def resumir_desde_app(file: UploadFile = File(...), titulo: str | None = Form(None)):
    """Entrada de la app: el usuario sube un documento."""
    ext = Path(file.filename).suffix.lower()
    if ext not in EXTENSIONES:
        raise HTTPException(400, f"Tipo de fichero no soportado: {ext}")

    destino = SALIDA_DIR / f"entrada_{uuid.uuid4().hex}{ext}"
    try:
        with open(destino, "wb") as salida:
            shutil.copyfileobj(file.file, salida)
        texto = parser.parse_file(str(destino), file.filename)
    except Exception:
        raise HTTPException(500, MSG_ERROR)
    finally:
        destino.unlink(missing_ok=True)

    return _procesar(texto, "app", titulo or file.filename)


@router.post("/resumen-agente")
async def resumir_desde_cinefilo(data: TextoAgente):
    """Entrada del agente Cinefilo: texto ya extraido."""
    return _procesar(data.texto, "cinefilo", data.titulo or data.origen_id or "cinefilo")


@router.get("/pdf/{resumen_id}")
async def descargar_pdf(resumen_id: str):
    ruta = SALIDA_DIR / f"{resumen_id}.pdf"
    if not resumen_id.isalnum() or not ruta.is_file():
        raise HTTPException(404, "Resumen no encontrado")
    return FileResponse(ruta, media_type="application/pdf", filename=f"resumen_{resumen_id}.pdf")
