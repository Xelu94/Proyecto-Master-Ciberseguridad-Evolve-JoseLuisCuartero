"""Agente Cinefilo de CyberKB.

Convierte un video en texto: descarga sus subtitulos oficiales o, si no los tiene,
transcribe su audio. Comprueba que el material sea ciberseguridad, guarda el resultado
en JSON y se lo entrega al agente Escritor.

Para engancharlo en main.py. El repositorio de agentes es hermano del de la app y su
nombre lleva guion, asi que no se puede importar como paquete:

    import sys
    from pathlib import Path
    sys.path.insert(0, str(
        Path(__file__).resolve().parent.parent / "Agentes-CyberKB" / "Editor" / "Cinefilo"
    ))
    from cinefilo import router as cinefilo_router
    app.include_router(cinefilo_router)
"""

from __future__ import annotations

import ipaddress
import json
import os
import re
import socket
import subprocess
import tempfile
import unicodedata
import uuid
from datetime import datetime, timezone
from pathlib import Path
from shutil import rmtree
from urllib.parse import urlsplit

import anthropic
import httpx
import yt_dlp
from fastapi import APIRouter, HTTPException
from openai import OpenAI
from pydantic import BaseModel

BASE_DIR = Path(__file__).resolve().parent
CFG = json.loads((BASE_DIR / "config.json").read_text(encoding="utf-8"))

CLASIFICADOR = CFG["clasificador"]
SUBTITULOS = CFG["subtitulos"]
TRANSCRIPCION = CFG["transcripcion"]
LIMITES = CFG["limites"]
RED = CFG["red"]
ERRORES = CFG["errores"]

# Cuelga de la carpeta del agente, no del directorio desde el que se arranque el
# proceso: asi los videos procesados viven siempre junto al Cinefilo.
SALIDA_DIR = Path(
    os.getenv("CINEFILO_OUTPUT_DIR") or BASE_DIR / CFG["salida"]["directorio"]
).resolve()
SALIDA_DIR.mkdir(parents=True, exist_ok=True)

ESCRITOR_URL = os.getenv("ESCRITOR_URL", CFG["escritor"]["url"])

router = APIRouter(prefix="/api/cinefilo", tags=["cinefilo"])


class PeticionVideo(BaseModel):
    url: str
    titulo: str | None = None


ESQUEMA_CLASIFICACION = {
    "type": "object",
    "properties": {
        "es_ciberseguridad": {"type": "boolean"},
        "certeza": {"type": "number"},
        "temas": {"type": "array", "items": {"type": "string"}},
        "motivo": {"type": "string"},
    },
    "required": ["es_ciberseguridad", "certeza", "temas", "motivo"],
    "additionalProperties": False,
}


def _visibles(texto: str) -> int:
    """Cuenta solo caracteres con contenido.

    Descarta separadores (Z*) y caracteres de control o invisibles (C*): una
    transcripcion de un video mudo, o unos subtitulos rotos, pueden sumar miles
    de caracteres que no dicen nada y superar asi el minimo.
    """
    return sum(1 for c in texto if unicodedata.category(c)[0] not in "ZC")


def _error_url() -> HTTPException:
    return HTTPException(400, ERRORES["url_invalida"])


def _error_tema() -> HTTPException:
    return HTTPException(422, ERRORES["no_ciberseguridad"])


def _error_generico() -> HTTPException:
    return HTTPException(500, ERRORES["generico"])


# --------------------------------------------------------------------------- red


def _validar_url(url: str) -> None:
    """Rechaza lo que no sea una URL publica http(s). Cierra la via SSRF mas obvia."""
    partes = urlsplit(url.strip())
    if partes.scheme not in RED["esquemas_permitidos"] or not partes.hostname:
        raise _error_url()

    if not RED["bloquear_direcciones_privadas"]:
        return

    try:
        resueltas = socket.getaddrinfo(partes.hostname, None)
    except socket.gaierror:
        raise _error_url()

    for familia in resueltas:
        ip = ipaddress.ip_address(familia[4][0])
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved:
            raise _error_url()


# ------------------------------------------------------------------------ yt-dlp


def _inspeccionar(url: str) -> dict:
    """Lee los metadatos del video sin descargarlo."""
    opciones = {
        "quiet": True,
        "no_warnings": True,
        "noplaylist": True,
        "socket_timeout": LIMITES["timeout_descarga_segundos"],
    }
    try:
        with yt_dlp.YoutubeDL(opciones) as ydl:
            info = ydl.extract_info(url, download=False)
    except Exception:
        raise _error_url()

    if not info or info.get("_type") == "playlist":
        raise _error_url()

    duracion = info.get("duration")
    if not duracion or duracion <= 0:
        raise _error_url()
    if duracion > LIMITES["duracion_maxima_segundos"]:
        raise _error_url()

    return info


def _url_subtitulos(info: dict) -> str | None:
    """Localiza la pista de subtitulos oficiales. Ignora los generados automaticamente."""
    if not SUBTITULOS["usar_oficiales"]:
        return None

    pistas = info.get("subtitles") or {}
    if SUBTITULOS["usar_automaticos"]:
        pistas = {**(info.get("automatic_captions") or {}), **pistas}

    for idioma in SUBTITULOS["idiomas"]:
        for etiqueta, formatos in pistas.items():
            if not etiqueta.lower().startswith(idioma):
                continue
            for formato in formatos:
                if formato.get("ext") == SUBTITULOS["formato"] and formato.get("url"):
                    return formato["url"]
    return None


def _descargar_subtitulos(url_pista: str) -> str | None:
    try:
        respuesta = httpx.get(
            url_pista,
            timeout=LIMITES["timeout_descarga_segundos"],
            follow_redirects=True,
        )
        respuesta.raise_for_status()
    except httpx.HTTPError:
        return None

    texto = _vtt_a_texto(respuesta.text)
    return texto or None


def _vtt_a_texto(vtt: str) -> str:
    """Extrae el dialogo de un WebVTT: sin marcas de tiempo, etiquetas ni repeticiones."""
    lineas: list[str] = []
    for linea in vtt.splitlines():
        linea = linea.strip()
        if not linea or "-->" in linea or linea.startswith(("WEBVTT", "NOTE", "STYLE", "Kind:", "Language:")):
            continue
        if linea.isdigit():
            continue
        linea = re.sub(r"<[^>]+>", "", linea).strip()
        # Los subtitulos rodantes repiten la linea anterior en cada fotograma de texto.
        if linea and (not lineas or lineas[-1] != linea):
            lineas.append(linea)
    return " ".join(lineas)


def _descargar_audio(url: str, destino: Path) -> Path:
    """Descarga la mejor pista de audio disponible."""
    opciones = {
        "format": "bestaudio/best",
        "outtmpl": str(destino / "audio.%(ext)s"),
        "quiet": True,
        "no_warnings": True,
        "noplaylist": True,
        "socket_timeout": LIMITES["timeout_descarga_segundos"],
    }
    try:
        with yt_dlp.YoutubeDL(opciones) as ydl:
            ydl.extract_info(url, download=True)
    except Exception:
        raise _error_url()

    descargados = list(destino.glob("audio.*"))
    if not descargados:
        raise _error_generico()
    return descargados[0]


# ------------------------------------------------------------------------ ffmpeg


def _ffmpeg(argumentos: list[str]) -> None:
    try:
        subprocess.run(
            ["ffmpeg", "-hide_banner", "-loglevel", "error", "-y", *argumentos],
            check=True,
            capture_output=True,
            timeout=LIMITES["timeout_ffmpeg_segundos"],
        )
    except (subprocess.SubprocessError, OSError):
        raise _error_generico()


def _preparar_audio(origen: Path) -> list[Path]:
    """Normaliza a mono 16 kHz —lo que espera un motor de voz— y trocea si hace falta.

    La normalizacion recorta el peso en mas de un orden de magnitud, de modo que la
    mayoria de videos caben en una sola peticion pese al limite de 25 MB.
    """
    normalizado = origen.parent / "normalizado.m4a"
    _ffmpeg(["-i", str(origen), "-vn", "-ac", "1", "-ar", "16000", "-c:a", "aac", "-b:a", "32k", str(normalizado)])

    if normalizado.stat().st_size <= 24 * 1024 * 1024:
        return [normalizado]

    _ffmpeg([
        "-i", str(normalizado),
        "-f", "segment",
        "-segment_time", str(LIMITES["troceo_segundos"]),
        "-reset_timestamps", "1",
        "-c", "copy",
        str(origen.parent / "parte_%03d.m4a"),
    ])
    partes = sorted(origen.parent.glob("parte_*.m4a"))
    if not partes:
        raise _error_generico()
    return partes


# ------------------------------------------------------------------------- openai


def _transcribir(partes: list[Path]) -> str:
    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        raise _error_generico()
    cliente = OpenAI(api_key=api_key, timeout=LIMITES["timeout_transcripcion_segundos"])

    trozos: list[str] = []
    for parte in partes:
        for intento in range(TRANSCRIPCION["max_reintentos"] + 1):
            try:
                with open(parte, "rb") as audio:
                    peticion = {
                        "model": TRANSCRIPCION["modelo"],
                        "file": audio,
                        "prompt": TRANSCRIPCION["terminos_dominio"],
                    }
                    if TRANSCRIPCION["idioma"]:
                        peticion["language"] = TRANSCRIPCION["idioma"]
                    trozos.append(cliente.audio.transcriptions.create(**peticion).text)
                break
            except Exception:
                if intento == TRANSCRIPCION["max_reintentos"]:
                    raise _error_generico()
    return " ".join(t.strip() for t in trozos if t.strip())


# ------------------------------------------------------------------------- claude


def _muestra(texto: str, limite: int = 12000) -> str:
    """Recorta conservando principio, centro y final: la materia util no siempre abre."""
    if len(texto) <= limite:
        return texto
    tercio = limite // 3
    centro = (len(texto) - tercio) // 2
    return (
        f"{texto[:tercio]}\n[...]\n"
        f"{texto[centro:centro + tercio]}\n[...]\n"
        f"{texto[-tercio:]}"
    )


def _clasificar(contenido: str, modo: str) -> dict:
    api_key = os.getenv("ANTHROPIC_API_KEY")
    if not api_key:
        raise _error_generico()

    try:
        respuesta = anthropic.Anthropic(api_key=api_key).beta.messages.create(
            model=CLASIFICADOR["modelo"],
            max_tokens=CLASIFICADOR["max_tokens"],
            system=(BASE_DIR / "prompt.md").read_text(encoding="utf-8"),
            messages=[{"role": "user", "content": f"MODO: {modo}\n\n{contenido}"}],
            thinking={"type": "adaptive"},
            output_config={
                "effort": CLASIFICADOR["effort"],
                "format": {"type": "json_schema", "schema": ESQUEMA_CLASIFICACION},
            },
            # Un corpus de amenazas puede activar el clasificador de seguridad;
            # el reintento en el modelo de respaldo evita perder el video.
            betas=["server-side-fallback-2026-06-01"],
            fallbacks=[{"model": CLASIFICADOR["modelo_respaldo"]}],
        )
    except Exception:
        raise _error_generico()

    if respuesta.stop_reason == "refusal":
        raise _error_generico()

    # El parseo va dentro del control de errores: una respuesta que no sea JSON
    # valido debe salir como error del agente, no como excepcion sin tratar.
    try:
        return json.loads(next(b.text for b in respuesta.content if b.type == "text"))
    except (json.JSONDecodeError, StopIteration):
        raise _error_generico()


def _descarte_por_metadatos(info: dict) -> None:
    """Corta antes de gastar una transcripcion, pero solo ante un 'no' rotundo."""
    ficha = "\n".join(
        filter(None, [
            f"Titulo: {info.get('title', '')}",
            f"Canal: {info.get('uploader', '')}",
            f"Etiquetas: {', '.join(info.get('tags') or [])}",
            f"Descripcion: {(info.get('description') or '')[:2000]}",
        ])
    )
    veredicto = _clasificar(ficha, "metadatos")
    if not veredicto["es_ciberseguridad"]:
        if veredicto["certeza"] >= CLASIFICADOR["certeza_minima_para_descartar"]:
            raise _error_tema()


# ----------------------------------------------------------------------- escritor


def _enviar_a_escritor(payload: dict) -> bool:
    if not ESCRITOR_URL:
        return False
    try:
        respuesta = httpx.post(
            ESCRITOR_URL,
            json={
                "texto": payload["texto"],
                "titulo": payload["titulo"],
                "origen_id": payload["id"],
            },
            timeout=CFG["escritor"]["timeout_segundos"],
        )
        respuesta.raise_for_status()
        return True
    except httpx.HTTPError:
        # El texto ya existe y esta guardado en disco: que el Escritor este caido o
        # rechace el material no invalida el trabajo de extraccion.
        return False


# ------------------------------------------------------------------ orquestacion


def _extraer_texto(url: str, info: dict, trabajo: Path) -> tuple[str, str]:
    """Devuelve (texto, fuente). Los subtitulos oficiales ganan: los revisa una persona."""
    pista = _url_subtitulos(info)
    if pista:
        texto = _descargar_subtitulos(pista)
        if texto and _visibles(texto) >= LIMITES["caracteres_minimos"]:
            return texto, "subtitulos"

    audio = _descargar_audio(url, trabajo)
    return _transcribir(_preparar_audio(audio)), "transcripcion"


def _procesar(url: str, titulo: str | None) -> dict:
    """Red de seguridad: lo que falle de forma imprevista sale como error del
    agente, no como excepcion sin tratar. El Escritor y el Agrupador envuelven
    igual su proceso; sin esto, un JSON del modelo al que le falte una clave
    llega a la app como error interno en vez de como el mensaje de siempre.
    """
    try:
        return _ejecutar(url, titulo)
    except HTTPException:
        raise
    except Exception:
        raise _error_generico()


def _ejecutar(url: str, titulo: str | None) -> dict:
    _validar_url(url)
    info = _inspeccionar(url)
    _descarte_por_metadatos(info)

    trabajo = Path(tempfile.mkdtemp(prefix="cinefilo_"))
    try:
        texto, fuente = _extraer_texto(url, info, trabajo)
    finally:
        rmtree(trabajo, ignore_errors=True)

    # Sin espacios: un video mudo puede dejar una transcripcion de puros blancos.
    if _visibles(texto) < LIMITES["caracteres_minimos"]:
        raise _error_tema()

    veredicto = _clasificar(_muestra(texto), "texto")
    if not veredicto["es_ciberseguridad"]:
        raise _error_tema()

    video_id = uuid.uuid4().hex
    payload = {
        "id": video_id,
        "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "source": "cinefilo",
        "video_url": url,
        "titulo": titulo or info.get("title") or url,
        "texto": texto,
        "fuente_texto": fuente,
        "duracion_segundos": info.get("duration"),
        "idioma_detectado": info.get("language"),
        "caracteres": len(texto),
        "temas": veredicto["temas"],
        "certeza_clasificacion": veredicto["certeza"],
        "motivo_clasificacion": veredicto["motivo"],
    }

    try:
        (SALIDA_DIR / f"{video_id}.json").write_text(
            json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8"
        )
    except OSError:
        raise _error_generico()

    return {**payload, "escritor_entregado": _enviar_a_escritor(payload)}


@router.post("/transcribir")
async def transcribir(peticion: PeticionVideo):
    """Entrada de la app: el usuario pega la URL de un video."""
    return _procesar(peticion.url, peticion.titulo)
