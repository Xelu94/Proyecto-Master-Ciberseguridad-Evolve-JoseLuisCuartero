# Agente Cinefilo

Convierte un vídeo en texto. Recibe una URL, saca de ella lo que se dice —subtítulos
oficiales si los hay, transcripción del audio si no—, comprueba que sea ciberseguridad
y entrega el resultado al agente **Escritor**.

```
App ──URL──> Cinefilo ──texto──> Escritor ──> PDF (app) + JSON (Agrupador)
                  │
                  └──> {id}.json en disco
```

## Entradas

| Endpoint | Origen | Cuerpo |
|---|---|---|
| `POST /api/cinefilo/transcribir` | `app` | `application/json`: `{ "url": "https://...", "titulo": "..." }` (`titulo` opcional) |

Sirve cualquier URL que [yt-dlp](https://github.com/yt-dlp/yt-dlp) sepa abrir: YouTube,
Vimeo, y el fichero de vídeo servido directamente.

## Ciclo de trabajo

1. **Leer la URL** que llega desde la app.
2. **Comprobar que es un vídeo**: esquema `http(s)`, host público y metadatos legibles con
   duración real. Lo que no lo sea se rechaza aquí (ver Reglas).
3. **Descartar por metadatos**: título, canal, etiquetas y descripción pasan por el
   clasificador antes de gastar una transcripción. Solo corta ante un «no» rotundo; en
   caso de duda el vídeo continúa.
4. **Sacar el texto**, por uno de dos caminos:
   - **Subtítulos oficiales** en español o inglés, si el vídeo los publica. Se descarga
     el WebVTT y se limpia de marcas de tiempo, etiquetas y líneas repetidas.
   - **Transcripción del audio** en caso contrario: se descarga la mejor pista de audio,
     se normaliza a mono 16 kHz y se envía a `gpt-transcribe`.
5. **Clasificar el texto real**: este es el juicio definitivo sobre si hay materia de
   ciberseguridad. Los criterios viven en [prompt.md](prompt.md), que el agente carga en
   cada petición; editarlo cambia el comportamiento sin tocar código.
6. **Guardar** `{id}.json` en la carpeta de salida.
7. **Entregar** el texto al Escritor por `POST /api/escritor/resumen-agente`.

Los subtítulos oficiales van primero porque los revisa una persona: no alucinan, no
confunden acrónimos y no cuestan nada. La transcripción es el plan B.

## Salidas

El JSON se escribe en `CINEFILO_OUTPUT_DIR` (por defecto `videos/`, dentro de la carpeta
del agente) con el identificador
del trabajo, y se devuelve en la respuesta HTTP junto a `escritor_entregado`:

```json
{
  "id": "4b81...",
  "timestamp": "2026-09-18T17:40:12+00:00",
  "source": "cinefilo",
  "video_url": "https://www.youtube.com/watch?v=...",
  "titulo": "Obligaciones de notificacion bajo NIS2",
  "texto": "...",
  "fuente_texto": "subtitulos",
  "duracion_segundos": 1840,
  "idioma_detectado": "es",
  "caracteres": 21430,
  "temas": ["nis2", "cumplimiento", "respuesta-incidentes"],
  "certeza_clasificacion": 0.96,
  "motivo_clasificacion": "Charla sobre plazos de notificacion y organos competentes bajo NIS2.",
  "escritor_entregado": true
}
```

Al Escritor solo viajan los tres campos que su endpoint acepta —`texto`, `titulo` y
`origen_id`—; el resto queda en disco como trazabilidad.

## Reglas

1. **La URL debe llevar a un vídeo.** Si no lo es —esquema raro, host privado, página sin
   vídeo, duración nula, vídeo más largo que el límite o descarga imposible— la petición
   responde `400` con el texto exacto
   `Comprueba la URL, no parece ser de video.`
2. **Solo ciberseguridad.** Si el material no trata de seguridad de la información se
   cancela el proceso y la petición responde `422` con el texto exacto
   `Esto no es ciberseguridad.`
   Se aplica igual cuando el vídeo no deja texto aprovechable: un vídeo sin habla no
   contiene materia de ciberseguridad.
3. **Los subtítulos oficiales mandan.** Si el vídeo publica subtítulos propios en un
   idioma soportado y el material es de ciberseguridad, se usan como texto y no se
   transcribe nada. Los generados automáticamente **no** cuentan como oficiales y están
   desactivados en `config.json`; son transcripciones de máquina sin revisar, y para eso
   ya está el motor de voz.

Cualquier otro fallo durante el proceso responde `500` con
`Ha pasado algo, vuelve a intentarlo.`, la misma convención que usa el Escritor.

Que el Escritor esté caído —o que rechace el texto por quedarse corto— no se considera un
error del Cinéfilo: el JSON ya existe en disco, así que la respuesta llega con
`escritor_entregado: false` en lugar de fallar.

## Configuración

Todo lo ajustable vive en [config.json](config.json) y el agente lo lee en cada arranque:
modelos, idiomas de subtítulos, límites de duración y troceo, umbral de descarte por
metadatos y los tres mensajes de error. Los términos de dominio que se le pasan al motor
de voz también están ahí: son los que evitan que «NIS2» acabe escrito «nisdos».

### Variables de entorno

| Variable | Uso |
|---|---|
| `ANTHROPIC_API_KEY` | Clave de Claude para el clasificador. Ya la gestiona `POST /api/settings` de la app. |
| `OPENAI_API_KEY` | Clave de OpenAI para `gpt-transcribe`. |
| `ESCRITOR_URL` | Endpoint del Escritor. Por defecto el de `config.json`. |
| `CINEFILO_OUTPUT_DIR` | Carpeta de salida. Por defecto `videos/`, dentro de esta misma carpeta. |

## Integración en la app

Los dos repositorios son carpetas hermanas:

```
C:\Users\Usuario\
├── Agentes-CyberKB\                              <- este repositorio
│   └── Editor\Cinefilo\cinefilo.py
└── Proyecto-Master-Ciberseguridad-Evolve-...\    <- la app
    └── main.py
```

El nombre `Agentes-CyberKB` lleva guion, así que no es importable como paquete de
Python. Se añade al `sys.path` resolviendo la carpeta hermana:

```python
import sys
from pathlib import Path

sys.path.insert(0, str(
    Path(__file__).resolve().parent.parent / "Agentes-CyberKB" / "Editor" / "Cinefilo"
))
from cinefilo import router as cinefilo_router

app.include_router(cinefilo_router)
```

### Dependencias nuevas

`yt-dlp` y `openai` están añadidas al `requirements.txt` de la app:

```bash
pip install -r requirements.txt
```

Además hace falta **ffmpeg** en el `PATH` del sistema: normaliza el audio antes de
transcribirlo y lo trocea cuando supera el límite por petición. No se instala con pip.

```bash
winget install Gyan.FFmpeg
```

## Limitaciones conocidas

- **Un vídeo sin habla no da nada.** Música, pantallazos mudos o audio ininteligible
  producen texto vacío, que se trata como «no es ciberseguridad». El mínimo de
  caracteres cuenta solo los que se ven: espacios, saltos y marcas invisibles no
  suman, así que unos subtítulos rotos no pueden colarse por longitud.
- **Español e inglés.** Otros idiomas se transcriben peor y el clasificador los juzga con
  menos base. El material que mezcla dos idiomas en la misma frase es el peor caso del
  motor de voz.
- **El motor de voz no puntúa su propia salida.** `gpt-transcribe` devuelve texto y nada
  más, así que no hay forma de medir la confianza de la transcripción desde la API. La
  certeza que aparece en el JSON es la del clasificador sobre el tema, no sobre la
  fidelidad de las palabras.
- **Las cifras se transcriben mal.** Identificadores CVE, versiones y plazos son lo
  primero que un motor de voz se inventa. Lo que salga de un vídeo merece verificarse
  contra la fuente antes de darlo por bueno.
- **La comprobación de URL no cubre todo.** Se rechazan esquemas no `http(s)` y hosts que
  resuelven a direcciones privadas, pero una redirección posterior escapa a ese control.
  El agente está pensado para URLs que teclea una persona, no para ingesta automática de
  enlaces de terceros.
- **El texto de un vídeo es material sin filtrar.** Puede contener frases dirigidas a un
  sistema automático; el prompt del clasificador las trata como contenido, nunca como
  instrucciones, y lo mismo debe hacer cualquier agente que consuma su salida.
- **Coste por vídeo.** La rama de subtítulos es gratis; la de transcripción se paga por
  minuto de audio. El descarte por metadatos existe justamente para no pagarla en balde.

---

**Versión** 1.0 · **Flujo** App→Cinefilo→Escritor→Agrupador
