# Agente Escritor

Lee un documento, descarta todo lo que no sea ciberseguridad, lo resume y emite dos
salidas: un **PDF** que la app ofrece al usuario y un **JSON** que viaja al agente
**Agrupador**.

```
Cinefilo ─┐
          ├─> Escritor ─> PDF (app)  +  JSON (Agrupador)
App ──────┘
```

El ciclo es el mismo venga de donde venga el texto. Lo único que cambia es la puerta
de entrada, y esa puerta es lo que identifica el origen.

## Entradas

| Endpoint | Origen | Cuerpo |
|---|---|---|
| `POST /api/escritor/resumen` | `app` | `multipart/form-data`: `file` (`.pdf .odt .txt .md .log`), `titulo` opcional |
| `POST /api/escritor/resumen-agente` | `cinefilo` | `application/json`: `{ "texto": "...", "titulo": "...", "origen_id": "..." }` |

No hay cabeceras ni campos que declaren el origen: el endpoint por el que llega la
petición **es** el origen. Un emisor no puede falsear de dónde viene ni olvidarse de
indicarlo.

La ruta de la app reutiliza `document_parser.parse_file()`, el mismo parser que ya usa
`POST /api/upload`, de modo que los PDF y ODT se extraen igual que en el resto de CyberKB.

## Ciclo de trabajo

1. **Recibir** el fichero o el texto por uno de los dos endpoints.
2. **Leer y contar** los caracteres del texto extraído.
3. **Validar el mínimo**: por debajo de 4000 caracteres visibles se cancela todo (ver Reglas).
4. **Filtrar**: se descarta cuanto no pertenezca al campo de la ciberseguridad.
5. **Resumir**: pirámide invertida, apertura ejecutiva, epígrafes temáticos y cierre
   accionable. Los criterios completos viven en [prompt.md](prompt.md), que el agente
   carga en cada petición; editarlo cambia el comportamiento sin tocar código.
6. **Generar** `.txt`, `.pdf` y `.json` en la carpeta de salida.
7. **Entregar**: el PDF queda descargable y el JSON se envía al Agrupador.

## Salidas

Los tres ficheros se escriben en `ESCRITOR_OUTPUT_DIR` (por defecto `resumenes/`, dentro
de la carpeta del agente),
nombrados con el identificador del resumen.

- `{id}.txt` — el resumen en texto plano.
- `{id}.pdf` — descargable en `GET /api/escritor/pdf/{id}`.
- `{id}.json` — copia en disco de lo que se envía al Agrupador.

La respuesta HTTP devuelve ese mismo JSON más `pdf_url` y `agrupador_entregado`:

```json
{
  "id": "9f2c...",
  "timestamp": "2026-09-18T10:22:04+00:00",
  "source": "cinefilo",
  "archivo_original": "informe-nis2.pdf",
  "titulo": "Obligaciones de notificacion bajo NIS2",
  "resumen": "...",
  "temas": ["nis2", "cumplimiento", "respuesta-incidentes"],
  "caracteres_originales": 18420,
  "caracteres_resumen": 3180,
  "pdf_url": "/api/escritor/pdf/9f2c...",
  "agrupador_entregado": true
}
```

## Reglas

1. **Mínimo de 4000 caracteres, contando solo los que se ven.** Por debajo de esa cifra
   no se inicia el resumen: la petición responde `422` con el texto exacto
   `El resumen no llega al minimo de caracteres requeridos para iniciar el resumen.`

   Espacios, saltos de línea, tabuladores, marcas BOM y caracteres de ancho cero **no
   suman**. Un PDF escaneado sin capa de texto llega con miles de esos caracteres: antes
   superaba el umbral y se pagaba una llamada al modelo para resumir la nada.

   El efecto secundario es que el umbral se vuelve más exigente que antes: en texto
   técnico en español los espacios son cerca del 16 %, así que hacen falta unos 4750
   caracteres en bruto para reunir 4000 visibles. Si prefieres el comportamiento
   anterior, baja `min_caracteres_entrada` a unos 3400 en [config.json](config.json).
   Se aplica igual si el documento supera el umbral pero, una vez filtrado, no contiene
   materia de ciberseguridad.
2. **Cualquier error durante la creación del resumen** responde `500` con
   `Ha pasado algo, vuelve a intentarlo.` La app muestra ese mensaje tal cual.
3. **El origen se deduce del endpoint**, nunca de datos que envíe el llamante.

Que el Agrupador esté caído no se considera un error del resumen: el PDF ya existe y es
descargable, así que la respuesta llega con `agrupador_entregado: false` en lugar de
fallar. El JSON queda en disco para reenviarlo.

## Configuración

Todo lo ajustable vive en [config.json](config.json) y el agente lo lee al arrancar:

| Bloque | Contiene |
|---|---|
| `modelo` | Modelo (`claude-opus-5`), respaldo, `max_tokens` y esfuerzo de razonamiento |
| `limites` | Mínimo de caracteres, extensiones admitidas y tiempo de espera del Agrupador |
| `mensajes` | Los dos textos de error que la app muestra tal cual |

El fichero no repite nada que esté en este README, y el código no repite nada que esté en
el fichero: los dos textos de error y el umbral de 4000 caracteres que aparecen en
**Reglas** salen de ahí, así que cambiarlos en `config.json` cambia el comportamiento de
verdad.

## Integración en la app

Los dos repositorios son carpetas hermanas:

```
C:\Users\Usuario\
├── Agentes-CyberKB\                              <- este repositorio
│   └── Editor\Escritor\escritor.py
└── Proyecto-Master-Ciberseguridad-Evolve-...\    <- la app
    └── main.py
```

El nombre `Agentes-CyberKB` lleva guion, así que no es importable como paquete de
Python. Se añade al `sys.path` resolviendo la carpeta hermana:

```python
import sys
from pathlib import Path

sys.path.insert(0, str(
    Path(__file__).resolve().parent.parent / "Agentes-CyberKB" / "Editor" / "Escritor"
))
from escritor import router as escritor_router

app.include_router(escritor_router)
```

Si algún día los dos repositorios dejan de ser hermanos, esta es la única línea que hay
que tocar.

### Dependencia nueva

La generación del PDF usa **reportlab**, ya añadido al `requirements.txt` de la app
(`pdfplumber` solo lee PDF, no los escribe). Instalarlo en el entorno virtual:

```bash
pip install -r requirements.txt
```

### Variables de entorno

| Variable | Uso |
|---|---|
| `ANTHROPIC_API_KEY` | Clave de Claude. Ya la gestiona `POST /api/settings`; el agente la relee en cada petición, así que un cambio en caliente surte efecto sin reiniciar. |
| `AGRUPADOR_URL` | Endpoint de ingesta del Agrupador. Sin definir, el JSON se guarda en disco y no se envía. |
| `ESCRITOR_OUTPUT_DIR` | Carpeta de salida. Por defecto `resumenes/`, dentro de esta misma carpeta. |

## Limitaciones conocidas

- Solo texto: no analiza imágenes, binarios ni audio. Un PDF escaneado sin capa de texto
  entrega cadena vacía y cae en la regla de los 4000 caracteres.
- Espera español o inglés; no traduce.
- El resumen no se persiste en la base de datos de CyberKB. Si debe aparecer como `Note`
  junto al resto del conocimiento, esa parte la hace el Agrupador.
- Si el modelo declina resumir el documento —posible con corpus de malware— hay un
  reintento automático en el modelo de respaldo antes de devolver el error genérico.

---

**Versión** 1.0 · **Flujo** Cinefilo→Escritor→Agrupador · App→Escritor→Agrupador
