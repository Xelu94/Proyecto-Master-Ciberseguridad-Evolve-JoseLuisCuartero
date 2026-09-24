# Auditoría de Comandos + Plan de integración del Editor (frontend/backend)

Investigación y planificación, sin construir nada. 2026-09-24.

---

## PARTE 1 — Auditoría a fondo del apartado Comandos

La pestaña `⌘ COMANDOS` de CyberKB no es una simple lista: es la unión de **cuatro
mecanismos de datos distintos** con **cuatro comportamientos de persistencia
distintos**. Esto es clave para cuando nuestros agentes escriban en la tabla
`commands`.

### 1.1 — Fuentes de comandos

| Fuente | Cómo entra | ¿A la BBDD real? | Dedup |
|---|---|---|---|
| Análisis de texto/documento con IA | `_persist_commands()` en `main.py`, vía `/api/analyze` o `/api/upload` | Sí, `commands` | **Ninguna** — cada re-análisis duplica |
| Seeds al arrancar la app | `_seed_google_dorks()`, `PRIVESC_COMMANDS` en `main.py` | Sí, `commands`, `os='google'` o `category='privesc'`, `note_id=NULL` | Insert-or-ignore, solo al primer arranque |
| Botón "💾 Guardar en KB" (Enum, SQLi, RevShell, Shell, PrivEsc) | `POST /api/commands` (`create_command`) | Sí, `commands` | Por `(command, category)`, `note_id=NULL` |
| **Técnicas PrivEsc que el usuario crea a mano** | `loadPeTechniques()`/`savePeTechniques()` | **NO — solo `localStorage` del navegador** | N/A |

### 1.2 — Hallazgo que no estaba documentado: PrivEsc vive partido en dos sitios

El panel "⚡ TÉCNICAS DE ESCALADA DE PRIVILEGIOS" (dentro de Comandos) es el caso más
raro de toda la pestaña:

- La **ficha completa** de cada técnica (nombre, comando de detección, comando de
  explotación, tu nota de referencia) se guarda **solo en `localStorage`**
  (`cyberkb_privesc`), nunca en SQLite. Si limpias el navegador o cambias de máquina,
  se pierde — solo sobrevive el `PE_SEED` hardcodeado de 7 técnicas base.
- Pero el botón 💾 de cada línea de comando dentro de esa ficha **sí** llama a
  `saveCmdKB()` → `POST /api/commands` → **eso sí llega a SQLite**, con
  `category='privesc'`.

Consecuencia práctica: **ninguno de nuestros agentes (Agrupador/Agente-BBDD) puede
ver nunca las técnicas PrivEsc que un usuario cree a mano**, porque no pasan por
ningún documento ni vídeo — viven fuera de la cadena de ingesta por diseño de la app.
Esto no es un bug que haya que arreglar nosotros, pero es importante saberlo: si algún
día alguien pregunta "¿por qué el chat/los agentes no saben de mi técnica PrivEsc
personalizada?", la respuesta es esta.

### 1.3 — Generadores de comandos sin persistencia propia

SQLi (`openSqliModal`), Shell stabilizer (`openShellStabModal`), Reverse Shell
(`openRevShellModal`) y Diccionarios (`openDictModal`) son **plantillas JS estáticas**
(arrays `SQLI_PAYLOADS`, `SHELL_STEPS`, `DICT_POLYGLOTS`, `DICT_WORDLISTS` — no vienen
de la BBDD). Cada línea tiene botón de copiar y, casi siempre, botón de "Guardar en
KB" que va a `POST /api/commands`. El stabilizador de shell no tiene botón de guardar
(son pasos genéricos de manual, no comandos de un objetivo concreto).

### 1.4 — Los cinco valores de `os` y la clave de dedup del Agente-BBDD

Ya lo teníamos verificado: los 5 valores (`linux/windows/powershell/google/both`)
están alineados entre app y Agrupador. El Agente-BBDD deduplica por
`(command, note_id)` — decisión ya tomada (opción A, ver conversación previa): cada
comando pertenece a su nota de origen, no se fusiona con lo que ya hubiera de otras
fuentes. Esto queda confirmado como coherente tras esta auditoría más profunda: como
los comandos "sueltos" (seeds, guardado manual, PrivEsc) tienen `note_id=NULL`, nunca
podrían chocar contra los que trae el Agrupador de todas formas.

---

## PARTE 2 — Plan de backend: enganchar los agentes a `main.py`

**Nota**: esto sigue sin ejecutarse — es solo el plan, tal y como se pidió. Sigue en
pie la regla de no tocar `main.py` hasta que el usuario lo pida explícitamente.

### 2.1 — Estado real de las piezas (verificado hoy)

| Pieza | Estado |
|---|---|
| Routers registrados en `main.py` | **Cero** `include_router` — confirmado de nuevo |
| `yt-dlp`, `openai`, `reportlab` | **En `requirements.txt` pero NO instalados** en el `.venv` de la app — ni con `python` del sistema ni con el venv. Hay que correr `pip install -r requirements.txt` de verdad. |
| `ffmpeg` en PATH | **No está instalado** — bloquea la ruta de transcripción por audio de Cinéfilo (la ruta de subtítulos oficiales sí funcionaría sin él) |
| `.env` de la app | Tiene `ANTHROPIC_API_KEY` y `AGRUPADOR_URL`. **Falta `ESCRITOR_URL`**, que Cinéfilo necesita para entregarle el texto a Escritor. **Falta `OBSIDIAN_VAULT_DIR`** (agente Obsi, aún sin construir). |
| Agente Obsi (3b) | No construido — carpeta vacía |
| Agente4-IndexerO (4) | Decisión previa: no hace falta si solo entra información por la pipeline (ver `project_investigacion_obsidian_ia` en memoria) |

### 2.2 — Cómo se registrarían los routers (cuando se decida hacerlo)

Cada agente ya expone su propio `router = APIRouter(prefix=...)`. El patrón, documentado
en cada README, es idéntico para los cuatro:

```python
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "Agentes-CyberKB" / "Editor" / "Cinefilo"))
from cinefilo import router as cinefilo_router
app.include_router(cinefilo_router)
# ... repetir para Escritor, Agrupador, Agente-BBDD, (Obsi cuando exista)
```

Prefijos ya fijados y sin colisión con los 57 endpoints actuales de `main.py`:
`/api/cinefilo`, `/api/escritor`, `/api/agrupador`, `/api/bbdd`, (futuro `/api/obsi`).

### 2.3 — La cadena es SÍNCRONA de punta a punta — implicación real de rendimiento

Esto es importante y no estaba analizado hasta ahora: cuando el frontend llama a
`POST /api/cinefilo/transcribir`, esa petición **no vuelve** hasta que, dentro de la
misma llamada, Cinéfilo ha llamado a Escritor, Escritor ha llamado al Agrupador, y el
Agrupador ha llamado (en paralelo) a Agente-BBDD y a Obsi. Es decir:

```
Frontend ──POST /api/cinefilo/transcribir──▶ Cinéfilo
                                                │  (descarga + transcribe, puede tardar minutos)
                                                ▼
                                             Escritor (POST interno)
                                                │  (1ª llamada a Claude — resumen)
                                                ▼
                                             Agrupador (POST interno)
                                                │  (2ª llamada a Claude — extracción)
                                                ├──▶ Agente-BBDD (POST interno)
                                                └──▶ Obsi (POST interno, en paralelo con BBDD)
                                                ▼
Frontend ◀────────── una sola respuesta HTTP, con todos los *_entregado anidados ─────
```

Un vídeo largo puede tardar **varios minutos** en esa única petición (descarga +
transcripción de audio + 2 llamadas a Claude + 2 escrituras). Esto obliga a:

- Timeouts generosos en cada tramo de la cadena (`config.json` de cada agente ya tiene
  los suyos — hay que revisar que sean coherentes entre sí, el de arriba siempre mayor
  que la suma de los de abajo).
- Un `fetch()` en el frontend sin timeout corto por defecto.
- Una UI que deje claro que es una operación larga (ver Parte 3).
- Si varios usuarios lanzan vídeos a la vez, cada uno ocupa un worker de Uvicorn
  durante todo ese tiempo — con un solo worker (el caso normal en una app así),
  las peticiones se encolan. Aceptable para un uso personal/pequeño equipo; a vigilar
  si esto escala.

### 2.4 — La decisión de fondo que hay que tomar: qué pasa con `/api/upload` y `/api/analyze`

Este es el hallazgo más importante de toda la investigación. La app **ya tiene** un
camino que hace, en una sola llamada a Claude, lo que Escritor+Agrupador hacen en dos:
`POST /api/upload` y `POST /api/analyze` llaman a `ai.analyze_content()` directamente
y guardan con `_persist_commands/_persist_cves/_persist_tools/_persist_mitre` — sin
pasar por ningún agente, y **sin mandar nunca nada a Obsidian**.

Esto dEja tres caminos posibles, y es una decisión de producto, no técnica:

**Opción 1 — Convivencia.** Se deja `/api/upload` tal cual (rápido, un solo modelo,
sin Obsidian) para el uso rápido del botón "⊕ Subir doc", y se añade la cadena de
agentes como un camino **nuevo y separado**, pensado sobre todo para vídeo (que hoy no
existe en absoluto). Menos riesgo, pero mantiene dos lógicas de análisis distintas
para siempre, con el coste de mantenimiento que eso implica.

**Opción 2 — Migración.** `/api/upload` deja de llamar a `ai.analyze_content()` y en
su lugar llama a `POST /api/escritor/resumen` (que ya acepta `multipart/form-data`
con el mismo fichero). Un solo camino de análisis para todo, todo termina también en
Obsidian automáticamente. Coste: pierde el `auto_save` inmediato de hoy (Escritor
resume, pero es el Agrupador quien decide si se guarda) y pasa a costar 2 llamadas a
Claude en vez de 1 — más lento y más caro por documento.

**Opción 3 — Híbrida por umbral.** Documentos cortos (que hoy pasarían igualmente el
mínimo de `/api/analyze`) siguen por el camino rápido; documentos que se suban con
intención de "guardar en el conocimiento permanente" van por la cadena de agentes.
Requiere una decisión de UI de qué botón dispara cuál.

**No elijo ninguna por mi cuenta** — es justo el tipo de decisión que cambia el
comportamiento de la app para el usuario final. Lo dejo listo para que se decida
cuando se aborde la construcción real.

---

## PARTE 3 — Plan de frontend: extender la pestaña `✎ EDITOR` existente

Hallazgo clave: **ya existe una pestaña `EDITOR`** en la app (`panel-editor`, primera
pestaña, activa por defecto) — con título, categoría, tags, textarea, y una zona de
arrastrar-y-soltar documento. Es el sitio natural para la nueva funcionalidad, no hay
que inventar una pestaña nueva.

### 3.1 — Qué le falta hoy y qué habría que añadir

1. **Un campo de URL de vídeo.** No existe ningún input de URL en toda la pestaña
   Editor hoy. Se añadiría una fila nueva, con el mismo lenguaje visual que la barra
   de consulta de OSINT (`osint-query-bar`: input + botón "▶ Ejecutar"), aquí con
   placeholder tipo "Pega una URL de YouTube/Vimeo..." y botón "▶ Transcribir",
   llamando a `POST /api/cinefilo/transcribir`.

2. **Una tira de progreso por etapas.** La app **ya tiene** exactamente este patrón
   construido para el Modo Forense (`#forensicPipeline`, con iconos `⟳/✓/·/✕` por
   paso, flechas `→` entre etapas, y una barra de progreso indeterminada). Es el
   molde perfecto a reutilizar: `Transcribir (1a) → Resumir (1b) → Extraer (2) →
   Guardar (3a + 3b)`, con la única particularidad de que 3a y 3b son la misma etapa
   visual en paralelo, no secuencial (por ejemplo, dos iconos lado a lado en el mismo
   paso: "🗄 BBDD" y "🗒 Obsidian").

3. **Resultado final.** Reutilizar `showAIResult()` (ya renderiza categoría, resumen,
   tags, tools, CVEs, comandos) — el Agrupador devuelve exactamente ese tipo de datos,
   así que la tarjeta `ai-card` que ya existe sirve tal cual, sin rediseñar nada.
   Añadir dos chips nuevos de estado, calcados de los `*_entregado` que cada agente ya
   devuelve: `✓ Guardado en BBDD` / `✗ No guardado en BBDD` y lo mismo para Obsidian
   (cuando 3b exista) — igual que `agrupador_entregado`/`escritor_entregado` ya
   viajan en las respuestas de Escritor/Cinéfilo.

4. **Errores y reintento.** Cualquier fallo en cualquier tramo de la cadena responde
   con el texto exacto `"Ha habido un error"` (convención ya fijada desde el diseño
   original de Agrupador/Agente-BBDD). El frontend debe mostrarlo igual que ya muestra
   `hideGlobalProgress(msg,'error')` en el resto de la app, con un botón "↺ Reintentar"
   que repite la misma petición — no hace falta guardar estado de en qué paso se quedó,
   porque toda la cadena se repite entera en cada intento (así está diseñado el
   backend: es todo o nada por transacción).

### 3.2 — El modal rápido de "⊕ Subir doc" — depende de la decisión de la Parte 2.4

Si se elige la Opción 2 (migración), el modal de subida rápida (`uploadModal`, con su
checkbox "guardar automáticamente") pasaría a llamar también a Escritor en vez de a
`/api/analyze`, y heredaría gratis el envío a Obsidian. Si se elige la Opción 1
(convivencia), el modal se queda exactamente como está, y la cadena de agentes se
activa solo desde la pestaña Editor completa, no desde el atajo rápido.

---

## PARTE 4 — Checklist de lo que hay que resolver antes de construir nada de esto

- [ ] Ejecutar `pip install -r requirements.txt` de verdad en el `.venv` de la app
      (hoy `yt-dlp`, `openai`, `reportlab` no están instalados pese a estar listados)
- [ ] Instalar `ffmpeg` en el sistema (`winget install Gyan.FFmpeg`) — si no, Cinéfilo
      solo funciona con vídeos que ya traen subtítulos oficiales
- [ ] Añadir `ESCRITOR_URL` al `.env` de la app
- [ ] Construir el agente Obsi (3b) — sigue pendiente, con su propia investigación ya
      guardada en `Agente4-IndexerO`/`Obsi` (ver memoria del proyecto)
- [ ] Decidir Parte 2.4 (convivencia / migración / híbrida) antes de tocar
      `/api/upload` o `/api/analyze`
- [ ] Decidir si se registra todo de una vez en `main.py` o por agente, según vaya
      quedando listo cada uno

---

## Resumen de una línea

Comandos: la pestaña mezcla cuatro orígenes de datos con reglas de persistencia
distintas, y el hallazgo nuevo es que las fichas PrivEsc creadas a mano viven
**solo en el navegador**, nunca llegan a los agentes. Editor: ya existe la pestaña
donde encajar todo esto, ya existe el patrón visual de pipeline (copiado del Modo
Forense), y la decisión real pendiente no es de diseño de UI sino de si el subir-documento
rápido de hoy convive con la cadena de agentes o se sustituye por ella.
