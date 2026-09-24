# Decisiones — construcción del Editor (frontend + backend de agentes)

Lista viva. Se actualiza cada vez que aclaramos algo, en orden cronológico. No es
el plan en sí (eso vive en `PLAN_COMANDOS_Y_FRONTEND_BACKEND.md`) — esto es el
registro de qué se decidió, cuándo, y por qué.

## Decidido

- **2026-09-24** — Se aprueba el diseño visual del mockup (`Antes`/`Después`) como
  punto de partida: campo de URL de vídeo con el estilo de `osint-query-bar`, tira
  de pipeline calcada del Modo Forense, chips de estado "Guardado en BBDD/Obsidian"
  en la tarjeta de resultado existente.
- **2026-09-24 — Prerrequisito 1 completado** ("haz el prerrequisito 1"):
  - `yt-dlp`, `openai`, `reportlab` instalados y verificados en el `.venv` real de
    la app (antes solo estaban en `requirements.txt`, no instalados).
  - `ffmpeg` 9.0.2 instalado vía winget (`Gyan.FFmpeg`), en el PATH de usuario.
    Verificado que el binario arranca. Una terminal ya abierta no lo ve hasta
    reiniciarse — normal, cualquier proceso nuevo (incluida la app al arrancar) sí.
  - `ESCRITOR_URL=http://localhost:8000/api/escritor/resumen-agente` añadido al
    `.env` de la app, junto al `AGRUPADOR_URL` que ya existía.

## Aplazado (no decidido, pero conscientemente pospuesto)

- **`/api/upload`/`/api/analyze` vs. la cadena de agentes** (Parte 2.4 del plan):
  **2026-09-24 — "por el momento no lo tocamos"**. `/api/upload` y `/api/analyze`
  se quedan exactamente como están (Opción 1 de facto, sin comprometerse a ella).
  No se toca `main.py` en ese punto todavía. Revisar más adelante.
- **2026-09-24 — Alcance de esta fase**: "vamos a aclarar el frontend y el backend
  de lo que tenemos, sease la pipeline que conecta con BBDD y no con obsidian, esa
  la haremos más adelante". A partir de aquí, frontend/backend/plan se centran
  **solo** en Cinéfilo→Escritor→Agrupador→Agente-BBDD. Todo lo de Obsi (frontmatter,
  ruta del vault) queda fuera de esta ronda, para cuando se retome ese agente.

## Hecho — primer cambio de código real (no mockup)

- **2026-09-24** — Investigación exhaustiva sobre IA (fuera y dentro de
  ciberseguridad, ~47 búsquedas, señal "calipo" pendiente de confirmación final)
  aplicada directamente a los prompts de **Cinéfilo** y **Escritor**: nueva
  categoría **"Seguridad de la IA"** añadida a la lista de "qué cuenta como
  ciberseguridad" en ambos (`prompt injection, jailbreaks, envenenamiento de
  datos/modelo, ataques adversariales, MITRE ATLAS, OWASP Top 10 LLM, red
  teaming, deepfakes como vector de ataque, AIBOM, guardarraíles/firewalls de
  IA, agentes de IA como superficie de ataque`). Además, en los dos se añadió
  una exclusión explícita de **IA sin enfoque de seguridad** (cómo funciona un
  modelo, asistentes de código, generación de imagen/vídeo, vehículos
  autónomos, traducción, lanzamientos de laboratorios, ética/regulación sin
  materia de seguridad) para que el filtro no dé falsos positivos solo porque
  el contenido menciona "IA". Objetivo del usuario: "quiero que el filtro sea
  más preciso" — cubre tanto el falso negativo (seguridad de IA sin categoría)
  como el falso positivo (IA genérica colándose por la palabra de moda).
  **No se tocó Agrupador** (categorización en 16 categorías) ni el mockup —
  esto es prompt real de los agentes ya construidos.

## Hallazgo — ejemplos del placeholder actual no sirven para la cadena de agentes

- **2026-09-24** — Los 4 ejemplos del placeholder real del textarea del Editor
  ("Apuntes de clase...", "nmap -sV...", "CVE-2021-44228...", "Herramienta: Burp
  Suite...") tienen entre 29 y 50 caracteres — muy por debajo del mínimo de 4000
  caracteres visibles de Escritor. Ninguno pasaría por la cadena de agentes (422
  inmediato); solo funcionan hoy porque van por `/api/analyze` (sin mínimo).
  Refuerza que hay que comunicar bien la diferencia de umbrales si ambos caminos
  conviven en la misma pestaña — ver Parte 2.4, sigue aplazada. No se tocó el
  mockup por este hallazgo, es solo para tenerlo en cuenta.

## Verificado (no es una decisión, es un hecho del código ya comprobado)

- **2026-09-24** — El Agrupador ya intenta entregar siempre a BBDD **y** a Obsi (regla
  original "siempre a ambos"), pero `_entregar()` envuelve cada envío en
  `try/except httpx.HTTPError` y devuelve `False` sin romper nada si el destino no
  responde. Con Obsi sin construir, `obsi_entregado` será simplemente `false` en
  cada respuesta — no bloquea ni ralentiza de forma relevante la entrega a BBDD.
  **No hace falta tocar código del Agrupador para trabajar en esta fase.**

## Decidido (Inicial)

- **2026-09-24** — Corrección del usuario: "error mío, me refería al art inicial".
  Se revirtió el cambio en `Antes` (vuelve a su estado original, sigue siendo solo
  referencia fija). En `Inicial` se añadió la tarjeta ANÁLISIS IA en **versión
  vacía/placeholder** (sin datos de ejemplo, coherente con que ahí nada ha corrido
  todavía) — "Aquí aparecerá el resumen, las herramientas, los comandos y los CVEs
  detectados... Tampoco existe todavía", colocada antes de la nota de la tira de
  pipeline. **Corrección**: quedó en 2º lugar (después del campo de vídeo); movida
  a 1er lugar, antes del campo de vídeo, para que coincida exactamente con la
  posición de la tarjeta en Después.

## Decidido (Después)

- **2026-09-24** — La tarjeta **ANÁLISIS IA** completa (Resumen, Herramientas
  detectadas, Entrega de la cadena) pasa a ser lo primero del apartado central,
  antes del campo de URL de vídeo, la tira de pipeline y la zona de subir
  documento. Confirmado explícitamente por el usuario tras pregunta directa
  (no era la nota del drop-zone ni un bloque nuevo).

## Decidido (comportamiento)

- **2026-09-24** — La tira de pipeline (el "cuadrado de los procesos") es
  **invisible hasta que arranca el proceso** — no existe en el estado inicial,
  aparece solo al pulsar "▶ Transcribir" o soltar un documento. Añadido nuevo
  artboard `Inicial.dc.html` mostrando ese estado (sin tira, sin tarjeta de
  resultado, solo campo de vídeo + zona de subida). Canvas reorganizado en dos
  filas: `Antes` como referencia fija arriba; `Inicial → Después → Error` como
  la secuencia real de estados, en orden, en la fila de abajo.

## Corregido

- **2026-09-24** — En `Inicial.dc.html` la explicación de "aquí no hay tira de
  pipeline todavía" estaba como comentario HTML (`<!-- -->`), invisible por
  definición — se detectó porque no se veía en el artboard. Convertido a bloque
  de texto visible con el mismo estilo de nota que el resto del mockup.

## Alcance de trabajo

- **2026-09-24** — "centrémonos en el mockup de después, el de antes solo lo
  usamos de referencia". A partir de aquí, los cambios de diseño se hacen sobre
  `Despues.dc.html`. `Antes.dc.html` se deja fijo, solo como comparación — no se
  sigue iterando sobre él salvo que se diga lo contrario.

## Reiniciado

- **2026-09-24** — "pon los art como estaban, volvemos a empezar, pero manten la
  lista". Se revirtieron los cambios de orden/prioridad hechos sobre `Antes` y
  `Error` (la reubicación de notas explicativas) — los tres artboards vuelven a su
  estado original. La lista de decisiones sigue en pie, no se reinicia.

## Aplazado (fase BBDD)

- **2026-09-24 — "el dos no, guárdalo en la lista"**: registrar los routers en
  `main.py` se queda **sin hacer** por ahora. `main.py` sigue sin ningún
  `include_router`. Retomar cuando se decida seguir.

## Fuera de alcance por ahora (retomar cuando se construya Obsi)

- Frontmatter de Obsidian (nombre exacto del campo de fecha).
- Ruta del vault (`OBSIDIAN_VAULT_DIR`).
