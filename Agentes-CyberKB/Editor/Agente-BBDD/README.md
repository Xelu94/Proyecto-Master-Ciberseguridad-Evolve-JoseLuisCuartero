# Agente-BBDD

Recibe la agrupación del **Agrupador** y la reparte entre las tablas de la aplicación.
Es el único agente de la cadena que escribe en la base de datos.

```
Agrupador ──JSON──> Agente-BBDD ──> notes · tools · commands · cves
                                    mitre_techniques · graph_entities
                                    entity_relations
```

No tiene `prompt.md`: **no consulta a ningún modelo**. Todo lo que hace es determinista
—mapear campos, buscar duplicados y escribir—, así que la misma entrada produce siempre
el mismo resultado. El criterio ya lo aplicaron el Escritor y el Agrupador.

## Entradas

| Endpoint | Origen | Cuerpo |
|---|---|---|
| `POST /api/bbdd/ingesta` | Agrupador | `application/json`: el payload del Agrupador |

Obligatorios `id_resumen`, `titulo` y `resumen`; el resto tiene valores por defecto, de
modo que una agrupación sin CVEs ni comandos entra igual.

## Ciclo de trabajo

1. **Recibir** el JSON del Agrupador.
2. **Leerlo** y validarlo contra el modelo de entrada.
3. **Repartir** cada bloque a su tabla, recortando cada campo al ancho real de su columna.
4. **Comprobar duplicados** antes de escribir, tabla por tabla (ver más abajo).
5. **Guardar**, todo dentro de una única transacción.

El orden no es negociable: la nota se crea primero porque comandos, CVEs y técnicas
cuelgan de su `note_id` por clave foránea. Las entidades van después, y las relaciones las
últimas, porque necesitan los `id` que la base asigna a las entidades.

## Salidas

```json
{
  "id_resumen": "abc123",
  "guardado": true,
  "nota_id": 1,
  "herramientas": 2,
  "comandos": 1,
  "cves": 1,
  "mitre": 1,
  "entidades": 3,
  "relaciones": 2
}
```

Los números son elementos **procesados**, no necesariamente nuevos: en un reintento valen
lo mismo aunque no se haya creado ninguna fila.

## Reglas

1. **Cualquier fallo responde `Ha habido un error`.** Sale con código `500` y, antes de
   responder, **deshace la transacción entera**. Es lo que hace seguro reintentar: la base
   nunca queda a medio escribir, así que la app puede repetir la petición sin limpiar nada.
2. **Lo que ya existe se actualiza, no se duplica.** El dato nuevo sobrescribe al viejo,
   con dos matices que evitan destruir información:
   - **Un valor nuevo vacío no borra el que había.** Un documento que menciona Nmap de
     pasada no debe vaciar la descripción que aportó otro más completo.
   - **Los contadores se incrementan, no se reinician.** `mention_count`, `frequency` y
     `weight` miden cuántas veces se ha visto algo; sustituirlos por 1 destruiría
     precisamente lo que cuentan, y con ello el tamaño de los nodos del grafo.
3. **El mapa de la base de datos sale del escaneo de la app**, no de suposiciones: se
   inspeccionaron el esquema real de `data/cyberkb.db`, sus restricciones `UNIQUE` y el
   modo en que `main.py` persiste hoy cada tabla.

## Cómo se detectan los duplicados

Cada tabla necesita su propio criterio, porque no todas tienen restricción `UNIQUE`:

| Tabla | `UNIQUE` en la base | Criterio de búsqueda |
|---|---|---|
| `tools` | `name` | `name` sin distinguir mayúsculas |
| `cves` | `cve_id` | `cve_id` en mayúsculas |
| `graph_entities` | `name` | `name` sin distinguir mayúsculas |
| `entity_relations` | `(entity_a_id, entity_b_id)` | par **ordenado por id** |
| `notes` | — | `title` + `source_file` |
| `commands` | — | `command` + `note_id` |
| `mitre_techniques` | — | `technique_id` + `note_id` |

Tres detalles que hacen falta para no corromper datos:

- **Las tres tablas sin `UNIQUE` duplicarían en cada reintento** si no se comprobara a
  mano. La app hoy inserta comandos a ciegas; aquí no.
- **`entity_relations` tiene un `UNIQUE` que no es simétrico.** Si una vez se guarda
  `(3, 7)` y otra `(7, 3)`, la base acepta las dos y el grafo acaba con la misma arista
  duplicada. Por eso el par se ordena por id antes de buscar y de insertar.
- **Las búsquedas son insensibles a mayúsculas** en herramientas y entidades, porque su
  `name` es la clave única: `wireshark` y `Wireshark` tienen que ser la misma fila.

### De dónde sale la URL de una herramienta

No la propone el Agrupador: la pone este agente consultando `KNOWN_TOOLS`, el catálogo de
la app, con 96 direcciones verificadas a mano y sus alias (`burp`, `burpsuite` y
`burp suite` resuelven al mismo enlace). Pedirle URLs a un modelo produce direcciones
verosímiles que no existen, y aquí hay un dato curado disponible.

El tipo de herramienta funciona al revés según quién sepa más. Si el nombre está en
`WEB_RESOURCES`, manda el catálogo —así Shodan queda como `web` aunque el Agrupador lo
haya tipado como `software`—; si no lo conoce, se respeta lo que diga el Agrupador, que
puede reconocer una herramienta más nueva que la lista.

Una herramienta que el catálogo no conozca se guarda sin URL antes que con una inventada.
Y si alguien se la rellena a mano después, un reprocesado no la borra.

### Un arreglo respecto al comportamiento actual de la app

`_persist_cves` en `main.py` ignora por completo un CVE que ya exista: ni actualiza sus
campos ni lo vincula al documento nuevo. Un CVE citado en tres documentos queda atado solo
al primero. Este agente sí adopta el CVE huérfano —le asigna `note_id` si no tenía— y
actualiza sus campos con los datos nuevos.

## Formato de los datos

Verificado sobre las filas reales de la base:

- **`tags` y `flags` se guardan como texto con JSON dentro**, no como lista. En la base hay
  literalmente `'["Directorios expuestos"]'`.
- **`commands.category` es texto libre**, no las 16 categorías de `notes`. Aquí se rellena
  con la categoría de la nota para poder filtrar.
- **Cada campo se recorta al ancho de su columna** antes de escribir: `notes.title` 500,
  `tools.name` 200, `cves.cve_id` 50, `mitre.technique_id` 20, `graph_entities.name` 200.
  Los anchos están en [config.json](config.json).

## Configuración

[config.json](config.json) recoge los anchos de columna, el mensaje de error y los dos
interruptores de comportamiento:

| Opción | Efecto |
|---|---|
| `incrementar_contadores` | `mention_count`, `frequency` y `weight` suman en vez de reiniciarse |
| `conservar_valor_si_el_nuevo_esta_vacio` | Un campo vacío no pisa un valor ya guardado |

### Variables de entorno

| Variable | Uso |
|---|---|
| `DATABASE_URL` | La hereda de la app. Por defecto `sqlite:///data/cyberkb.db`. |

## Integración en la app

Este agente **importa `models.py` y `database.py` de la aplicación**, igual que el Escritor
importa `document_parser`. Comparte sesión, tablas y transacciones con la app, así que no
hay que duplicar el esquema ni mantenerlo sincronizado.

```python
import sys
from pathlib import Path

sys.path.insert(0, str(
    Path(__file__).resolve().parent.parent / "Agentes-CyberKB" / "Editor" / "Agente-BBDD"
))
from agente_bbdd import router as bbdd_router

app.include_router(bbdd_router)
```

El Agrupador ya apunta aquí por defecto (`http://localhost:8000/api/bbdd/ingesta`), así que
no hace falta configurar nada más. No hay dependencias nuevas.

## Limitaciones conocidas

- **La identidad de una nota es `title` + `source_file`.** La tabla `notes` no tiene
  restricción `UNIQUE` ni columna donde guardar el `id_resumen`, así que dos documentos
  distintos con el mismo título y el mismo fichero de origen se tomarían por el mismo.
  Resolverlo bien pediría añadir una columna al esquema de la app.
- **Los contadores suben también en un reintento.** Repetir la misma petición no crea
  filas, pero sí incrementa `mention_count`, `frequency` y `weight`: son el número de veces
  que se ha procesado el concepto, no el de documentos distintos que lo citan.
- **Un comando corregido deja huérfano al anterior.** La búsqueda es por texto exacto
  dentro de la nota, así que si un documento se reprocesa con una bandera distinta, entra
  como comando nuevo y el viejo permanece.
- **Las entidades se comparten entre documentos, las descripciones no se fusionan.** La
  descripción de una entidad es la del último documento que la describió con contenido, no
  una síntesis de todos.
- **No hay borrado.** El agente crea y actualiza; nada de lo que entra se retira desde
  aquí.

---

**Versión** 1.0 · **Flujo** Agrupador→Agente-BBDD→base de datos
