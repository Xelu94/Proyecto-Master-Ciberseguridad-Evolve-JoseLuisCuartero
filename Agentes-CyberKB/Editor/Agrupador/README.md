# Agente Agrupador

Descompone el resumen que produce el **Escritor** en fichas estructuradas y las entrega
al **Agente-BBDD** y al agente **Obsi**. No resume ni filtra: toma un texto ya validado y
lo convierte en filas de base de datos y nodos de grafo.

```
                                    ┌──> Agente-BBDD  (tablas)
Escritor ──resumen──> Agrupador ────┤
                          │         └──> Obsi         (vault de Obsidian)
                          │
                          └──> agrupaciones/{id_resumen}.json
```

## Entradas

| Endpoint | Origen | Cuerpo |
|---|---|---|
| `POST /api/agrupador/agrupar` | Escritor | `application/json`: el payload del Escritor |

Obligatorios `id`, `titulo` y `resumen`; `temas`, `timestamp`, `source` y
`archivo_original` son opcionales. Esa tolerancia existe para que la app pueda reintentar
con lo mínimo cuando un envío falla.

```json
{
  "id": "4b81c0de...",
  "titulo": "Obligaciones de notificacion bajo NIS2",
  "resumen": "...",
  "temas": ["nis2", "cumplimiento"],
  "source": "cinefilo"
}
```

## Ciclo de trabajo

1. **Recibir** el JSON del Escritor.
2. **Leerlo** y comprobar que el resumen tiene cuerpo suficiente.
3. **Agrupar**: Claude descompone el texto en siete bloques siguiendo
   [prompt.md](prompt.md), que el agente carga en cada petición.
4. **Validar** la salida del modelo contra el modelo de datos de la app —este paso es el
   que protege la base de datos, y se detalla más abajo.
5. **Guardar** `{id_resumen}.json` en `agrupaciones/`, dentro de la carpeta del agente.
6. **Entregar** al Agente-BBDD y al agente Obsi. Siempre a los dos, en el mismo envío.

## Salidas

Un único JSON que reciben **ambos** agentes sin diferencias. Cada uno toma lo que necesita:
el Agente-BBDD reparte los bloques entre sus tablas, y Obsi construye la nota y sus enlaces.

```json
{
  "id_resumen": "4b81c0de...",
  "timestamp": "2026-09-19T18:22:41+00:00",
  "source": "cinefilo",
  "titulo": "Obligaciones de notificacion bajo NIS2",
  "archivo_original": "charla-nis2.pdf",
  "resumen": "...",

  "category": "metodologia",
  "subcategory": "Plazos de notificacion NIS2",
  "tags": ["nis2", "cumplimiento", "respuesta-incidentes"],

  "tools":    [{"name": "...", "description": "...", "tool_type": "software|web",
                "use_cases": "...", "requires_api": false}],
  "commands": [{"command": "...", "description": "...", "tool_name": "...",
                "os": "linux|windows|powershell|google|both", "flags": ["..."]}],
  "cves":     [{"cve_id": "CVE-2021-44228", "title": "...", "description": "...",
                "severity": "critica", "cvss": 10.0, "affected": "..."}],
  "mitre":    [{"technique_id": "T1055", "technique_name": "...",
                "tactic": "Defense Evasion", "context_snippet": "..."}],
  "entities": [{"name": "Pass-the-Hash", "type": "attack", "description": "..."}],
  "relations": [["Mimikatz", "Pass-the-Hash"]],

  "bbdd_entregado": true,
  "obsi_entregado": true
}
```

Cada bloque está calcado del modelo de datos de la app, de modo que el Agente-BBDD pueda
insertar sin traducir nada:

| Bloque | Tabla |
|---|---|
| `titulo`, `resumen`, `category`, `subcategory`, `tags` | `notes` |
| `tools` | `tools` |
| `commands` | `commands` |
| `cves` | `cves` |
| `mitre` | `mitre_techniques` |
| `entities` | `graph_entities` |
| `relations` | `entity_relations` |

## Reglas

1. **Un fallo al agrupar responde `Ha habido un error`.** El mensaje es literal y sale con
   código `500`, así que la app puede mostrarlo y ofrecer reintentar. El reintento es la
   misma petición otra vez: el fichero de salida se llama como el resumen, de modo que
   repetir sobrescribe en lugar de acumular copias.

   Hay un caso que **no** es un fallo al agrupar y por eso lleva mensaje propio: un
   resumen por debajo del mínimo de caracteres responde `422` con
   `El resumen es demasiado corto para agrupar.` Reintentar con el mismo texto no puede
   arreglarlo, así que decir «Ha habido un error» solo conseguiría que el usuario lo
   intentase en vano. Es la misma distinción que hace el Escritor.

   En la práctica ese aviso casi no aparece: el Escritor ya garantiza resúmenes de 500
   caracteres y aquí el mínimo son 200. Existe porque este endpoint es una frontera y
   puede recibir una llamada que no venga del Escritor.

   El recuento ignora espacios, saltos, marcas BOM y caracteres de ancho cero: solo
   cuentan los caracteres que se ven.
2. **El JSON va siempre a los dos agentes.** No hay ruta que entregue a uno solo. Si uno
   de los dos no responde, la petición **no** falla: el JSON ya está en disco y la
   respuesta lo indica con `bbdd_entregado` u `obsi_entregado` en `false`. Volver a fallar
   la petición entera obligaría a pagar otra vez la llamada al modelo por un problema que
   no está en la agrupación.
3. **La base de conocimiento vive en [prompt.md](prompt.md).** El vocabulario canónico
   —herramientas, protocolos, marcos, ataques, defensas, conceptos y criptografía— sale de
   la recopilación hecha sobre fuentes oficiales (NIST, OWASP, CIS, ISO, MITRE, CISA).
   Ampliarlo es editar ese fichero; no hace falta tocar código.

## Por qué el vocabulario canónico importa

`tools.name`, `graph_entities.name` y `cves.cve_id` son columnas **únicas**. Si un
documento produce `Burp Suite` y el siguiente `burpsuite`, la base de datos acaba con dos
filas para la misma herramienta y el grafo con dos nodos que deberían ser uno. El
vocabulario del prompt fija la grafía, y la validación del código deduplica sin distinguir
mayúsculas por si el modelo se desvía igualmente.

## Validación de la salida del modelo

Nada de lo que devuelve Claude llega a los otros agentes sin pasar por
`_validar()`. Lo que hace, y por qué:

- **`category`** fuera de las 16 de la app cae a `teoria`.
- **`os`** fuera de los cinco valores admitidos cae a `linux`.
- **`tool_type`** se reduce a `web` o `software`.
- **CVEs** que no cumplen `CVE-AAAA-NNNN` se descartan: «Log4Shell» a secas no es un
  identificador, y colarlo rompe el enlace con la NVD.
- **CVSS** fuera de `0..10` pasa a `null` en vez de guardar un número imposible.
- **Técnicas** sin identificador `T####` se descartan; la táctica se normaliza contra las
  14 de ATT&CK y, si no coincide con ninguna, queda vacía en lugar de inventada.
- **Nombres de entidad** se recortan a 200 caracteres, el ancho real de la columna. El
  prompt pide nombres cortos por calidad, pero el recorte no baja de ahí: cortar antes
  mutilaba nombres legítimos a media palabra, y el nombre es la clave única del grafo.
- **Tipos de entidad** fuera de los ocho admitidos caen a `concept`.
- **Relaciones** hacia entidades que no están en la propia lista se eliminan, igual que
  los bucles y los pares repetidos en orden inverso. Una relación huérfana deja un nodo
  colgado en el grafo.
- **Duplicados** se fusionan por nombre sin distinguir mayúsculas en herramientas,
  entidades, CVEs y técnicas.

## Configuración

Todo lo ajustable vive en [config.json](config.json) y se lee en cada arranque: modelos,
las 16 categorías, los 8 tipos de entidad, las 14 tácticas, límites por bloque, destinos y
el mensaje de error.

### Variables de entorno

| Variable | Uso |
|---|---|
| `ANTHROPIC_API_KEY` | Clave de Claude. Ya la gestiona `POST /api/settings` de la app. |
| `BBDD_URL` | Endpoint del Agente-BBDD. Por defecto el de `config.json`. |
| `OBSI_URL` | Endpoint del agente Obsi. Por defecto el de `config.json`. |
| `AGRUPADOR_OUTPUT_DIR` | Carpeta de salida. Por defecto `agrupaciones/`, dentro de esta misma carpeta. |

## Integración en la app

Los dos repositorios son carpetas hermanas:

```
C:\Users\Usuario\
├── Agentes-CyberKB\                              <- este repositorio
│   └── Editor\Agrupador\agrupador.py
└── Proyecto-Master-Ciberseguridad-Evolve-...\    <- la app
    └── main.py
```

El nombre `Agentes-CyberKB` lleva guion, así que no es importable como paquete de Python.
Se añade al `sys.path` resolviendo la carpeta hermana:

```python
import sys
from pathlib import Path

sys.path.insert(0, str(
    Path(__file__).resolve().parent.parent / "Agentes-CyberKB" / "Editor" / "Agrupador"
))
from agrupador import router as agrupador_router

app.include_router(agrupador_router)
```

Para cerrar la cadena, el Escritor necesita saber a dónde enviar. Ya lo lee de una
variable de entorno:

```
AGRUPADOR_URL=http://localhost:8000/api/agrupador/agrupar
```

No hay dependencias nuevas: `anthropic`, `httpx`, `fastapi` y `pydantic` ya están en el
`requirements.txt` de la app.

## Limitaciones conocidas

- **La calidad depende del resumen.** El Agrupador solo ve lo que el Escritor decidió
  conservar. Un comando o un CVE que no sobrevivió al resumen no existe para este agente.
- **Los comandos no se verifican.** Se extraen tal como aparecen en el texto. Si el
  documento traía una bandera mal escrita, la base de datos hereda el error.
- **Las técnicas ATT&CK sin identificador se pierden.** Es deliberado: preferimos perder
  una técnica nombrada de pasada a guardar un `T1055` inventado que luego alguien dé por
  bueno. Aun así, un identificador puede estar bien formado y no existir en ATT&CK —el
  agente no consulta el catálogo de MITRE.
- **La deduplicación es solo dentro de un documento.** Que `Nmap` ya exista en la base de
  datos por otro resumen es cosa del Agente-BBDD, que deberá hacer *upsert* sobre la
  columna única en lugar de insertar a ciegas.
- **El recorte a 20 000 caracteres afecta solo a la extracción.** Es lo que se le manda al
  modelo, así que de un resumen más largo no se extraen entidades del tramo final. El
  campo `resumen` del payload viaja entero: los destinos reciben el texto completo.
- **El texto es material sin filtrar.** Puede contener frases dirigidas a un sistema
  automático; el prompt las trata como contenido, nunca como instrucciones, y lo mismo
  debe hacer cualquier agente que consuma esta salida.
- **`bbdd_entregado: false` no se reintenta solo.** El JSON queda en disco y la reentrega
  es responsabilidad de quien orqueste, o del usuario repitiendo la petición.

---

**Versión** 1.0 · **Flujo** Escritor→Agrupador→{Agente-BBDD, Obsi}
