# Investigación — cómo conectar el vault a la IA (búsqueda por significado)

Guardado el 2026-09-23 para cuando nos pongamos con el agente 4. Contiene un hallazgo
que cambia el planteamiento original: puede que no haga falta construir un Indexer
desde cero.

## Recordatorio del problema (del pipeline corregido)

El agente 4 tenía que: leer la nota final de 3b, trocearla, generar un embedding por
fragmento con un proveedor externo (Claude no ofrece embeddings), guardarlo en una
tabla `embeddings` nueva, y comparar fecha de última actualización antes de
recalcular. Objetivo final: que el chat de la app busque por significado.

## Hallazgo — ya existe un plugin de Obsidian que hace exactamente esto

Se llama **Smart Connections**
([repo](https://github.com/brianpetro/obsidian-smart-connections),
[ficha oficial](https://community.obsidian.md/plugins/smart-connections)):

- Genera embeddings **localmente**, con un modelo propio bundleado
  (`TaylorAI/bge-micro-v2`, 384 dimensiones) — **sin API key, sin coste, sin mandar
  nada a internet**.
- Mantiene el índice **sincronizado solo con lo que cambia**: escucha los eventos de
  Obsidian y reindexar solo lo que se ha modificado — es la misma idea de "comparar
  fecha antes de recalcular" que pedía el diseño original del agente 4, pero ya
  resuelta.
- Cero configuración: se instala como plugin normal y funciona.

Esto cubre punto por punto lo que el agente 4 iba a hacer manualmente (trocear +
embeber + indexar + evitar recálculo), **sin tocar el esquema de la BBDD de CyberKB y
sin elegir/pagar un proveedor de embeddings**.

## Cómo se conecta eso a una IA externa (al chat de la app, o a Claude)

Existe un servidor MCP comunitario —
[**smart-connections-mcp**](https://github.com/msdanyg/smart-connections-mcp)— que
expone el índice que ya generó Smart Connections:

- Lee los embeddings que Smart Connections ya calculó (variable de entorno
  `SMART_VAULT_PATH`), y para buscar, **embebe la pregunta con el mismo modelo local**
  (se descarga una vez, ~25 MB, corre vía `transformers.js`, sin llamadas a la nube).
- Expone herramientas tipo `search_notes` (búsqueda semántica por nota completa o por
  bloque, con ranking de similitud), `get_similar_notes`, `get_connection_graph`.
- **Cualquier aplicación externa puede consultar los embeddings sin pasar por
  Obsidian** — no hace falta que Obsidian esté abierto para leer el índice ya generado
  (a diferencia de la REST API del otro documento, que sí lo necesita para escribir).

## Lo que esto cambia para nuestro diseño

Dos caminos posibles, a decidir cuando nos pongamos con ello — no lo estoy decidiendo
yo aquí, solo dejo las opciones con sus costes reales:

| | Construir Agente4-IndexerO a medida | Apoyarse en Smart Connections + su MCP |
|---|---|---|
| Tabla nueva en la BBDD (`embeddings`) | Sí, migración propia | No hace falta |
| Proveedor de embeddings a elegir/pagar | Sí (Voyage AI u otro) | No — modelo local incluido, gratis |
| Trabajo de desarrollo | Agente completo desde cero | Instalar un plugin + un servidor MCP ya hechos |
| Quién consulta la búsqueda semántica | Habría que modificar `/api/chat` de CyberKB a mano | Cualquier cliente MCP (incl. Claude) directamente, o igualmente se podría enchufar a `/api/chat` leyendo el mismo índice |
| Control total sobre el formato/calidad del embedding | Sí | No — depende del plugin de terceros |
| Mantenimiento | Nuestro | De la comunidad (hay que vigilar que el plugin siga activo) |

La columna de la derecha es objetivamente menos trabajo y resuelve el mismo problema
que motivó el agente 4. La columna de la izquierda da más control si algún día
queremos que el embedding sea consistente con otro pipeline nuestro (por ejemplo, si
quisiéramos embeber también contenido que no pasa por Obsidian). Es una decisión de
alcance del proyecto, no una decisión técnica que yo deba tomar sola.

## Fuentes

- [Smart Connections — Obsidian Plugin](https://community.obsidian.md/plugins/smart-connections)
- [brianpetro/obsidian-smart-connections (GitHub)](https://github.com/brianpetro/obsidian-smart-connections)
- [Smart Connections: Semantic Search & Knowledge Graphs — MCP Market](https://mcpmarket.com/server/smart-connections)
- [msdanyg/smart-connections-mcp (GitHub)](https://github.com/msdanyg/smart-connections-mcp)
- [Obsidian + AI: From Simple Plugin to Full Agent Integration — Krzysztof's Blog](https://3sztof.github.io/posts/obsidian-smart-connections-mcp/)
- [Obsidian MCP Server: Connect Your Vault to AI Agents (2026 Guide) — MorphLLM](https://www.morphllm.com/obsidian-mcp-server)
