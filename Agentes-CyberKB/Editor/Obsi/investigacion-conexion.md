# Investigación — cómo debe conectarse el agente Obsi al vault

Guardado el 2026-09-23 para cuando construyamos el agente 3b. No es código, es la
base de decisión: qué opción usar y por qué, antes de escribir `obsi.py`.

## La pregunta

El pipeline dice que 3b "genera una nota .md dentro del vault de Obsidian, con
frontmatter y wikilinks". Hay tres formas técnicas de hacer eso desde un backend
Python/FastAPI. Las comparé.

## Opción A — Escritura directa en el sistema de ficheros ✅ recomendada

Un vault de Obsidian **es literalmente una carpeta de ficheros Markdown**. Obsidian la
vigila y refresca sola cuando detecta cambios externos — no hace falta ninguna API para
que una nota escrita por otro proceso aparezca en la app.

- **No depende de que Obsidian esté abierto.** Funciona igual si el usuario procesa un
  documento a las 3 de la mañana con Obsidian cerrado.
- **Sin dependencias nuevas.** Ya usamos este patrón en Escritor/Cinéfilo/Agrupador
  para sus `salida/`; aquí es lo mismo pero apuntando a `OBSIDIAN_VAULT_DIR` en vez de
  a una carpeta propia del agente.
- **Es justo el patrón que la comunidad recomienda para automatización en background**:
  se lo conoce como "Filesystem MCP" en el ecosistema de integraciones Obsidian+IA —
  "acceso directo a los ficheros Markdown del vault sin necesidad de plugins […] no
  requiere Obsidian abierto ni plugins adicionales […] mejor para automatización en
  segundo plano" ([awesomeclaude.ai](https://awesomeclaude.ai/how-to/use-obsidian-with-claude)).

**Conclusión: esta es la opción para 3b.** Escribir el `.md` con `pathlib`/`open()`
igual que ya hacen los demás agentes. No usar la REST API para esto (ver Opción B, por
qué no).

## Opción B — Plugin "Local REST API" (con servidor MCP incorporado) ❌ para esta tarea

Existe un plugin comunitario muy maduro,
[obsidian-local-rest-api de coddingtonbear](https://github.com/coddingtonbear/obsidian-local-rest-api)
([documentación interactiva](https://coddingtonbear.github.io/obsidian-local-rest-api/)),
que expone el vault por HTTPS local (puerto `27124`) con autenticación por API key, y
en su versión reciente trae también un servidor MCP incorporado.

Soporta de todo: `PATCH /vault/{path}` para editar solo una sección por heading, bloque
o clave de frontmatter (`replace`/`prepend`/`append`/`delete`), `PATCH /active/` sobre
la nota abierta, `PATCH /periodic/{period}/` para notas periódicas.

Ejemplo (para referencia futura, si alguna vez hiciera falta parchear una nota ya
existente en vez de reescribirla entera):

```python
import requests
requests.patch(
    "https://127.0.0.1:27124/vault/ruta/nota.md",
    headers={"Authorization": f"Bearer {API_KEY}"},
    json={"targetType": "frontmatter", "target": "status", "operation": "replace", "value": "done"},
    verify=False,  # certificado autofirmado del plugin
)
```

**Por qué NO usarla para 3b**: requiere que **Obsidian esté abierto** en el momento de
la llamada — "el plugin solo sirve peticiones mientras Obsidian está en ejecución; si
lo cierras, las llamadas fallan con conexión rechazada" (confirmado en varias fuentes,
incl. [mcp.directory](https://mcp.directory/blog/obsidian-mcp-complete-guide-2026)). Un
agente de ingesta que depende de que el usuario tenga una app de escritorio abierta no
es fiable para un pipeline automático. Se descarta para 3b.

## La otra mitad de la pregunta — "que se conecte a la IA"

Esto es un asunto distinto al de arriba: no es cómo *escribimos* en el vault, sino cómo
lo hacemos *consultable por significado* una vez tiene contenido. Aquí es donde entra
lo que iba a ser el agente 4 (Indexer) — ver
[Editor/Agente4-IndexerO/investigacion-conexion-ia.md](../Agente4-IndexerO/investigacion-conexion-ia.md)
para el hallazgo importante: puede que no haga falta construirlo desde cero.

## Fuentes

- [Local REST API with MCP — Obsidian Plugin](https://community.obsidian.md/plugins/obsidian-local-rest-api)
- [coddingtonbear/obsidian-local-rest-api (GitHub)](https://github.com/coddingtonbear/obsidian-local-rest-api)
- [Documentación interactiva de la API](https://coddingtonbear.github.io/obsidian-local-rest-api/)
- [PATCH Operations and Content Insertion — DeepWiki](https://deepwiki.com/coddingtonbear/obsidian-local-rest-api/6.1-patch-operations)
- [3 Ways to Use Obsidian with Claude Code — Awesome Claude](https://awesomeclaude.ai/how-to/use-obsidian-with-claude)
- [Obsidian MCP Setup 2026: Local REST API Complete Guide — MCP.Directory](https://mcp.directory/blog/obsidian-mcp-complete-guide-2026)
