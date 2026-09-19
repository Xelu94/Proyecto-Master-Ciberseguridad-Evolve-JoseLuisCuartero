# CLAUDE.md — Agentes-CyberKB

Guía de trabajo para Claude Code en este repositorio. El propósito de esta carpeta es almacenar y mantener agentes (definiciones, prompts, configuraciones) usados en el ecosistema CyberKB.

## Propósito del repositorio

Este directorio centraliza los agentes: cada agente vive en su propia subcarpeta con su definición, prompt del sistema, configuración y (si aplica) herramientas asociadas.

## Estructura esperada

```
Agentes-CyberKB/
├── CLAUDE.md              # esta guía
├── Agentes-x          # carpeta de agentes que se encargan del proceso x
|   ├── <nombre-del-agente>/
│       ├── README.md          # qué hace el agente y cómo se usa
│       ├── prompt.md           # system prompt / instrucciones del agente
│       └── config.(json|yaml)  # configuración específica (modelo, herramientas, límites)
└── ...
```

Cuando crees un agente nuevo, pide al usuario que te escriba el nombre de la carpeta de la herramienta y el nombre de la herramienta si no te lo han dicho ya.

## Convenciones de nombres

- Archivos de prompt en `prompt.md`, siempre en español salvo que el agente esté pensado para operar en otro idioma.
- Evitar espacios y tildes en nombres de archivos/carpetas.

## Buenas prácticas al crear o editar agentes

- Cada agente debe tener un propósito único y bien delimitado.
- Documentar en el `README.md` de cada agente: objetivo, entradas esperadas, salidas esperadas, y limitaciones conocidas.
- No incluir credenciales, tokens ni datos sensibles en ningún archivo de este repositorio. Si un agente necesita secretos, referenciarlos por nombre de variable de entorno, nunca en texto plano.
- Mantener los prompts concisos y accionables; evitar relleno o instrucciones redundantes.
- Antes de duplicar lógica entre agentes, revisar si puede extraerse a un agente/plantilla común.
- Enseña de forma visual lo que vayas haciendo al usuario.
- Cada vez que quieras crear un apartado o concepto debe de explicar y preguntar al usuario si debe o no continuar.

## Contexto de seguridad

Este repositorio puede incluir agentes orientados a ciberseguridad (análisis, triage, threat intel, etc.). Al trabajar aquí:

- Asumir contexto de uso defensivo/autorizado salvo indicación contraria explícita del usuario.
- No generar agentes ni instrucciones orientadas a actividades destructivas, evasión de detección con fines maliciosos, o ataques no autorizados.
- Si un agente maneja datos sensibles (logs, IOCs, credenciales de prueba), señalarlo claramente en su README.

## Flujo de trabajo sugerido

1. Antes de crear un agente nuevo, revisar si ya existe uno similar en el repositorio.
2. Preguntar el nombre de la carpeta de la herramienta a la que pertenerce el agente y crearla si es necesaria.
3. Crear la subcarpeta correspondiente en la localización correspondiente.
4. Redactar el prompt y la documentación juntos, no el prompt solo.
5. Mantener este `CLAUDE.md` actualizado si cambian las convenciones generales del repositorio.

---


