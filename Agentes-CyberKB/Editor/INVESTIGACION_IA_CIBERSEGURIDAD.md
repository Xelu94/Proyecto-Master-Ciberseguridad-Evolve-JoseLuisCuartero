# Investigación — la IA fuera y dentro de la ciberseguridad

Investigación de fondo, 2026-09-24. Solo fuentes primarias/oficiales u organizaciones
con autoridad reconocida en el tema (OWASP, MITRE, NIST, fabricantes de seguridad
establecidos, divulgadores técnicos verificados). Se descartaron blogs de marketing
sin autoría clara encontrados en las búsquedas. Contexto: nace de la conversación
sobre por qué el Agrupador no tiene categoría propia para "seguridad de IA" — esta
investigación es la base de conocimiento, no implica que se vaya a añadir esa
categoría, eso queda pendiente de decidir.

---

## A. Cómo funciona la IA — fundamentos

Los sistemas de IA de uso general hoy (2026) se basan casi todos en el mismo bloque
de construcción: el **transformer**, una arquitectura de red neuronal que procesa
secuencias de texto (o de otro tipo de datos) mediante un mecanismo llamado
*self-attention*, que le permite ponderar qué partes de la entrada importan más
para predecir la siguiente ficha ("token"). A diferencia de las redes neuronales
recurrentes anteriores, el transformer procesa toda la secuencia en paralelo, lo
que lo hizo viable a la escala de miles de millones de parámetros
([Wikipedia — Transformer](https://en.wikipedia.org/wiki/Transformer_(deep_learning_architecture)),
[IBM — LLMs](https://www.ibm.com/think/topics/large-language-models)).

Un **modelo de lenguaje grande (LLM)** es, en esencia, una máquina de predicción del
siguiente token: dada una secuencia de entrada, calcula la probabilidad de cada
token posible como continuación, lo elige, y repite. Sobre esa base simple se
construye toda la conversación, el razonamiento y la generación de código que
vemos hoy ([IBM](https://www.ibm.com/think/topics/large-language-models)).

Los **modelos fundacionales** son modelos entrenados a gran escala sobre datos
masivos, pensados para adaptarse después a tareas muy distintas (asistentes,
buscadores, generación de código, visión) sin reentrenar desde cero.

**Para entender el mecanismo interno con rigor matemático y sin coste**, la
referencia más citada y verificable es la serie de vídeos de
[3Blue1Brown (Grant Sanderson) sobre transformers y LLMs](https://www.3blue1brown.com/lessons/gpt) —
divulgador con formación matemática (Stanford) reconocido en toda la comunidad de
IA por la precisión y el rigor de sus animaciones, no un canal de opinión.

**Tendencia de arquitectura en 2026**: la extensión dominante es *Mixture of
Experts* (MoE), que sustituye la red feed-forward estándar del transformer por
varias redes "expertas" en paralelo más un enrutador que decide qué expertos
procesan cada token — permite modelos mucho más grandes sin disparar el coste de
cómputo por token.

---

## B. La IA fuera de la ciberseguridad — usos generales en 2026

- **IA agéntica**: el cambio más señalado de 2026 es el paso de modelos que
  responden a sistemas que ejecutan tareas de varios pasos de forma autónoma,
  coordinando varios agentes especializados entre sí.
- **Salud**: coordinación de cuidados de pacientes, diagnóstico asistido, robótica
  médica con precisión comparable (o superior en detección temprana de cáncer) a
  especialistas humanos en tareas concretas.
- **Finanzas**: modelos de riesgo, detección de fraude, análisis de inversión,
  cumplimiento normativo automatizado.
- **Manufactura y logística**: mantenimiento predictivo, robótica autónoma,
  optimización de cadena de suministro.
- **Marco regulatorio de referencia**: el
  [NIST AI Risk Management Framework](https://www.nist.gov/itl/ai-risk-management-framework)
  (EE. UU., de uso voluntario) es el estándar más citado para gestionar el riesgo de
  cualquier sistema de IA a lo largo de su ciclo de vida, estructurado en cuatro
  funciones: **Gobernar, Mapear, Medir, Gestionar**, sobre unas características de
  "IA de confianza" (válida y fiable, segura, resiliente, responsable, transparente,
  explicable, que preserve la privacidad, justa).

---

## C. La IA dentro de la ciberseguridad — tres ángulos distintos

Esto es lo importante para nuestro caso: **"IA y ciberseguridad" no es un solo
tema, son tres relaciones distintas entre ambas cosas**, y cada una necesitaría un
tratamiento distinto si algún día se refleja en el esquema del Agrupador.

### C1. La IA como herramienta defensiva (SOC, detección, respuesta)

Aplicaciones ya operativas en centros de operaciones de seguridad (SOC):
priorización inteligente de alertas (reducir el ruido para que el analista se
centre en lo que de verdad importa), detección de anomalías de comportamiento,
enriquecimiento de inteligencia de amenazas, respuesta automatizada a incidentes,
caza proactiva de amenazas, detección de amenazas internas, priorización de
vulnerabilidades
([Fortinet — IA en ciberseguridad](https://www.fortinet.com/resources/cyberglossary/artificial-intelligence-in-cybersecurity)).

### C2. La IA como objetivo de ataque — asegurar los propios sistemas de IA

Aquí es donde viven los dos frameworks de referencia, ambos con autoría verificable:

**[OWASP Top 10 para aplicaciones LLM](https://genai.owasp.org/llm-top-10/)**
(proyecto oficial de OWASP, organización sin ánimo de lucro reconocida como
autoridad en seguridad de aplicaciones desde hace más de 20 años):

| # | Riesgo | En qué consiste |
|---|---|---|
| LLM01 | **Prompt Injection** | Entradas que alteran el comportamiento previsto del modelo — el riesgo nº1, porque el LLM procesa instrucciones y contenido no confiable en el mismo contexto |
| LLM02 | **Sensitive Information Disclosure** | El modelo revela datos sensibles propios o de su aplicación |
| LLM03 | **Supply Chain** | Vulnerabilidades en la cadena de suministro del modelo (datos, componentes, terceros) |
| LLM04 | **Data and Model Poisoning** | Contaminación de los datos de entrenamiento, ajuste fino o embeddings |
| LLM05 | **Improper Output Handling** | Validación/saneado insuficiente de lo que el modelo devuelve antes de usarlo |
| LLM06 | **Excessive Agency** | El sistema LLM tiene más autonomía/control del que debería, sin restricciones adecuadas |
| LLM07 | **System Prompt Leakage** | Se filtran las instrucciones internas del sistema |
| LLM08 | **Vector and Embedding Weaknesses** | Debilidades en la representación vectorial usada para búsqueda/RAG |
| LLM09 | **Misinformation** | El modelo genera información falsa presentada como fiable |
| LLM10 | **Unbounded Consumption** | Consumo de recursos sin límite (coste, denegación de servicio económica) |

**[MITRE ATLAS](https://atlas.mitre.org/)** (Adversarial Threat Landscape for
Artificial-Intelligence Systems — mantenido por MITRE, la misma organización
detrás de ATT&CK y de la propia numeración CVE): es el equivalente de ATT&CK pero
para sistemas de IA/ML. Modelado explícitamente sobre la estructura de ATT&CK
(tácticas → técnicas), documenta **16 tácticas y 84 técnicas** (versión 5.1.0,
noviembre 2025), con casos reales documentados. Cubre las cuatro categorías de
ataque adversarial que define NIST: **evasión, envenenamiento, privacidad y
abuso**. La revisión de 2025 amplió mucho la cobertura de IA generativa:
envenenamiento de RAG, inyección falsa de entradas RAG, elaboración de prompts
maliciosos, suplantación, compromiso de la cadena de suministro de IA.

**Esto confirma directamente lo que vimos en el código del Agrupador**: sus
técnicas MITRE extraídas solo cubren las 14 tácticas de ATT&CK clásico — ATLAS es
un catálogo separado, con su propia numeración, que hoy no tiene ningún soporte en
el esquema.

### C3. La IA como herramienta de ataque — abuso por actores maliciosos

Según el [blog oficial de seguridad de Microsoft](https://www.microsoft.com/en-us/security/blog/2026/04/02/threat-actor-abuse-of-ai-accelerates-from-tool-to-cyberattack-surface/)
(abril 2026), la IA ha pasado de usarse como herramienta de apoyo a convertirse en
parte de la propia superficie de ataque. Ha sido adoptada por actores estatales,
bandas cibercriminales con motivación económica y colectivos hacktivistas por
igual, actuando como "multiplicador de fuerza": reduce el esfuerzo necesario para
lanzar una campaña y aumenta su impacto.

Usos documentados:
- **Phishing generado por IA**: mensajes más realistas y personalizados a mayor
  escala.
- **Deepfakes** para suplantar empleados legítimos (voz, vídeo) — usados en fraude
  de ingeniería social e infiltración.
- **Malware polimórfico** optimizado con IA para evadir detección.
- **Identidades sintéticas** generadas por actores estatales para infiltrarse en
  organizaciones desde dentro.

El impacto económico ya se mide de forma diferenciada: el informe de brechas 2026
de IBM cifra el coste medio de una brecha "asistida por IA" en torno a 1 millón de
dólares por encima de la media global de brechas, con el impersonation por
deepfake y el malware asistido por IA como causas principales.

---

## D. Por qué esto importa para el esquema del Agrupador (sin decidir nada)

Recapitulando el hallazgo de antes en esta conversación: las 16 categorías fijas
del Agrupador y las 14 tácticas MITRE que extrae son del **pentesting/red-team
clásico**. Esta investigación confirma que existe un campo paralelo, con
autoridades propias y ya consolidado (OWASP LLM Top 10, MITRE ATLAS, NIST AI RMF),
que hoy no tiene representación en el esquema. Es información para decidir más
adelante si se amplía — no una recomendación de que haya que hacerlo ya.

## Fuentes

- [3Blue1Brown — Transformers, the tech behind LLMs](https://www.3blue1brown.com/lessons/gpt)
- [IBM — What are LLMs](https://www.ibm.com/think/topics/large-language-models)
- [Wikipedia — Transformer (deep learning architecture)](https://en.wikipedia.org/wiki/Transformer_(deep_learning_architecture))
- [NIST — AI Risk Management Framework](https://www.nist.gov/itl/ai-risk-management-framework)
- [NIST AI RMF 1.0 (PDF oficial)](https://nvlpubs.nist.gov/nistpubs/ai/nist.ai.100-1.pdf)
- [OWASP — Top 10 for LLM Applications (oficial)](https://genai.owasp.org/llm-top-10/)
- [MITRE ATLAS (oficial)](https://atlas.mitre.org/)
- [CrowdStrike — What is MITRE ATLAS](https://www.crowdstrike.com/en-us/cybersecurity-101/artificial-intelligence/mitre-atlas/)
- [Fortinet — AI in Cybersecurity](https://www.fortinet.com/resources/cyberglossary/artificial-intelligence-in-cybersecurity)
- [Microsoft Security Blog — Threat actor abuse of AI (abril 2026)](https://www.microsoft.com/en-us/security/blog/2026/04/02/threat-actor-abuse-of-ai-accelerates-from-tool-to-cyberattack-surface/)
