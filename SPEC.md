# SPEC — n8n-auditor

## Kickoff (pegar esto en la sesión de Fable, abierta en esta carpeta)

```
Leé CLAUDE.md y SPEC.md completos. Construí el proyecto entero según el spec, de punta a punta,
hasta el "Definition of done". Trabajá autónomo: hacé como máximo 5 preguntas de aclaración
ANTES de empezar y después no frenes hasta terminar. Commiteá por milestone (M1..M6) con
Conventional Commits. Al final entregá un resumen: qué quedó hecho, qué quedó fuera y por qué,
y cómo correr cada cosa.
```

---

## 1. Qué es y qué NO es

**Es:** un analizador de workflows n8n (JSON exportado o vía REST API) que detecta problemas de
**seguridad, confiabilidad y gobernanza** con dos capas:

1. **Capa estática** (Python puro, determinista, sin LLM): catálogo de reglas tipo semgrep/eslint
   sobre el JSON. Rápida, testeable, corre en CI.
2. **Capa IA** (Gemini API): sobre el workflow + hallazgos estáticos, razona lo que un linter no
   puede: qué hace el flujo, si el patrón de arquitectura es el correcto, tabla "qué pasa si…",
   triage de falsos positivos, priorización impacto × esfuerzo.

**No es:**
- `n8n audit` (CLI/REST nativo): eso audita la **instancia** (credenciales sin uso, nodos community,
  filesystem). Nosotros auditamos la **lógica de cada workflow**. Documentar la diferencia en el README.
- Un validador de esquema de nodos (eso ya lo hace n8n-mcp `validate_workflow`). No validar que
  los parámetros de un nodo sean válidos; asumir que el workflow ya corre.

**Analogía para el README:** "semgrep for n8n workflows, with an LLM reviewer on top".

## 2. Entradas

- Uno o más archivos `.json` de workflow (export de n8n). Soportar formato de export de UI
  (`{name, nodes, connections, settings, pinData?, meta?}`) y respuesta de la API
  (`GET /api/v1/workflows/{id}` → incluye `id`, `active`, `updatedAt`, `versionId`).
- Directorio completo (`--dir`), glob.
- Opcional: instancia viva vía `N8N_API_URL` + `N8N_API_KEY` en `.env` → `n8n-auditor scan --remote`
  descarga todos los workflows y los audita. Para las reglas cross-workflow (ver §3 GOV/REL-002)
  hace falta el set completo; con un solo archivo esas reglas se marcan `skipped`.
- Soportar n8n **1.x y 2.x** (hay diferencias de `typeVersion` de nodos; no romperse con campos
  desconocidos, nunca fallar por un nodo que no conocemos).

## 3. Catálogo de reglas (capa estática)

Cada regla: `id`, `severity` (critical/high/medium/low/info), `category`, `title`, `description`,
`node` (nombre + tipo), `path` (JSON pointer al campo), `evidence` (fragmento redactado — nunca
imprimir el secreto entero, mostrar primeros 6 chars + `…`), `fix` (texto accionable), `confidence`.

Las reglas están **inspiradas en incidentes reales** (descritos genéricamente, nunca con nombres).
Implementar TODAS; las marcadas ★ son las de mayor valor.

### SEC — seguridad

| id | sev | qué detecta |
|---|---|---|
| SEC-001 ★ | critical | Secreto hardcodeado en `parameters` (no en `credentials`): JWT (`eyJ…` 3 segmentos), API keys de proveedores conocidos (`sk-`, `sk-ant-`, `AIza`, `ghp_`, `xoxb-`, etc.), `Bearer <token>` literal, `Basic <base64>` que decodifica a `user:pass`, connection strings (`Server=…;Password=…`, `postgres://user:pass@`), campos llamados `password/token/secret/apiKey` con valor literal no-expresión. Incluye headers de HTTP Request, body JSON, query params, `jsCode`, `pythonCode`, Set nodes, sticky notes (`n8n-nodes-base.stickyNote`), y **`pinData`**. Ignorar valores que son expresiones (`={{ $env.X }}`, `={{ $credentials… }}`) y placeholders obvios (`<your-key>`, `xxx`, `${TOKEN}`). |
| SEC-002 ★ | high | Webhook (`n8n-nodes-base.webhook`, Form Trigger, Chat Trigger) con `authentication: none` (o ausente) y sin ningún nodo `If`/`Code` aguas abajo que valide un header/secreto antes de una acción con efecto (DB write, HTTP, mail). Reportar severity `medium` si hay validación downstream detectada. |
| SEC-003 | medium | IP privada (`10.`, `192.168.`, `172.16-31.`) o URL de túnel volátil (`*.ngrok*.app`, `*.loca.lt`, `*.trycloudflare.com`) hardcodeada en `url`/`host`. |
| SEC-004 | high | Code node con patrones peligrosos: `eval(`, `new Function(`, `require('child_process')`, `require('fs')`, `process.env` (fuga de env), `exec(`/`os.system` en Python. Marcar `info` si es solo `console.log` de un objeto completo de credenciales. |
| SEC-005 | medium | Credencial cuyo **nombre** sugiere privilegio máximo (`service_role`, `admin`, `root`, `master`) en un flujo que solo hace lecturas (heurística: todos los nodos DB con `operation: select/executeQuery` con `SELECT`). |
| SEC-006 | medium | Credencial con nombre **personal** en workflow activo: patrón configurable (`--personal-cred-pattern`, default `^[A-Z][a-z]+-` o contiene `personal`). Es bus factor. |
| SEC-007 | medium | HTTP Request con `allowUnauthorizedCerts: true`. |
| SEC-008 | low | HTTP Request a dominio fuera de una allowlist opcional (`--allowed-domains`); sin allowlist, solo listar dominios externos como `info`. |
| SEC-009 | high | SQL construido por concatenación/expresión dentro del `query` de Postgres/MySQL/MSSQL (`={{ … }}` interpolando `$json.*` directo en el string) sin `queryReplacement`/parámetros. SQL injection. |

### REL — confiabilidad

| id | sev | qué detecta |
|---|---|---|
| REL-001 ★ | high | Workflow activo sin `settings.errorWorkflow`. |
| REL-002 ★ | high | `errorWorkflow` apunta a un id que (a) no existe en el set, o (b) existe pero no tiene nodo `n8n-nodes-base.errorTrigger`. Cross-workflow. |
| REL-003 | medium | Nodo HTTP Request / DB / FTP / mail sin `retryOnFail` ni `onError` (`continueErrorOutput`/`continueRegularOutput`). Un 500 transitorio mata la ejecución. |
| REL-004 ★ | high | Parámetro obligatorio vacío con marcador de TODO cerca: `dataTableId: ""`, `workflowId: ""`, `tableId: ""`, o notas/sticky con `TODO`/`FIXME` referenciando el nodo. Lógica inerte. |
| REL-005 ★ | medium | Ruteo por **nombre** de workflow: `If`/`Switch` comparando `$workflow.name` / `{{ $json.workflow.name }}` contra un literal. Los nombres cambian, los ids no. |
| REL-006 | low | Dos o más triggers del mismo tipo con la misma config (cron idéntico, mismo path de webhook). |
| REL-007 | low | `settings.timezone` ausente o distinto de una esperada (`--expected-timezone`). |
| REL-008 | medium | Nodo `Sort` (o `.sort()` en Code) sobre un campo cuyo nombre sugiere fecha (`date|fecha|created|updated|time`) con tipo `string`. Orden alfabético ≠ cronológico. |
| REL-009 | high | `Execute Workflow` apuntando a un `workflowId` inexistente en el set (cross-workflow) o vacío. |
| REL-010 | low | Nodos `disabled: true` que quedaron en el flujo (deuda / confusión). |
| REL-011 | medium | Escritura a DB sin idempotencia detectable: `INSERT` sin `ON CONFLICT` y sin nodo previo que chequee existencia, en un flujo con trigger cron/polling (puede correr dos veces). Confidence `low`; es heurística. |
| REL-012 | medium | Trigger de polling (Schedule + HTTP/DB "get") donde el origen podría avisar (webhook disponible para ese servicio: lista corta de servicios conocidos con webhooks). Confidence `low`. |

### GOV — gobernanza

| id | sev | qué detecta |
|---|---|---|
| GOV-001 ★ | medium | Cross-workflow: dos credenciales con el **mismo nombre y distinto id** (indistinguibles en la UI; rotás una y la otra sigue viva). |
| GOV-002 | info | Cross-workflow: mismo id con distintos nombres cacheados (es una sola credencial renombrada; los JSON viejos mienten). |
| GOV-003 ★ | high | `pinData` con datos reales (emails, nombres, montos, ids) dejado en el workflow: viaja al backup/repo. |
| GOV-004 | low | Sticky notes con credenciales, IPs, o texto que parece configuración sensible. |
| GOV-005 | info | Workflow sin descripción/sticky de propósito; nodos con nombre default (`HTTP Request1`, `Code2`). |
| GOV-006 | medium | Workflow activo con `settings.saveDataSuccessExecution: "all"` + nodos que manejan datos sensibles (heurística por nombres de campos) → retención innecesaria. Confidence `low`. |

## 4. Capa IA

- SDK oficial `google-genai` (Python, `from google import genai`) con key de Google AI Studio
  (`GEMINI_API_KEY` en `.env`, **free tier**). Modelo configurable por env (`LLM_MODEL`); default el
  Gemini más capaz disponible en AI Studio al momento de construir — verificarlo listando modelos
  con el SDK, no asumirlo. **Salida JSON estructurada** (`response_mime_type="application/json"` +
  `response_schema` con un modelo Pydantic). Nada de parseo de texto libre. Verificar la firma
  exacta contra la doc del SDK instalado; no inventar parámetros.
- Free tier = rate limits bajos: backoff exponencial ante 429, cache en disco de respuestas por
  hash del input (para re-correr evals sin re-pagar cuota), y un flag `--max-llm-calls`.
- Input al modelo: un **resumen compacto** del workflow (no el JSON crudo entero cuando supera N
  tokens): lista de nodos (nombre, tipo, parámetros relevantes truncados), conexiones como grafo
  en texto, settings, y los hallazgos estáticos. Mantener el system prompt estable y corto (el free tier no justifica context caching).
- Output (schema):
  - `summary`: qué hace el flujo en 2-3 líneas, lenguaje de negocio.
  - `architecture`: patrón (event-driven / polling / batch / orchestrator / proxy) + `is_right_pattern` + justificación.
  - `what_if`: lista de `{scenario, current_behavior, should_be}` (timeout, 500, credencial vencida, item duplicado, corrida doble, payload malformado…).
  - `finding_triage`: por cada hallazgo estático, `{id, verdict: confirmed|false_positive|needs_context, reason}`.
  - `additional_findings`: cosas que el linter no ve (lógica, fallos silenciosos), mismo shape que los estáticos con `source: "llm"`.
  - `priorities`: top 5 ordenado por impacto × esfuerzo, distinguiendo bug / deuda / riesgo.
- Manejar respuestas bloqueadas por safety (`finish_reason` distinto de STOP / `prompt_feedback`),
  respuestas vacías y errores tipados del SDK; nunca dejar que un 429 tire el scan completo.
- Flag `--no-llm` para correr solo la capa estática (CI, sin API key).
- Costo: loguear `usage` por llamada; imprimir tokens y costo estimado al final.

## 5. Salidas

- `--format json`: array de findings + bloque `llm` (si corrió). Estable, versionado (`schema_version`).
- `--format sarif`: SARIF 2.1.0 mínimo válido (para GitHub code scanning).
- `--format md`: reporte Markdown legible, un archivo por workflow, con la sección IA si corrió.
  Estructura: header (nombre, id, activo, N nodos) → resumen → arquitectura → tabla "qué pasa si" →
  tabla de hallazgos (severidad, id, nodo, detalle, fix) → prioridades.
- Exit code: `0` sin hallazgos ≥ `--fail-on` (default `high`), `1` si hay, `2` error de ejecución.
- `--baseline baseline.json`: ignora hallazgos ya conocidos (fingerprint = rule id + workflow id + node name + path). Para adoptar en CI sin arreglar todo el día 1.

## 6. Integraciones

- **Claude Code skill** en `.claude/skills/n8n-audit/SKILL.md`: dispara con "auditá este workflow /
  este JSON / esta carpeta", corre la CLI y presenta el `.md`. Debe ser instalable copiando la carpeta
  a `~/.claude/skills/`.
- **GitHub Action** (`action.yml` + ejemplo de workflow) que corre `scan --no-llm --format sarif` sobre
  un directorio y sube el SARIF. Opcional el modo con LLM si hay `GEMINI_API_KEY` en secrets.
- **pre-commit hook** (config de ejemplo) para repos que backupean workflows.

## 7. Evaluación (esto es lo que hace al proyecto mostrable)

`tests/fixtures/` con workflows **sintéticos**, cada uno con un `expected.json` al lado:

- **Clean set** (≥ 5): workflows bien hechos; expected = `[]`. Miden falsos positivos.
- **Planted set** (≥ 1 por regla, ≥ 25 total): cada uno con 1-3 bugs plantados y su expected exacto.
- **Adversarial set** (≥ 10): casos diseñados para engañar al linter —
  secreto partido en dos expresiones y concatenado; secreto en base64 dentro de un body JSON;
  secreto en `pinData`; secreto en sticky note; JWT dentro de un string de `jsCode`; placeholder
  `sk-xxxxxxxx` (debe ser **ignorado**); `={{ $env.API_KEY }}` (ignorado); `example.com` con
  `Bearer` de ejemplo en una nota de documentación (ignorado); webhook sin auth pero con `If`
  validando `headers['x-secret']` (SEC-002 baja a medium); `errorWorkflow` válido pero el destino
  tiene el Error Trigger `disabled: true` (REL-002 debe disparar).
- Test runner (`pytest`) que calcula **precision / recall por regla** y global, y lo imprime en tabla.
  Objetivo: recall ≥ 0.95 en planted, precision ≥ 0.9 en adversarial. Fallar el test si baja.
- **Eval de la capa IA** (`evals/llm/`): 8 workflows sintéticos más complejos (15-40 nodos) con un
  rubric por workflow (`rubric.md`: 5-8 criterios verificables, ej. "identifica que el sort por string
  es un fallo silencioso", "clasifica como polling y dice que debería ser webhook"). Script
  `evals/run_llm_eval.py` que corre la capa IA y usa un modelo Gemini distinto al generador (o el mismo con temperatura 0 si no hay otro) como juez contra el rubric,
  guarda resultados con fecha en `evals/results/`. Correrlo una vez y commitear el resultado.

## 8. Estructura

```
n8n-auditor/
├── src/n8n_auditor/
│   ├── cli.py            # typer
│   ├── loader.py         # file / dir / remote
│   ├── model.py          # Workflow, Node, Finding dataclasses
│   ├── rules/            # un módulo por categoría; registro de reglas por decorador
│   ├── crossref.py       # análisis cross-workflow (credenciales, errorWorkflow, executeWorkflow)
│   ├── llm.py            # capa IA
│   ├── report/           # json / sarif / md
│   └── secrets.py        # detectores + redacción de evidencia
├── tests/  evals/  .claude/skills/n8n-audit/  action.yml  pyproject.toml  README.md  CHANGELOG.md
```

`pyproject.toml` con `[project.scripts] n8n-auditor = ...`, `ruff`, `pytest`. Dependencias mínimas:
`typer`, `pydantic`, `google-genai`, `httpx`, `python-dotenv`, `rich`.

## 9. README (portfolio)

Inglés. Secciones: qué es en una línea + captura del reporte · por qué existe (los 3-4 incidentes
genéricos que motivan las reglas ★) · quickstart · catálogo de reglas (tabla generada desde el código,
no a mano) · capa IA (qué agrega, costo por workflow) · resultados de evaluación (tabla precision/recall)
· integraciones (skill, Action, pre-commit) · diferencia con `n8n audit` · roadmap.

## 10. Milestones

- **M1** — model + loader + 5 reglas SEC + reporte JSON + tests fixtures iniciales.
- **M2** — resto de reglas SEC/REL/GOV + crossref + reporte md/sarif + baseline + exit codes.
- **M3** — fixtures completos (clean/planted/adversarial) + runner precision/recall.
- **M4** — capa IA + structured outputs + caching + `--no-llm`.
- **M5** — eval IA con rubrics + resultados commiteados.
- **M6** — skill, Action, pre-commit, README final, CHANGELOG.

## 11. Definition of done

- `pip install -e .` + `n8n-auditor scan tests/fixtures/planted --no-llm` corre y reporta.
- `pytest` verde con la tabla precision/recall impresa y dentro de objetivo.
- `n8n-auditor scan <un fixture complejo> --format md` con LLM produce un reporte coherente.
- README completo; ningún nombre, IP, host ni dato de APG en el repo (grep de verificación en el
  resumen final: `grep -ri "apg\|viga\|comfiar" .` debe devolver vacío).
