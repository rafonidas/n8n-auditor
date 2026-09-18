# n8n-auditor — analizador estático + IA de workflows n8n

> Proyecto **personal / portfolio**. Público en GitHub cuando esté listo.

## Reglas duras (no negociables)

- **Cero datos de APG.** No leer, copiar ni referenciar `../n8n-apg/`, `../n8n-rafa/apg-upgrade-2.34/`,
  `../apg-contexto/`, `../arquitectura-datos/` ni ningún workflow exportado de la instancia APG.
  Los fixtures son **sintéticos**, escritos a mano. Único JSON real permitido como muestra:
  `../bot-whatsapp-espana/n8n/chatwoot-bot-test.json` (personal, sin secretos).
- Nombres internos de APG (clientes, sistemas, personas, IPs, hosts) **no aparecen** en código,
  fixtures, docs ni tests. Si un ejemplo necesita un nombre, es inventado.
- Secretos de prueba en fixtures: formato válido pero **inventados y marcados** (`sk-test-FAKE...`,
  JWT con payload `{"fake":true}`). Nunca un secreto real, ni siquiera revocado.
- `.env` gitignoreado. Nunca imprimir `GEMINI_API_KEY`. No hay API de Anthropic disponible: todo LLM es Gemini vía Google AI Studio (free tier).
- Python 3.11, venv propio en `.venv/`. Nada global.

## Estilo

- Código, comentarios, README, docstrings, mensajes de commit: **inglés técnico**.
- Commits: Conventional Commits `type(scope): subject`.
- Simplicidad > arquitectura. Sin POO obligatoria; funciones y dataclasses alcanzan.

## Spec

Todo lo que hay que construir está en `SPEC.md`. Leerlo completo antes de escribir una línea.
