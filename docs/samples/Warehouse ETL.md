# Audit report — Warehouse ETL

**id:** `wf-eval-07` · **active:** yes · **nodes:** 12 · **source:** `evals\llm\workflows\wf07-warehouse-etl.json`

## Findings

| Sev | Rule | Node | Detail | Fix |
|---|---|---|---|---|
| 🟠 high | REL-001 | — | Active workflow without error workflow: active: true, errorWorkflow: (not set) | Create an error workflow (Error Trigger → notification) and set it in workflow settings. |
| 🟡 medium | REL-003 | Load into warehouse | Network/DB node without retry or error handling: retryOnFail: false, onError: stopWorkflow (default) | Enable Retry On Fail (2-3 tries with wait) and/or route the error output. |
| 🟡 medium | REL-003 | Mark processed | Network/DB node without retry or error handling: retryOnFail: false, onError: stopWorkflow (default) | Enable Retry On Fail (2-3 tries with wait) and/or route the error output. |
| 🟡 medium | REL-003 | Push stats | Network/DB node without retry or error handling: retryOnFail: false, onError: stopWorkflow (default) | Enable Retry On Fail (2-3 tries with wait) and/or route the error output. |
| 🟡 medium | REL-003 | Read source events | Network/DB node without retry or error handling: retryOnFail: false, onError: stopWorkflow (default) | Enable Retry On Fail (2-3 tries with wait) and/or route the error output. |
| 🟡 medium | SEC-003 | Push stats | Private IP or volatile tunnel URL hardcoded: 10.0.44.7 | Use a stable DNS name or an environment variable; tunnel URLs rotate and private IPs break outside the original network. |
| ⚪ info | SEC-008 | Push stats | HTTP request to domain outside allowlist: external domain: 10.0.44.7 | Review that this external destination is expected; configure --allowed-domains to enforce an allowlist. |
