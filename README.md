# n8n-auditor

**Semgrep for n8n workflows, with an LLM reviewer on top.**

A static analyzer + AI reviewer for [n8n](https://n8n.io) workflow JSON exports. The static
layer runs a catalog of 27 deterministic rules (security, reliability, governance) with no
LLM and no network — fast enough for CI and pre-commit. The AI layer (Gemini, structured
output) then reasons about what a linter can't: what the flow actually does, whether the
architecture pattern fits, "what happens if…" scenarios, false-positive triage and an
impact × effort priority list.

```
$ n8n-auditor scan workflows/ --no-llm
report: reports/Warehouse ETL.md
3 workflow(s), findings: 1 critical, 3 high, 5 medium, 2 low
```

Sample report: [docs/samples/Warehouse ETL.md](docs/samples/Warehouse%20ETL.md)

## Why it exists

Every rule is inspired by a real incident pattern (described generically):

- **The webhook anyone could call.** A public webhook with no auth feeding straight into
  DB writes. Nothing failed — that was the problem. → SEC-002
- **The error workflow that didn't exist.** Production flows pointed their error handler
  at a workflow id that had been deleted months earlier. Failures died in silence. → REL-001/002
- **The alphabetical "latest".** A `.sort()` on a date-as-string picked the wrong "most
  recent" row for months. No error, wrong data. → REL-008
- **The secret in a sticky note.** Credentials pasted "temporarily" into notes and pinned
  test data — then exported, backed up and committed to git forever. → SEC-001, GOV-003

## Quickstart

```bash
pip install -e .                                    # Python 3.11+
n8n-auditor scan path/to/workflow.json --no-llm     # single file, static only
n8n-auditor scan --dir workflows/ --no-llm          # folder (enables cross-workflow rules)
n8n-auditor scan --remote                           # live instance (N8N_API_URL + N8N_API_KEY)
n8n-auditor scan --dir workflows/                   # static + AI review (GEMINI_API_KEY in .env)
n8n-auditor rules                                   # the whole catalog
```

Outputs: `--format md` (default, one readable report per workflow), `--format json`
(stable, `schema_version`ed), `--format sarif` (SARIF 2.1.0 for GitHub code scanning).
Exit codes: `0` clean, `1` findings at or above `--fail-on` (default `high`), `2` execution
error. `--baseline baseline.json` suppresses known findings by fingerprint so you can adopt
it in CI without fixing everything on day one (`--write-baseline` generates it).

## Rule catalog

<!-- Generated with: n8n-auditor rules --markdown -->

| id | severity | category | what it detects |
|---|---|---|---|
| GOV-001 | medium | governance | **Two credentials share the same name.** Two different credential ids carry the same display name: indistinguishable in the n8n UI, so rotating one leaves the other alive unnoticed. |
| GOV-002 | info | governance | **Stale credential name cached in exports.** The same credential id appears with different cached names across workflows: the credential was renamed and older exports lie about which one they use. |
| GOV-003 | high | governance | **Real data pinned in the workflow (pinData).** pinData contains what looks like real data (emails, names, amounts, ids). It travels with every export, backup and git commit. |
| GOV-004 | low | governance | **Sensitive content in sticky notes.** A sticky note contains credentials, IPs or configuration-looking text: notes are exported with the workflow and read by anyone with access. |
| GOV-005 | info | governance | **Undocumented workflow / default node names.** The workflow has no purpose description (no sticky note) or keeps default node names (HTTP Request1, Code2): hard to maintain by anyone else. |
| GOV-006 | medium | governance | **Full success-execution retention with sensitive data.** An active workflow saves all successful execution data while handling sensitive-looking fields: unnecessary retention of personal data. |
| REL-001 | high | reliability | **Active workflow without error workflow.** The workflow is active but settings.errorWorkflow is not set: failures die silently with no notification path. |
| REL-002 | high | reliability | **Error workflow broken or missing.** settings.errorWorkflow points to a workflow id that does not exist in the set, or exists but has no enabled Error Trigger node. |
| REL-003 | medium | reliability | **Network/DB node without retry or error handling.** An HTTP/DB/FTP/mail node has neither retryOnFail nor an onError strategy: a transient 500 kills the whole execution. |
| REL-004 | high | reliability | **Required parameter left empty (inert logic).** A required id parameter is empty (dataTableId, workflowId, tableId...) or a TODO/FIXME note references the node: the branch looks alive but does nothing. |
| REL-005 | medium | reliability | **Routing by workflow name.** An If/Switch compares $workflow.name against a literal. Names change; ids don't. Renaming the workflow silently breaks the route. |
| REL-006 | low | reliability | **Duplicate triggers with identical configuration.** Two or more triggers of the same type share the same configuration (identical cron, same webhook path): double executions or dead code. |
| REL-007 | low | reliability | **Timezone not set or unexpected.** settings.timezone is absent (falls back to instance default) or differs from the expected timezone: cron schedules drift. |
| REL-008 | medium | reliability | **Sorting a date-like field as string.** A Sort node (or .sort() in code) orders by a field whose name suggests a date but is treated as a string: alphabetical order is not chronological order. |
| REL-009 | high | reliability | **Execute Workflow target missing.** An Execute Workflow node points to a workflow id that does not exist in the scanned set, or is empty. |
| REL-010 | low | reliability | **Disabled nodes left in the workflow.** Nodes with disabled: true remain in the flow: dead code that confuses maintenance and hides intent. |
| REL-011 | medium | reliability | **Non-idempotent DB write on a polling/cron trigger.** An INSERT without ON CONFLICT and no prior existence check, in a workflow triggered by cron/polling: a double run inserts duplicates. |
| REL-012 | medium | reliability | **Polling a service that offers webhooks.** A Schedule trigger polls a service (HTTP get) that is known to support webhooks: event-driven would be cheaper and faster. |
| SEC-001 | critical | security | **Hardcoded secret in workflow definition.** A literal secret (API key, JWT, token, password or connection string) is stored in node parameters, code, sticky notes or pinned data instead of an n8n credential. |
| SEC-002 | high | security | **Unauthenticated webhook with side effects.** A webhook/form/chat trigger accepts requests without authentication and downstream nodes perform actions with side effects (DB writes, HTTP calls, mail). |
| SEC-003 | medium | security | **Private IP or volatile tunnel URL hardcoded.** A private network IP or an ephemeral tunnel domain (ngrok, localtunnel, trycloudflare) is hardcoded in a URL/host parameter. |
| SEC-004 | high | security | **Dangerous pattern in Code node.** A Code node uses eval/new Function/child_process/fs/process.env (JS) or os.system/subprocess/eval/exec (Python). |
| SEC-005 | medium | security | **Over-privileged credential for a read-only workflow.** A credential named like a maximum-privilege role (service_role, admin, root, master) is used in a workflow that only performs reads. |
| SEC-006 | medium | security | **Personal credential in active workflow.** An active workflow uses a credential whose name looks personal (bus factor: the workflow dies when that person leaves or rotates their account). |
| SEC-007 | medium | security | **TLS certificate validation disabled.** An HTTP Request node has allowUnauthorizedCerts enabled, accepting any certificate (man-in-the-middle risk). |
| SEC-008 | low | security | **HTTP request to domain outside allowlist.** An HTTP Request targets a domain that is not in the configured allowlist. Without an allowlist, external domains are listed as info. |
| SEC-009 | high | security | **SQL built by string interpolation (SQL injection).** A database query interpolates $json/$node values directly into the SQL string via expressions instead of using query parameters (queryReplacement). |

Evidence is always redacted (first 6 chars + `…`); the tool never prints a full secret.
Expressions (`={{ $env.X }}`, `={{ $credentials.* }}`) and obvious placeholders
(`sk-xxxx…`, `<your-key>`, `${TOKEN}`) are never reported.

## AI layer

With `GEMINI_API_KEY` in `.env` (Google AI Studio, free tier works), each workflow also
gets a structured review — everything is schema-validated JSON, no free-text parsing:

- **Summary**: what the flow does, in business language.
- **Architecture**: detected pattern (event-driven / polling / batch / orchestrator /
  proxy) and whether it's the *right* pattern.
- **What-if table**: timeout, 500, expired credential, duplicate item, double run,
  malformed payload — current behavior vs. what it should be.
- **Finding triage**: each static finding confirmed / false positive / needs context.
- **Additional findings**: silent logic failures a linter can't see (`source: "llm"`).
- **Priorities**: top 5 by impact × effort, tagged bug / debt / risk.

Free-tier hygiene built in: disk cache keyed by input hash (re-runs are free), exponential
backoff on 429, `--max-llm-calls` cap, and token/cost accounting printed per run. Typical
cost per workflow at paid-tier prices: fractions of a cent (`$0.00` on free tier).
`--no-llm` skips all of it. Model auto-selected; override with `LLM_MODEL`.

## Evaluation

The rules are tested against three synthetic fixture sets
(`pytest` prints the full per-rule table and fails if targets are missed):

| set | contents | metric | target | current |
|---|---|---|---|---|
| clean | 5 well-built workflows | false positives | 0 | 0 |
| planted | 29 workflows, all 27 rules covered | recall | ≥ 0.95 | **1.00** |
| adversarial | 11 traps (split secrets, base64, placeholders, pinData, disabled error triggers…) | precision | ≥ 0.90 | **1.00** |

Two adversarial cases are *documented misses by design* (secret split across expressions,
bare base64 blob): reassembled secrets are the AI layer's job, and the fixtures encode that
boundary honestly.

The AI layer has its own eval: 8 complex synthetic workflows with 7-criteria rubrics each,
graded by a second Gemini model as judge (`evals/run_llm_eval.py`, results committed under
`evals/results/`). See [evals/README.md](evals/README.md).

## Integrations

- **Claude Code skill** — copy `.claude/skills/n8n-audit/` into `~/.claude/skills/`, then
  ask: *"audit this workflow"*. It runs the CLI and presents the report.
- **GitHub Action** — [`action.yml`](action.yml) runs the static scan and emits SARIF for
  the Security tab. Example workflow: [examples/github-audit.yml](examples/github-audit.yml).
- **pre-commit** — [`.pre-commit-hooks.yaml`](.pre-commit-hooks.yaml) for repos that back
  up workflow exports. Example config: [examples/pre-commit-config.yaml](examples/pre-commit-config.yaml).

## How it differs from `n8n audit`

n8n's native `n8n audit` (CLI/REST) audits the **instance**: unused credentials, community
nodes, filesystem access risk. It doesn't look inside your workflow logic. n8n-auditor
audits **each workflow's logic**: hardcoded secrets, broken error paths, injection,
non-idempotent writes, silent failure modes. They complement each other; run both.

It's also not a schema validator — n8n (and tools like n8n-mcp's `validate_workflow`)
already check that node parameters are valid. n8n-auditor assumes the workflow runs and
asks whether it *should* run like that.

## Roadmap

- Auto-fix suggestions as importable workflow patches (JSON diff)
- Rule packs per stack (Supabase, Microsoft Graph, Chatwoot)
- Trend tracking: score per workflow over time from CI runs
- HTML report with the workflow graph annotated with findings

## Development

```bash
python -m venv .venv && .venv/Scripts/activate   # or bin/activate
pip install -e ".[dev]"
pytest            # prints the precision/recall table
ruff check src tests
```

MIT license. Built as a portfolio project; all fixtures are synthetic and hand-written.
