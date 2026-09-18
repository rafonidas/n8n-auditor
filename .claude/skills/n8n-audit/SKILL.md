---
name: n8n-audit
description: Audit n8n workflow JSON files for security, reliability and governance issues using the n8n-auditor CLI. Use when the user asks to audit, review or lint an n8n workflow, a workflow JSON/export, or a folder of workflows ("auditá este workflow", "revisá este JSON", "audit this n8n flow").
---

# n8n-audit

Run the `n8n-auditor` CLI on the workflow(s) the user points at and present the findings.

## Steps

1. Resolve the target: a `.json` file, several files, or a directory. If the user gave no
   path, ask for it. For a live instance, `--remote` works when `N8N_API_URL` and
   `N8N_API_KEY` are set in the environment/.env.
2. Run the static scan first (fast, no API key needed):

   ```bash
   n8n-auditor scan <target> --no-llm --format md --output ./reports
   ```

   If `n8n-auditor` is not on PATH, run it from the project venv
   (`<repo>/.venv/Scripts/n8n-auditor` on Windows, `<repo>/.venv/bin/n8n-auditor` on Unix)
   or `pip install n8n-auditor` / `pip install -e <repo>` first.
3. If `GEMINI_API_KEY` is available and the user wants the deep review, re-run without
   `--no-llm` (add `--max-llm-calls 5` for large folders).
4. Read the generated `.md` report(s) in `./reports/` and present them: lead with
   critical/high findings (rule id, node, evidence, fix), then reliability and governance.
   Keep the "what if" table and priorities if the AI layer ran.
5. Exit code 1 means findings ≥ high exist; 0 clean; 2 execution error (report the stderr).

## Notes

- Cross-workflow rules (REL-002, REL-009, GOV-001, GOV-002) only run when scanning a
  directory or several files; mention it when auditing a single file.
- Never print full secrets: the tool already redacts evidence, keep it that way.
- Useful flags: `--fail-on`, `--baseline`, `--allowed-domains`, `--expected-timezone`,
  `--personal-cred-pattern`. `n8n-auditor rules` lists the whole catalog.
