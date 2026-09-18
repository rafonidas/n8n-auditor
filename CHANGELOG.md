# Changelog

All notable changes to this project are documented here. Format based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow SemVer.

## [0.1.0] - 2026-09-18

### Added

- Static analysis engine with 27 rules across security (SEC-001…009), reliability
  (REL-001…012) and governance (GOV-001…006), including cross-workflow rules
  (broken error workflows, missing Execute Workflow targets, duplicate credential names).
- Secret detection with evidence redaction: JWTs, provider API keys, Bearer/Basic tokens,
  connection strings; expression references and placeholders are never flagged.
- Loaders for single files, directories, globs and live instances
  (`--remote` via `N8N_API_URL`/`N8N_API_KEY`), tolerant of n8n 1.x/2.x exports and
  unknown nodes.
- Reports: Markdown (per workflow), stable versioned JSON, SARIF 2.1.0.
- CI ergonomics: `--fail-on` severity threshold with exit codes 0/1/2, baseline
  suppression by fingerprint (`--baseline`, `--write-baseline`).
- AI review layer on Gemini (google-genai structured output): summary, architecture
  verdict, what-if table, finding triage, additional findings, priorities. Disk cache,
  429 backoff, `--max-llm-calls`, usage/cost accounting, `--no-llm` escape hatch.
- Evaluation suite: 45 synthetic fixtures (clean/planted/adversarial) with a
  precision/recall runner wired into pytest; AI-layer eval with rubrics and an LLM judge.
- Integrations: Claude Code skill, GitHub Action (SARIF upload), pre-commit hook.
