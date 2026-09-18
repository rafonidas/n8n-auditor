# Rubric — wf08 Notifier hub

1. Classifies the architecture as **event-driven with a batch digest** (or orchestrator);
   any of those labels is acceptable if justified by the two entry points.
2. Confirms the **duplicate digest triggers** (REL-006): the same 9:00 cron exists twice,
   so the digest mail and Slack post go out twice every day.
3. Spots the **severity routing gap**: only `critical` pages on-call; a `warning` alert is
   posted but an alert with severity `error` (or any unexpected value) falls to the
   fallback output and is only stored — nobody is notified.
4. Notes the **credential hygiene issue**: two different Slack credential ids share the
   name "Alerts Bot" (indistinguishable in the UI when rotating) — cross-checks GOV-001
   thinking inside a single workflow.
5. In the what-if table, covers the **pager API failing for a critical alert**: after
   retries the execution errors; the alert was stored but on-call was never paged.
6. Recognizes the alert intake as correctly **authenticated** (headerAuth) and does not
   flag SEC-002 here.
7. Mentions that digest **counts include info-level noise** or some equivalent observation
   about digest quality/duplication — shows it actually read the digest branch.
