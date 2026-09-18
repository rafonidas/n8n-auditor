# Rubric — wf03 Invoice batch orchestrator

1. Classifies the architecture as **batch / orchestrator** and accepts the pattern for a
   monthly billing run.
2. Flags the **active workflow without an error workflow** (or confirms REL-001) as
   especially serious for billing: a mid-batch crash means some accounts invoiced, some not.
3. Identifies the **empty `workflowId` in "Run enterprise addenda"** (or confirms REL-004):
   the enterprise branch is inert, enterprise accounts silently get no addenda.
4. Connects the **TODO sticky note** to that inert branch (the note admits the gap).
5. Spots the **bug in "Compute usage"**: `Math.round(Math.random() * 0)` is always 0, so
   usage falls back to `cached_units` — usage-based billing is silently wrong.
6. Acknowledges the **idempotent invoice insert** (ON CONFLICT DO NOTHING) as correct, and
   does not flag it as a duplicate-billing bug.
7. In the what-if table, covers a **crash mid-batch / partial run** (restart re-runs the
   whole account list; invoices are protected by ON CONFLICT but mails are re-sent).
