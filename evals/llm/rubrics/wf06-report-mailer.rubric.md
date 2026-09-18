# Rubric — wf06 Weekly ops report

1. Classifies the architecture as **batch** (weekly scheduled report) and accepts it.
2. Spots the **division-by-zero / NaN in "Compute KPIs"**: a week with zero closed tickets
   makes `avgSat` NaN, and the report mails "CSAT: NaN" silently.
3. Confirms the **pinned real-looking customer data** (GOV-003): ticket emails ride along
   in every export of this workflow.
4. Confirms the **retention issue** (GOV-006): `saveDataSuccessExecution: all` on a flow
   whose payloads carry customer emails.
5. Discusses the **string comparison sort on `opened_at`** in the Code node: works only
   while all timestamps share the same ISO format/timezone; flags it as fragile or as a
   confirmed REL-008.
6. In the what-if table, covers **the SMTP send failing after KPIs were archived** or the
   inverse ordering issue (mail sent but archive fails) — partial-completion behavior.
7. Does **not** flag the parameterized `weekly_kpis` upsert as a duplication bug (it is
   idempotent via ON CONFLICT).
