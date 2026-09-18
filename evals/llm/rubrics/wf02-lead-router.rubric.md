# Rubric — wf02 Lead router

1. Classifies the architecture as **event-driven** (webhook intake) and accepts it as the
   right pattern for lead capture.
2. Flags the **unauthenticated public webhook** feeding CRM writes (or confirms SEC-002):
   anyone can inject fake leads.
3. Identifies the **Switch on `$workflow.name`** as fragile routing (rename silently drops
   every lead) — the Switch has only a "prod" output, so on any other name items go nowhere.
4. Identifies the **silent drop**: when the workflow is renamed or the switch doesn't match,
   leads disappear with no error and no response to the form.
5. Flags the **personal Gmail credential** ("Federico-Gmail") in an active flow as bus factor.
6. Notes the **disabled dedupe node**: duplicate form submissions create duplicate CRM deals.
7. In the what-if table, covers **CRM API down** (retryOnFail exists, but what happens after
   retries are exhausted with respondToWebhook pending).
