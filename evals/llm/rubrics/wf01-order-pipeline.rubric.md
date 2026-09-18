# Rubric — wf01 Order pipeline

Verifiable criteria for the AI review of `wf01-order-pipeline.json`:

1. Classifies the architecture as **polling** (not event-driven).
2. States that polling the shop API is **not the right pattern**: the platform offers
   order webhooks, so the flow should be event-driven.
3. Identifies the **string sort on `created_at`** as a silent failure (alphabetical, not
   chronological) or confirms the static REL-008 finding as real.
4. Identifies that **`Insert order row` is not idempotent**: a 5-minute poll re-reading the
   same orders (or an overlapping run) inserts duplicates; suggests ON CONFLICT / unique
   key / dedupe on `order_ref`.
5. In the what-if table, covers **API failure or rate-limit during the poll** with a
   concrete current-behavior description.
6. Does **not** flag the parameterized queries (`$1` + queryReplacement) as SQL injection.
7. Mentions the **disabled "Old CSV export"** node as dead weight or confirms REL-010.
