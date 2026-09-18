# Rubric — wf07 Warehouse ETL

1. Classifies the architecture as **polling/batch** ETL and treats it as acceptable for
   DB-to-DB movement (no webhook exists for a database table).
2. Spots the **mark-processed race**: "Mark processed" re-runs `LIMIT 1000` on live data,
   so rows that arrived between read and update are marked processed without being loaded
   — silent data loss. This is the key finding.
3. Spots the **filtered-events leak**: test events are filtered out of the load but still
   marked processed... and, conversely, that filtered rows are never loaded anywhere
   (accepts either framing tied to the Filter node).
4. Flags **no retry / no error handling** on the DB and HTTP nodes (confirms REL-003):
   a transient failure aborts mid-batch between INSERT and UPDATE, causing duplicates on
   the next run (no ON CONFLICT on `wh_events`).
5. Flags the **dead-letter branch that is never connected** ("Dead letter set" / "Alert
   channel" have no incoming connection): the safety net is decorative.
6. Confirms the **active workflow without errorWorkflow** (REL-001) and the **private IP**
   metrics push (SEC-003) as real.
7. Mentions the **"Warehouse admin" credential** as over-privileged naming for an insert
   job (or confirms a SEC-005-style concern).
