# Rubric — wf05 Partner data proxy

1. Classifies the architecture as **proxy** (request in → internal system → push out).
2. Confirms the **SQL injection** in "Query partner rows" (SEC-009): `partner_id` and
   `period` from the request body are interpolated into T-SQL; a crafted body reads other
   partners' rows or worse.
3. Confirms the **`allowUnauthorizedCerts: true`** on "Push to partner API" (SEC-007) as
   real risk for data pushed to an external party.
4. Flags the **`callback_url` from the request body**: the push destination can be chosen
   by the caller (`$json.callback_url ||`), which is an exfiltration vector even with header
   auth on the webhook.
5. Questions whether **redaction in a Code node** is the right layer (a view / column
   permissions in the DB would be safer than remembering to destructure).
6. In the what-if table, covers the **partner API being unreachable**: request retried,
   then execution fails after "Reply delivered" was never sent — partner sees a timeout.
7. Does **not** flag the parameterized `delivery_log` insert as injection.
