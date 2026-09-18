# Rubric — wf04 Support bot

1. Classifies the architecture as **event-driven** (chat trigger) and accepts the pattern.
2. Confirms the **hardcoded JWT** in "Classify intent" (SEC-001) as a real finding, not a
   false positive.
3. Confirms or independently flags the **`console.log(process.env)` debug node** as an
   environment/secret leak into execution logs on a public chat flow.
4. Flags the **public chat trigger** with no rate limiting or abuse control ("Rate limiter
   placeholder" is a NoOp) — cost/abuse risk on every message.
5. Notes the **PII/retention angle**: every conversation is logged to `chat_log` with
   session ids and replies.
6. In the what-if table, covers **the KB API being down**: user still gets the fallback
   reply, but nothing distinguishes an outage from "no answer found".
7. Does **not** invent findings about the parameterized `Load user context` query.
