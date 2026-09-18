# AI-layer evaluation

8 synthetic workflows (12–15 nodes each) in `llm/workflows/`, each paired with a
`llm/rubrics/<name>.rubric.md` holding 7 verifiable criteria (silent failures, wrong
patterns, planted bugs the static layer cannot see).

Run:

```bash
python evals/run_llm_eval.py
```

Requires `GEMINI_API_KEY` in `.env` (Google AI Studio, free tier). The reviewer model is
auto-selected (override with `LLM_MODEL`); the judge is a *different* Gemini model when
available (`LLM_JUDGE_MODEL` to override), otherwise the same model at temperature 0.

Results are written to `results/<date>-<model>.json` (full grading with evidence quotes)
and `results/<date>-<model>.md` (score table). Reviews are cached in `.llm_cache/`, so
re-running after a rate-limit hiccup only re-pays the failed calls.

> Status: the harness is complete but no result is committed yet — this environment has no
> `GEMINI_API_KEY`. Run the command above once and commit `evals/results/`.
