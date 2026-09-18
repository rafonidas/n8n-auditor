"""Run the AI-layer eval: review each eval workflow, judge the review against its rubric.

Usage:
    python evals/run_llm_eval.py [--only wf01] [--judge-model MODEL]

Needs GEMINI_API_KEY in .env. The judge uses LLM_JUDGE_MODEL if set, otherwise a
different Gemini model than the reviewer when available, otherwise the same model
at temperature 0. Results land in evals/results/<date>-<reviewer-model>.json/.md.
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import sys
import time
from pathlib import Path
from typing import Literal

from dotenv import load_dotenv
from pydantic import BaseModel

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from n8n_auditor.engine import scan  # noqa: E402
from n8n_auditor.llm import LLMError, LLMReviewer, MODEL_PREFERENCE  # noqa: E402
from n8n_auditor.loader import load_file  # noqa: E402
from n8n_auditor.rules import ScanContext  # noqa: E402

WORKFLOWS_DIR = ROOT / "evals" / "llm" / "workflows"
RUBRICS_DIR = ROOT / "evals" / "llm" / "rubrics"
RESULTS_DIR = ROOT / "evals" / "results"

JUDGE_SYSTEM = """You are grading an automated AI review of an n8n workflow against a rubric.
For each rubric criterion, decide whether the review satisfies it. A criterion is met only
if the review states the substance of the criterion (exact wording not required). Quote the
part of the review that satisfies it as evidence, or explain briefly why it is not met.
Be strict: vague generalities do not satisfy specific criteria."""


class CriterionResult(BaseModel):
    criterion: str
    met: bool
    evidence: str


class JudgeResult(BaseModel):
    criteria: list[CriterionResult]
    overall_comment: str


def judge(client, model: str, rubric: str, review_json: str) -> JudgeResult:
    from google.genai import types

    prompt = (
        f"RUBRIC:\n{rubric}\n\nAI REVIEW (JSON):\n{review_json}\n\n"
        "Grade each numbered rubric criterion."
    )
    resp = client.models.generate_content(
        model=model,
        contents=prompt,
        config=types.GenerateContentConfig(
            system_instruction=JUDGE_SYSTEM,
            response_mime_type="application/json",
            response_schema=JudgeResult,
            temperature=0,
        ),
    )
    if resp.parsed is None:
        raise LLMError("judge returned an unparseable response")
    return resp.parsed


def pick_judge_model(reviewer: LLMReviewer, override: str | None) -> str:
    import os

    if override:
        return override
    if os.environ.get("LLM_JUDGE_MODEL"):
        return os.environ["LLM_JUDGE_MODEL"]
    for candidate in MODEL_PREFERENCE:
        if candidate != reviewer.model:
            return candidate
    return reviewer.model  # same model, temperature 0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--only", help="Run a single workflow by prefix, e.g. wf03")
    parser.add_argument("--judge-model", help="Override the judge model")
    parser.add_argument("--max-llm-calls", type=int, default=40)
    args = parser.parse_args()

    load_dotenv(ROOT / ".env")
    try:
        reviewer = LLMReviewer(max_calls=args.max_llm_calls, cache_dir=ROOT / ".llm_cache")
    except LLMError as e:
        print(f"Cannot run the AI eval: {e}. Put GEMINI_API_KEY in .env and retry.")
        return 2

    judge_model = pick_judge_model(reviewer, args.judge_model)
    print(f"reviewer model: {reviewer.model} | judge model: {judge_model}")

    results = []
    total_met = total_criteria = 0
    for wf_file in sorted(WORKFLOWS_DIR.glob("*.json")):
        if args.only and not wf_file.stem.startswith(args.only):
            continue
        rubric_file = RUBRICS_DIR / f"{wf_file.stem}.rubric.md"
        if not rubric_file.exists():
            print(f"skip {wf_file.name}: no rubric")
            continue
        print(f"reviewing {wf_file.name} …")
        wf = load_file(wf_file)
        findings, _ = scan([wf], ScanContext(full_set=False))
        try:
            review = reviewer.review(wf, findings)
        except LLMError as e:
            print(f"  review failed: {e}")
            results.append({"workflow": wf_file.stem, "error": str(e)})
            continue
        rubric = rubric_file.read_text(encoding="utf-8")
        try:
            graded = judge(reviewer.client, judge_model, rubric, json.dumps(review))
        except Exception as e:
            print(f"  judge failed: {e}")
            results.append({"workflow": wf_file.stem, "review": review, "error": f"judge: {e}"})
            continue
        met = sum(1 for c in graded.criteria if c.met)
        total_met += met
        total_criteria += len(graded.criteria)
        print(f"  score: {met}/{len(graded.criteria)}")
        results.append({
            "workflow": wf_file.stem,
            "score": {"met": met, "total": len(graded.criteria)},
            "criteria": [c.model_dump() for c in graded.criteria],
            "judge_comment": graded.overall_comment,
            "review": review,
        })
        time.sleep(2)  # be gentle with free-tier rate limits

    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    stamp = dt.date.today().isoformat()
    out_json = RESULTS_DIR / f"{stamp}-{reviewer.model}.json"
    out_json.write_text(json.dumps({
        "date": stamp,
        "reviewer_model": reviewer.model,
        "judge_model": judge_model,
        "total": {"met": total_met, "criteria": total_criteria},
        "results": results,
    }, indent=2, ensure_ascii=False), encoding="utf-8")

    lines = [f"# AI-layer eval — {stamp}", "",
             f"Reviewer: `{reviewer.model}` · Judge: `{judge_model}`", "",
             "| workflow | score |", "|---|---|"]
    for r in results:
        score = f"{r['score']['met']}/{r['score']['total']}" if "score" in r else f"error: {r.get('error')}"
        lines.append(f"| {r['workflow']} | {score} |")
    if total_criteria:
        lines.append(f"| **total** | **{total_met}/{total_criteria} "
                     f"({100 * total_met / total_criteria:.0f}%)** |")
    (RESULTS_DIR / f"{stamp}-{reviewer.model}.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"\nresults: {out_json}")
    if total_criteria:
        print(f"TOTAL: {total_met}/{total_criteria} ({100 * total_met / total_criteria:.0f}%)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
