"""AI review layer: Gemini structured-output review of a workflow + static findings.

Free-tier aware: disk cache keyed by input hash, exponential backoff on 429,
hard cap on calls per run, and usage/cost accounting.
"""
from __future__ import annotations

import hashlib
import json
import os
import time
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, Field

from .model import Finding, Workflow

CACHE_DIR = Path(".llm_cache")
FALLBACK_MODEL = "gemini-2.5-flash"
MODEL_PREFERENCE = ["gemini-2.5-pro", "gemini-2.5-flash"]

# USD per 1M tokens (input, output). Free tier bills $0; this estimates paid-tier cost.
PRICING = {
    "gemini-2.5-pro": (1.25, 10.0),
    "gemini-2.5-flash": (0.30, 2.50),
}

MAX_RAW_JSON_CHARS = 20000
MAX_RETRIES = 4

SYSTEM_PROMPT = """You are a senior automation reviewer auditing n8n workflows.
You receive a compact description of one workflow (nodes, connections graph, settings)
plus findings from a static linter. Reason about what the linter cannot see:
what the flow actually does, whether the architecture pattern fits, failure scenarios,
false positives in the static findings, and silent logic errors.
Be concrete and grounded in the given nodes; never invent nodes or parameters.
Severity values: critical, high, medium, low, info. Keep texts short and factual."""


class Architecture(BaseModel):
    pattern: Literal["event-driven", "polling", "batch", "orchestrator", "proxy", "other"]
    is_right_pattern: bool
    justification: str


class WhatIf(BaseModel):
    scenario: str
    current_behavior: str
    should_be: str


class Triage(BaseModel):
    id: str = Field(description="Rule id of the static finding, e.g. SEC-001")
    verdict: Literal["confirmed", "false_positive", "needs_context"]
    reason: str


class LLMFinding(BaseModel):
    title: str
    description: str
    severity: Literal["critical", "high", "medium", "low", "info"]
    node_name: str | None = None
    fix: str
    confidence: Literal["high", "medium", "low"]


class Priority(BaseModel):
    item: str
    kind: Literal["bug", "debt", "risk"]
    reason: str


class WorkflowReview(BaseModel):
    summary: str = Field(description="What the flow does, 2-3 lines, business language")
    architecture: Architecture
    what_if: list[WhatIf]
    finding_triage: list[Triage]
    additional_findings: list[LLMFinding]
    priorities: list[Priority] = Field(description="Top 5 by impact x effort")


class LLMError(Exception):
    pass


def summarize_workflow(wf: Workflow, findings: list[Finding]) -> str:
    """Compact, token-bounded text representation of a workflow for the model."""
    raw = json.dumps(wf.raw, ensure_ascii=False)
    lines = [f"WORKFLOW: {wf.name} (id={wf.id}, active={wf.active})"]
    lines.append(f"SETTINGS: {json.dumps(wf.settings, ensure_ascii=False)}")
    lines.append("NODES:")
    for n in wf.nodes:
        params = json.dumps(n.parameters, ensure_ascii=False)
        if len(params) > 400:
            params = params[:400] + "…"
        flags = []
        if n.disabled:
            flags.append("disabled")
        if n.raw.get("retryOnFail"):
            flags.append("retryOnFail")
        if n.raw.get("onError"):
            flags.append(f"onError={n.raw['onError']}")
        creds = ",".join(
            c.get("name", "?") if isinstance(c, dict) else str(c) for c in n.credentials.values()
        )
        lines.append(
            f"- {n.name} [{n.type}]"
            + (f" creds({creds})" if creds else "")
            + (f" ({', '.join(flags)})" if flags else "")
            + f" params: {params}"
        )
    lines.append("CONNECTIONS:")
    for source, conns in wf.connections.items():
        if not isinstance(conns, dict):
            continue
        for ctype, outputs in conns.items():
            for i, branch in enumerate(outputs or []):
                for link in branch or []:
                    if isinstance(link, dict):
                        lines.append(f"- {source} -[{ctype}:{i}]-> {link.get('node')}")
    if wf.pin_data:
        lines.append(f"PINDATA KEYS: {list(wf.pin_data.keys())}")
    lines.append("STATIC FINDINGS:")
    if findings:
        for f in findings:
            lines.append(f"- {f.rule_id} [{f.severity}] node={f.node_name} {f.title}: {f.evidence}")
    else:
        lines.append("- none")
    text = "\n".join(lines)
    # If the compact form is still small relative to the raw JSON, the raw JSON adds
    # nothing; only append raw when it fits the budget.
    if len(raw) <= MAX_RAW_JSON_CHARS:
        text += "\n\nRAW JSON:\n" + raw
    return text


class LLMReviewer:
    def __init__(self, max_calls: int = 20, model: str | None = None,
                 cache_dir: Path | None = None) -> None:
        api_key = os.environ.get("GEMINI_API_KEY")
        if not api_key:
            raise LLMError("GEMINI_API_KEY not set")
        from google import genai  # imported here so --no-llm never needs the SDK

        self._genai = genai
        self.client = genai.Client(api_key=api_key)
        self.model = model or os.environ.get("LLM_MODEL") or self._pick_model()
        self.max_calls = max_calls
        self.calls_made = 0
        self.prompt_tokens = 0
        self.output_tokens = 0
        self.cache_dir = cache_dir if cache_dir is not None else CACHE_DIR
        self.cache_hits = 0

    def _pick_model(self) -> str:
        """Prefer the most capable generally-available Gemini model the key can use."""
        try:
            available = {m.name.removeprefix("models/") for m in self.client.models.list()}
        except Exception:
            return FALLBACK_MODEL
        for candidate in MODEL_PREFERENCE:
            if candidate in available:
                return candidate
        return FALLBACK_MODEL

    def _cache_path(self, payload: str) -> Path:
        digest = hashlib.sha256(f"{self.model}|{SYSTEM_PROMPT}|{payload}".encode()).hexdigest()
        return self.cache_dir / f"{digest}.json"

    def review(self, wf: Workflow, findings: list[Finding]) -> dict[str, Any] | None:
        payload = summarize_workflow(wf, findings)
        cache_file = self._cache_path(payload)
        if cache_file.exists():
            self.cache_hits += 1
            return json.loads(cache_file.read_text(encoding="utf-8"))

        if self.calls_made >= self.max_calls:
            raise LLMError(f"--max-llm-calls limit reached ({self.max_calls})")

        review = self._call(payload)
        result = review.model_dump()
        self.cache_dir.mkdir(exist_ok=True)
        cache_file.write_text(json.dumps(result, ensure_ascii=False), encoding="utf-8")
        return result

    def _call(self, payload: str) -> WorkflowReview:
        from google.genai import errors, types

        config = types.GenerateContentConfig(
            system_instruction=SYSTEM_PROMPT,
            response_mime_type="application/json",
            response_schema=WorkflowReview,
            temperature=0,
        )
        delay = 2.0
        last_error: Exception | None = None
        for _attempt in range(MAX_RETRIES):
            try:
                self.calls_made += 1
                resp = self.client.models.generate_content(
                    model=self.model, contents=payload, config=config
                )
            except errors.APIError as e:
                last_error = e
                if getattr(e, "code", None) == 429 or isinstance(e, errors.ServerError):
                    time.sleep(delay)
                    delay *= 2
                    continue
                raise LLMError(f"Gemini API error {getattr(e, 'code', '?')}: {e}") from e

            usage = resp.usage_metadata
            if usage:
                self.prompt_tokens += usage.prompt_token_count or 0
                self.output_tokens += (usage.candidates_token_count or 0) + (
                    usage.thoughts_token_count or 0
                )

            if resp.prompt_feedback and resp.prompt_feedback.block_reason:
                raise LLMError(f"prompt blocked: {resp.prompt_feedback.block_reason}")
            candidate = resp.candidates[0] if resp.candidates else None
            finish = getattr(candidate, "finish_reason", None)
            if finish and str(finish).split(".")[-1] not in ("STOP", "MAX_TOKENS"):
                raise LLMError(f"generation stopped: {finish}")
            parsed = resp.parsed
            if parsed is None:
                raise LLMError("empty or unparseable structured response")
            return parsed  # type: ignore[return-value]
        raise LLMError(f"rate-limited after {MAX_RETRIES} retries: {last_error}")

    def additional_findings_as_findings(self, wf: Workflow, review: dict[str, Any]) -> list[Finding]:
        out: list[Finding] = []
        for i, af in enumerate(review.get("additional_findings", [])):
            node = wf.node(af.get("node_name") or "")
            out.append(Finding(
                rule_id=f"LLM-{i + 1:03d}",
                severity=af.get("severity", "info"),
                category="llm",
                title=af.get("title", ""),
                description=af.get("description", ""),
                workflow_id=wf.id,
                workflow_name=wf.name,
                node_name=af.get("node_name"),
                node_type=node.type if node else None,
                fix=af.get("fix"),
                confidence=af.get("confidence", "low"),
                source="llm",
            ))
        return out

    def estimated_cost(self) -> float:
        for prefix, (in_price, out_price) in PRICING.items():
            if self.model.startswith(prefix):
                return (self.prompt_tokens * in_price + self.output_tokens * out_price) / 1e6
        return 0.0

    def print_usage(self, console) -> None:
        console.print(
            f"[dim]LLM: model={self.model}, calls={self.calls_made}, "
            f"cache hits={self.cache_hits}, tokens in/out={self.prompt_tokens}/"
            f"{self.output_tokens}, est. paid-tier cost=${self.estimated_cost():.4f} "
            f"(free tier: $0)[/dim]"
        )
