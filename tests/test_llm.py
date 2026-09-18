"""AI-layer tests that run without an API key (cache, summarization, conversion)."""
import json

from n8n_auditor.llm import LLMReviewer, summarize_workflow
from n8n_auditor.loader import load_file
from n8n_auditor.model import Finding

FIXTURE = "tests/fixtures/planted/sec-002-open-webhook.json"


def _reviewer(cache_dir) -> LLMReviewer:
    """Build a reviewer without touching the network or needing a key."""
    r = LLMReviewer.__new__(LLMReviewer)
    r.model = "gemini-2.5-flash"
    r.max_calls = 5
    r.calls_made = 0
    r.prompt_tokens = 0
    r.output_tokens = 0
    r.cache_dir = cache_dir
    r.cache_hits = 0
    return r


def test_summarize_workflow_is_compact_and_complete():
    wf = load_file(FIXTURE)
    text = summarize_workflow(wf, [])
    assert "Incoming lead" in text and "Insert lead" in text
    assert "-[main:0]->" in text
    assert "STATIC FINDINGS" in text


def test_review_uses_disk_cache(tmp_path):
    wf = load_file(FIXTURE)
    r = _reviewer(tmp_path)
    payload = summarize_workflow(wf, [])
    cached = {"summary": "cached review", "additional_findings": []}
    r._cache_path(payload).write_text(json.dumps(cached), encoding="utf-8")
    assert r.review(wf, []) == cached
    assert r.cache_hits == 1 and r.calls_made == 0


def test_additional_findings_conversion(tmp_path):
    wf = load_file(FIXTURE)
    r = _reviewer(tmp_path)
    review = {"additional_findings": [{
        "title": "Silent drop of malformed payloads",
        "description": "No else-branch after validation",
        "severity": "medium", "node_name": "Insert lead",
        "fix": "Add an error path", "confidence": "medium",
    }]}
    findings = r.additional_findings_as_findings(wf, review)
    assert len(findings) == 1
    f = findings[0]
    assert isinstance(f, Finding) and f.source == "llm"
    assert f.rule_id == "LLM-001" and f.node_type == "n8n-nodes-base.postgres"


def test_cost_estimate():
    r = _reviewer(None)
    r.prompt_tokens, r.output_tokens = 1_000_000, 100_000
    assert round(r.estimated_cost(), 2) == round(0.30 + 0.25, 2)
