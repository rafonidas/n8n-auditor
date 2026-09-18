"""Report formats, baseline and exit-code helpers."""
import json

from n8n_auditor import baseline as baseline_mod
from n8n_auditor.engine import worst_severity_at_least
from n8n_auditor.model import Finding, Workflow
from n8n_auditor.report import json_report, md, sarif


def _finding(**overrides) -> Finding:
    base = dict(
        rule_id="SEC-001", severity="critical", category="security",
        title="Hardcoded secret", description="desc",
        workflow_id="wf1", workflow_name="Test WF",
        node_name="HTTP", node_type="n8n-nodes-base.httpRequest",
        path="/parameters/url", evidence="sk-tes…", fix="use credentials",
    )
    base.update(overrides)
    return Finding(**base)


def test_json_report_schema():
    doc = json.loads(json_report.render([_finding()], skipped_rules=["GOV-001"]))
    assert doc["schema_version"]
    assert doc["findings"][0]["rule_id"] == "SEC-001"
    assert doc["findings"][0]["fingerprint"] == "SEC-001|wf1|HTTP|/parameters/url"
    assert doc["skipped_rules"] == ["GOV-001"]


def test_sarif_is_valid_shape():
    doc = json.loads(sarif.render([_finding()]))
    assert doc["version"] == "2.1.0"
    run = doc["runs"][0]
    assert run["tool"]["driver"]["rules"][0]["id"] == "SEC-001"
    assert run["results"][0]["level"] == "error"
    assert run["results"][0]["partialFingerprints"]["n8nAuditor/v1"]


def test_md_report_contains_sections():
    wf = Workflow.from_json({"name": "Test WF", "id": "wf1", "nodes": [], "connections": {}})
    text = md.render_workflow(wf, [_finding()], llm={
        "summary": "Syncs invoices.",
        "architecture": {"pattern": "polling", "is_right_pattern": False, "justification": "j"},
        "what_if": [{"scenario": "API 500", "current_behavior": "dies", "should_be": "retry"}],
        "priorities": [{"kind": "bug", "item": "fix secret", "reason": "critical"}],
    })
    for fragment in ("# Audit report — Test WF", "## Summary", "## Architecture",
                     "## What if…", "## Findings", "SEC-001", "## Priorities"):
        assert fragment in text


def test_baseline_roundtrip(tmp_path):
    f1, f2 = _finding(), _finding(node_name="Other")
    path = tmp_path / "baseline.json"
    baseline_mod.write([f1], path)
    fingerprints = baseline_mod.load(path)
    kept, suppressed = baseline_mod.apply([f1, f2], fingerprints)
    assert suppressed == 1 and kept == [f2]


def test_fail_on_threshold():
    findings = [_finding(severity="medium")]
    assert worst_severity_at_least(findings, "medium")
    assert not worst_severity_at_least(findings, "high")
    assert not worst_severity_at_least([], "info")
