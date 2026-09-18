"""Minimal valid SARIF 2.1.0 output for GitHub code scanning."""
from __future__ import annotations

import json

from ..model import Finding

_LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}


def render(findings: list[Finding], tool_version: str = "0.1.0") -> str:
    rules_seen: dict[str, dict] = {}
    results = []
    for f in findings:
        rules_seen.setdefault(f.rule_id, {
            "id": f.rule_id,
            "name": f.rule_id.replace("-", ""),
            "shortDescription": {"text": f.title},
            "fullDescription": {"text": f.description},
            "helpUri": "https://github.com/rafanunez/n8n-auditor#rules",
            "properties": {"category": f.category, "severity": f.severity},
        })
        location = f.workflow_name + (f" › {f.node_name}" if f.node_name else "")
        results.append({
            "ruleId": f.rule_id,
            "level": _LEVEL.get(f.severity, "warning"),
            "message": {"text": f"[{location}] {f.title}: {f.evidence or f.description}"},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": (f.extra.get("source_path") or "workflow.json").replace("\\", "/")},
                },
                "logicalLocations": [{
                    "name": f.node_name or f.workflow_name,
                    "fullyQualifiedName": f"{f.workflow_name}{f.path or ''}",
                }],
            }],
            "partialFingerprints": {"n8nAuditor/v1": f.fingerprint},
        })
    doc = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "n8n-auditor",
                "version": tool_version,
                "informationUri": "https://github.com/rafanunez/n8n-auditor",
                "rules": list(rules_seen.values()),
            }},
            "results": results,
        }],
    }
    return json.dumps(doc, indent=2)
