"""Scan orchestration: rules over a set of workflows."""
from __future__ import annotations

from .model import Finding, Workflow, severity_rank
from .rules import ScanContext, run_rules


def scan(workflows: list[Workflow], ctx: ScanContext | None = None) -> tuple[list[Finding], ScanContext]:
    ctx = ctx or ScanContext()
    findings = run_rules(workflows, ctx)
    for f in findings:
        wf = next((w for w in workflows if w.name == f.workflow_name and w.id == f.workflow_id), None)
        if wf and wf.source_path:
            f.extra["source_path"] = wf.source_path
    findings.sort(key=lambda f: (-severity_rank(f.severity), f.rule_id, f.workflow_name, f.node_name or ""))
    return findings, ctx


def worst_severity_at_least(findings: list[Finding], threshold: str) -> bool:
    rank = severity_rank(threshold)
    return any(severity_rank(f.severity) >= rank for f in findings)
