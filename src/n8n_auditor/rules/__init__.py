"""Rule registry. Rules self-register via the @rule decorator on import."""
from __future__ import annotations

import importlib
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from ..model import Finding, Workflow


@dataclass
class ScanContext:
    """Options and cross-workflow state shared by all rules during a scan."""

    workflows: list[Workflow] = field(default_factory=list)
    full_set: bool = False  # True when we believe we have the whole instance (dir/remote scan)
    allowed_domains: list[str] = field(default_factory=list)
    personal_cred_pattern: str = r"(?i)(^[A-Z][a-z]+-|personal)"
    expected_timezone: str | None = None
    skipped_rules: set[str] = field(default_factory=set)


@dataclass
class Rule:
    id: str
    severity: str
    category: str
    title: str
    description: str
    func: Callable[..., list[Finding]]
    cross_workflow: bool = False


REGISTRY: dict[str, Rule] = {}


def rule(
    id: str,
    severity: str,
    category: str,
    title: str,
    description: str,
    cross_workflow: bool = False,
) -> Callable:
    def decorator(func: Callable[..., list[Finding]]) -> Callable:
        REGISTRY[id] = Rule(id, severity, category, title, description, func, cross_workflow)
        return func

    return decorator


def make_finding(r: Rule, workflow: Workflow, **overrides: Any) -> Finding:
    """Build a Finding pre-filled from the rule's metadata."""
    kwargs: dict[str, Any] = dict(
        rule_id=r.id,
        severity=r.severity,
        category=r.category,
        title=r.title,
        description=r.description,
        workflow_id=workflow.id,
        workflow_name=workflow.name,
    )
    kwargs.update(overrides)
    return Finding(**kwargs)


def load_all_rules() -> None:
    for module in ("sec", "rel", "gov"):
        try:
            importlib.import_module(f".{module}", package=__name__)
        except ImportError:
            pass


def run_rules(workflows: list[Workflow], ctx: ScanContext) -> list[Finding]:
    load_all_rules()
    ctx.workflows = workflows
    findings: list[Finding] = []
    for r in REGISTRY.values():
        if r.cross_workflow:
            if not ctx.full_set:
                ctx.skipped_rules.add(r.id)
                continue
            findings.extend(r.func(workflows, ctx))
        else:
            for wf in workflows:
                findings.extend(r.func(wf, ctx))
    return findings
