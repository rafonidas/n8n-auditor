"""Readable Markdown report, one document per workflow."""
from __future__ import annotations

from typing import Any

from ..model import Finding, Workflow, severity_rank

_SEV_ICON = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵", "info": "⚪"}


def _md_escape(text: str) -> str:
    return (text or "").replace("|", "\\|").replace("\n", " ")


def render_workflow(
    wf: Workflow,
    findings: list[Finding],
    llm: dict[str, Any] | None = None,
) -> str:
    lines: list[str] = []
    lines.append(f"# Audit report — {wf.name}")
    lines.append("")
    lines.append(f"**id:** `{wf.id or '—'}` · **active:** {'yes' if wf.active else 'no'} · "
                 f"**nodes:** {len(wf.nodes)}"
                 + (f" · **source:** `{wf.source_path}`" if wf.source_path else ""))
    lines.append("")

    if llm:
        if llm.get("summary"):
            lines.append("## Summary")
            lines.append(llm["summary"])
            lines.append("")
        arch = llm.get("architecture") or {}
        if arch:
            verdict = "✅ right pattern" if arch.get("is_right_pattern") else "⚠️ questionable pattern"
            lines.append("## Architecture")
            lines.append(f"**Pattern:** {arch.get('pattern', '?')} — {verdict}")
            if arch.get("justification"):
                lines.append("")
                lines.append(arch["justification"])
            lines.append("")
        what_if = llm.get("what_if") or []
        if what_if:
            lines.append("## What if…")
            lines.append("")
            lines.append("| Scenario | Current behavior | Should be |")
            lines.append("|---|---|---|")
            for w in what_if:
                lines.append(f"| {_md_escape(w.get('scenario', ''))} "
                             f"| {_md_escape(w.get('current_behavior', ''))} "
                             f"| {_md_escape(w.get('should_be', ''))} |")
            lines.append("")

    lines.append("## Findings")
    lines.append("")
    if not findings:
        lines.append("No findings. 🎉")
        lines.append("")
    else:
        triage = {t["id"]: t for t in (llm or {}).get("finding_triage", []) if isinstance(t, dict)}
        lines.append("| Sev | Rule | Node | Detail | Fix |")
        lines.append("|---|---|---|---|---|")
        for f in sorted(findings, key=lambda x: -severity_rank(x.severity)):
            icon = _SEV_ICON.get(f.severity, "")
            detail = f.evidence or f.description
            verdict = triage.get(f.rule_id, {}).get("verdict")
            tag = f" _(LLM: {verdict})_" if verdict else ""
            src = " `[llm]`" if f.source == "llm" else ""
            lines.append(f"| {icon} {f.severity} | {f.rule_id}{src} | {_md_escape(f.node_name or '—')} "
                         f"| {_md_escape(f.title)}: {_md_escape(detail)}{tag} | {_md_escape(f.fix or '')} |")
        lines.append("")

    if llm and llm.get("priorities"):
        lines.append("## Priorities (impact × effort)")
        lines.append("")
        for i, p in enumerate(llm["priorities"], 1):
            if isinstance(p, dict):
                kind = p.get("kind", "")
                lines.append(f"{i}. **[{kind}]** {p.get('item', p.get('title', ''))} — "
                             f"{p.get('reason', '')}")
            else:
                lines.append(f"{i}. {p}")
        lines.append("")

    return "\n".join(lines)
