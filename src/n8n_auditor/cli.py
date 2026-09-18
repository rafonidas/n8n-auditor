"""n8n-auditor CLI."""
from __future__ import annotations

import sys
from pathlib import Path
from typing import Optional

import typer
from dotenv import load_dotenv
from rich.console import Console

from . import __version__
from . import baseline as baseline_mod
from .engine import scan as run_scan
from .engine import worst_severity_at_least
from .loader import LoadError, load_paths, load_remote
from .model import SEVERITIES
from .rules import ScanContext

app = typer.Typer(add_completion=False, help="Static + AI auditor for n8n workflows.")
console = Console(stderr=True)

EXIT_OK, EXIT_FINDINGS, EXIT_ERROR = 0, 1, 2


@app.callback()
def _main() -> None:
    load_dotenv()


@app.command()
def scan(
    paths: list[str] = typer.Argument(None, help="Workflow .json files, directories or globs."),
    directory: Optional[str] = typer.Option(None, "--dir", help="Scan every .json under a directory."),
    remote: bool = typer.Option(False, "--remote", help="Fetch all workflows from N8N_API_URL."),
    fmt: str = typer.Option("md", "--format", help="Output format: json | sarif | md."),
    output: Optional[Path] = typer.Option(None, "--output", "-o", help="Output file (json/sarif) or directory (md)."),
    fail_on: str = typer.Option("high", "--fail-on", help="Exit 1 when findings ≥ this severity."),
    baseline: Optional[Path] = typer.Option(None, "--baseline", help="Suppress fingerprints listed in this file."),
    write_baseline: Optional[Path] = typer.Option(None, "--write-baseline", help="Write current findings as a baseline and exit 0."),
    no_llm: bool = typer.Option(False, "--no-llm", help="Skip the AI layer (static rules only)."),
    max_llm_calls: int = typer.Option(20, "--max-llm-calls", help="Hard cap on Gemini calls per run."),
    allowed_domains: Optional[str] = typer.Option(None, "--allowed-domains", help="Comma-separated domain allowlist for SEC-008."),
    personal_cred_pattern: Optional[str] = typer.Option(None, "--personal-cred-pattern", help="Regex marking personal credential names (SEC-006)."),
    expected_timezone: Optional[str] = typer.Option(None, "--expected-timezone", help="Expected settings.timezone (REL-007)."),
) -> None:
    """Audit one or more n8n workflows."""
    if fmt not in ("json", "sarif", "md"):
        console.print(f"[red]Unknown format: {fmt}[/red]")
        raise typer.Exit(EXIT_ERROR)
    if fail_on not in SEVERITIES:
        console.print(f"[red]--fail-on must be one of {SEVERITIES}[/red]")
        raise typer.Exit(EXIT_ERROR)

    try:
        if remote:
            workflows = load_remote()
            errors: list[str] = []
        else:
            if not paths and not directory:
                console.print("[red]Nothing to scan: pass files, --dir or --remote.[/red]")
                raise typer.Exit(EXIT_ERROR)
            workflows, errors = load_paths(paths or [], directory)
    except LoadError as e:
        console.print(f"[red]{e}[/red]")
        raise typer.Exit(EXIT_ERROR)
    except Exception as e:  # network errors on --remote, etc.
        console.print(f"[red]Load failed: {e}[/red]")
        raise typer.Exit(EXIT_ERROR)

    for err in errors:
        console.print(f"[yellow]skipped: {err}[/yellow]")
    if not workflows:
        console.print("[red]No workflows loaded.[/red]")
        raise typer.Exit(EXIT_ERROR)

    ctx = ScanContext(full_set=remote or bool(directory) or len(workflows) > 1)
    if allowed_domains:
        ctx.allowed_domains = [d.strip().lower() for d in allowed_domains.split(",") if d.strip()]
    if personal_cred_pattern:
        ctx.personal_cred_pattern = personal_cred_pattern
    if expected_timezone:
        ctx.expected_timezone = expected_timezone

    findings, ctx = run_scan(workflows, ctx)

    if baseline:
        try:
            fingerprints = baseline_mod.load(baseline)
        except Exception as e:
            console.print(f"[red]Cannot read baseline: {e}[/red]")
            raise typer.Exit(EXIT_ERROR)
        findings, suppressed = baseline_mod.apply(findings, fingerprints)
        if suppressed:
            console.print(f"[dim]{suppressed} finding(s) suppressed by baseline[/dim]")

    if write_baseline:
        baseline_mod.write(findings, write_baseline)
        console.print(f"Baseline with {len(findings)} fingerprint(s) written to {write_baseline}")
        raise typer.Exit(EXIT_OK)

    llm_results: dict = {}
    if not no_llm:
        from .llm import LLMError, LLMReviewer

        try:
            reviewer = LLMReviewer(max_calls=max_llm_calls)
        except LLMError as e:
            console.print(f"[yellow]AI layer disabled: {e} (running static only)[/yellow]")
            reviewer = None
        if reviewer:
            for wf in workflows:
                wf_findings = [f for f in findings if f.workflow_name == wf.name and f.workflow_id == wf.id]
                try:
                    review = reviewer.review(wf, wf_findings)
                except LLMError as e:
                    console.print(f"[yellow]LLM review failed for '{wf.name}': {e}[/yellow]")
                    continue
                if review:
                    llm_results[wf.id or wf.name] = review
                    findings.extend(reviewer.additional_findings_as_findings(wf, review))
            reviewer.print_usage(console)

    if ctx.skipped_rules:
        console.print(
            f"[dim]cross-workflow rules skipped (single workflow): {', '.join(sorted(ctx.skipped_rules))}[/dim]"
        )

    _emit(fmt, output, workflows, findings, llm_results, ctx)

    counts: dict[str, int] = {}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    summary = ", ".join(f"{counts[s]} {s}" for s in reversed(SEVERITIES) if s in counts) or "none"
    console.print(f"[bold]{len(workflows)} workflow(s), findings: {summary}[/bold]")

    if worst_severity_at_least(findings, fail_on):
        raise typer.Exit(EXIT_FINDINGS)
    raise typer.Exit(EXIT_OK)


def _emit(fmt, output, workflows, findings, llm_results, ctx) -> None:
    from .report import json_report, md, sarif

    if fmt == "json":
        text = json_report.render(findings, llm_results or None, sorted(ctx.skipped_rules))
        _write_or_print(text, output)
    elif fmt == "sarif":
        text = sarif.render(findings, tool_version=__version__)
        _write_or_print(text, output)
    else:
        out_dir = Path(output) if output else Path("reports")
        out_dir.mkdir(parents=True, exist_ok=True)
        for wf in workflows:
            wf_findings = [f for f in findings if f.workflow_name == wf.name and f.workflow_id == wf.id]
            doc = md.render_workflow(wf, wf_findings, llm_results.get(wf.id or wf.name))
            safe = "".join(c if c.isalnum() or c in "-_ " else "_" for c in wf.name).strip() or "workflow"
            path = out_dir / f"{safe}.md"
            path.write_text(doc, encoding="utf-8")
            console.print(f"report: {path}")


def _write_or_print(text: str, output: Optional[Path]) -> None:
    if output:
        Path(output).write_text(text, encoding="utf-8")
        console.print(f"report: {output}")
    else:
        sys.stdout.write(text + "\n")


@app.command()
def rules() -> None:
    """List the rule catalog."""
    from rich.table import Table

    from .rules import REGISTRY, load_all_rules

    load_all_rules()
    table = Table(title="n8n-auditor rules")
    for col in ("id", "severity", "category", "title"):
        table.add_column(col)
    for r in sorted(REGISTRY.values(), key=lambda r: r.id):
        table.add_row(r.id, r.severity, r.category, r.title)
    Console().print(table)


if __name__ == "__main__":
    app()
