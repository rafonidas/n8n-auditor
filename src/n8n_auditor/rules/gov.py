"""GOV — governance rules."""
from __future__ import annotations

import re
from collections import defaultdict

from ..crossref import all_credentials
from ..jsonwalk import walk_strings
from ..model import Finding, Workflow
from ..secrets import detect_secrets, redact
from . import REGISTRY, ScanContext, make_finding, rule

EMAIL_RE = re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b")
FAKE_EMAIL_DOMAINS = re.compile(r"(?i)@(example\.(com|org|net)|test\.com|email\.com|acme\.test)$")
PHONE_RE = re.compile(r"\+?\d[\d\s().-]{7,}\d")
IP_RE = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
PII_KEY = re.compile(r"(?i)^(email|e-mail|mail|first_?name|last_?name|full_?name|nombre|apellido|"
                     r"phone|telefono|dni|cuit|cuil|ssn|amount|monto|total|salary|iban|cbu)$")
DEFAULT_NODE_NAME = re.compile(r"^(HTTP Request|Code|Set|If|Switch|Webhook|Function|Merge|"
                               r"Postgres|MySQL|NoOp|Edit Fields)\d*$")
SENSITIVE_DATA_FIELD = re.compile(r"(?i)(email|password|dni|cuit|ssn|salary|iban|cbu|card|"
                                  r"account_?number|phone|address)")
CONFIG_LIKE = re.compile(r"(?i)(host|server|port|user(name)?|database)\s*[:=]\s*\S+")


@rule(
    id="GOV-001", severity="medium", category="governance",
    title="Two credentials share the same name",
    description="Two different credential ids carry the same display name: indistinguishable in "
    "the n8n UI, so rotating one leaves the other alive unnoticed.",
    cross_workflow=True,
)
def gov_001(workflows: list[Workflow], ctx: ScanContext) -> list[Finding]:
    r = REGISTRY["GOV-001"]
    findings: list[Finding] = []
    by_name: dict[str, set[str]] = defaultdict(set)
    refs = all_credentials(workflows)
    for _wf, _node, _ctype, cid, cname in refs:
        if cid and cname:
            by_name[cname].add(cid)
    duplicated = {name: ids for name, ids in by_name.items() if len(ids) > 1}
    reported: set[tuple[str, str]] = set()
    for wf, node, ctype, cid, cname in refs:
        if cname in duplicated and (wf.id or wf.name, cname) not in reported:
            reported.add((wf.id or wf.name, cname))
            findings.append(make_finding(
                r, wf,
                node_name=node.name, node_type=node.type,
                path=f"/credentials/{ctype}",
                evidence=f"name '{cname}' maps to ids {sorted(duplicated[cname])}",
                fix="Rename or delete one of the duplicates so each credential name is unique.",
            ))
    return findings


@rule(
    id="GOV-002", severity="info", category="governance",
    title="Stale credential name cached in exports",
    description="The same credential id appears with different cached names across workflows: "
    "the credential was renamed and older exports lie about which one they use.",
    cross_workflow=True,
)
def gov_002(workflows: list[Workflow], ctx: ScanContext) -> list[Finding]:
    r = REGISTRY["GOV-002"]
    findings: list[Finding] = []
    by_id: dict[str, set[str]] = defaultdict(set)
    refs = all_credentials(workflows)
    for _wf, _node, _ctype, cid, cname in refs:
        if cid and cname:
            by_id[cid].add(cname)
    renamed = {cid: names for cid, names in by_id.items() if len(names) > 1}
    reported: set[tuple[str, str]] = set()
    for wf, node, ctype, cid, cname in refs:
        if cid in renamed and (wf.id or wf.name, cid) not in reported:
            reported.add((wf.id or wf.name, cid))
            findings.append(make_finding(
                r, wf,
                node_name=node.name, node_type=node.type,
                path=f"/credentials/{ctype}",
                evidence=f"id {cid} cached as {sorted(renamed[cid])}",
                fix="Re-export the workflows so cached credential names match reality.",
            ))
    return findings


@rule(
    id="GOV-003", severity="high", category="governance",
    title="Real data pinned in the workflow (pinData)",
    description="pinData contains what looks like real data (emails, names, amounts, ids). It "
    "travels with every export, backup and git commit.",
)
def gov_003(wf: Workflow, ctx: ScanContext) -> list[Finding]:
    r = REGISTRY["GOV-003"]
    findings: list[Finding] = []
    if not wf.pin_data:
        return findings
    hits: list[str] = []
    for pointer, key, value in walk_strings(wf.pin_data):
        for m in EMAIL_RE.finditer(value):
            if not FAKE_EMAIL_DOMAINS.search(m.group(0)):
                hits.append(f"email at /pinData{pointer}: {redact(m.group(0))}")
        if PII_KEY.match(key) and value.strip():
            hits.append(f"field '{key}' at /pinData{pointer}: {redact(value)}")
    if hits:
        findings.append(make_finding(
            r, wf, path="/pinData",
            evidence="; ".join(hits[:5]) + ("…" if len(hits) > 5 else ""),
            fix="Unpin the data before exporting, or replace it with synthetic samples.",
            confidence="medium",
        ))
    return findings


@rule(
    id="GOV-004", severity="low", category="governance",
    title="Sensitive content in sticky notes",
    description="A sticky note contains credentials, IPs or configuration-looking text: notes "
    "are exported with the workflow and read by anyone with access.",
)
def gov_004(wf: Workflow, ctx: ScanContext) -> list[Finding]:
    r = REGISTRY["GOV-004"]
    findings: list[Finding] = []
    for node in wf.nodes:
        if node.base_type != "stickyNote":
            continue
        content = str(node.parameters.get("content", ""))
        if not content:
            continue
        reasons = []
        if detect_secrets(content):
            reasons.append("secret-like token")
        for m in IP_RE.finditer(content):
            octets = m.group(0).split(".")
            if all(o.isdigit() and int(o) <= 255 for o in octets):
                reasons.append(f"IP {m.group(0)}")
                break
        if CONFIG_LIKE.search(content):
            reasons.append("configuration-like text")
        if reasons:
            findings.append(make_finding(
                r, wf,
                node_name=node.name, node_type=node.type,
                path="/parameters/content",
                evidence=", ".join(dict.fromkeys(reasons)),
                fix="Move operational details to proper documentation; keep notes descriptive.",
                confidence="medium",
            ))
    return findings


@rule(
    id="GOV-005", severity="info", category="governance",
    title="Undocumented workflow / default node names",
    description="The workflow has no purpose description (no sticky note) or keeps default "
    "node names (HTTP Request1, Code2): hard to maintain by anyone else.",
)
def gov_005(wf: Workflow, ctx: ScanContext) -> list[Finding]:
    r = REGISTRY["GOV-005"]
    findings: list[Finding] = []
    has_doc = any(
        n.base_type == "stickyNote" and len(str(n.parameters.get("content", ""))) > 20
        for n in wf.nodes
    )
    if not has_doc and len(wf.nodes) > 3:
        findings.append(make_finding(
            r, wf, path="/nodes",
            evidence="no sticky note describing the workflow's purpose",
            fix="Add a sticky note with purpose, owner and expected behavior.",
        ))
    defaults = [n.name for n in wf.nodes if DEFAULT_NODE_NAME.match(n.name)]
    if defaults:
        findings.append(make_finding(
            r, wf, path="/nodes",
            node_name=defaults[0],
            evidence=f"default node names: {', '.join(defaults[:5])}",
            fix="Rename nodes to describe what they do (e.g. 'Fetch open invoices').",
        ))
    return findings


@rule(
    id="GOV-006", severity="medium", category="governance",
    title="Full success-execution retention with sensitive data",
    description="An active workflow saves all successful execution data while handling "
    "sensitive-looking fields: unnecessary retention of personal data.",
)
def gov_006(wf: Workflow, ctx: ScanContext) -> list[Finding]:
    r = REGISTRY["GOV-006"]
    if not wf.active or wf.settings.get("saveDataSuccessExecution") != "all":
        return []
    sensitive_hits = []
    for node in wf.nodes:
        if node.base_type == "stickyNote":
            continue
        for pointer, key, value in walk_strings(node.parameters):
            if SENSITIVE_DATA_FIELD.search(key) or SENSITIVE_DATA_FIELD.search(value[:200]):
                sensitive_hits.append(f"{node.name}: {key}")
                break
    if not sensitive_hits:
        return []
    return [make_finding(
        r, wf, path="/settings/saveDataSuccessExecution",
        evidence=f"saveDataSuccessExecution: all; sensitive fields near: {', '.join(sensitive_hits[:3])}",
        fix="Set success-execution saving to 'none' (or prune) for workflows touching "
            "personal data.",
        confidence="low",
    )]
