"""SEC — security rules."""
from __future__ import annotations

import re

from ..jsonwalk import walk_strings
from ..model import Finding, Workflow
from ..secrets import (
    detect_secrets,
    is_expression_reference,
    is_placeholder,
    is_sensitive_field_name,
    looks_like_literal_secret_value,
    redact,
)
from . import ScanContext, REGISTRY, make_finding, rule

STICKY_TYPE = "n8n-nodes-base.stickyNote"

WEBHOOK_TRIGGER_TYPES = {"webhook", "formTrigger", "chatTrigger"}

# Nodes whose execution has side effects (writes, sends, calls out).
EFFECT_NODE_TYPES = {
    "httpRequest", "postgres", "mySql", "microsoftSql", "mongoDb", "redis", "supabase",
    "emailSend", "gmail", "microsoftOutlook", "slack", "telegram", "whatsApp", "discord",
    "googleSheets", "airtable", "notion", "ftp", "ssh", "executeWorkflow", "dataTable",
}

DB_NODE_TYPES = {"postgres", "mySql", "microsoftSql", "mongoDb", "supabase", "questDb", "crateDb"}

PRIVATE_IP = re.compile(r"\b(?:10\.\d{1,3}|192\.168|172\.(?:1[6-9]|2\d|3[01]))\.\d{1,3}\.\d{1,3}\b")
TUNNEL_URL = re.compile(r"(?i)\b[\w.-]*\.(?:ngrok(?:-free)?\.(?:app|io|dev)|loca\.lt|trycloudflare\.com)\b")
URLISH_KEY = re.compile(r"(?i)^(url|host|hostname|endpoint|baseurl|server|uri)$")

DANGEROUS_JS = [
    ("eval(", "eval() executes arbitrary strings as code"),
    ("new Function(", "new Function() executes arbitrary strings as code"),
    ("require('child_process')", "child_process allows arbitrary command execution"),
    ('require("child_process")', "child_process allows arbitrary command execution"),
    ("require('fs')", "filesystem access from a Code node"),
    ('require("fs")', "filesystem access from a Code node"),
    ("process.env", "reads the host environment (potential env/secret leak)"),
]
DANGEROUS_PY = [
    ("os.system", "os.system allows arbitrary command execution"),
    ("subprocess.", "subprocess allows arbitrary command execution"),
    ("eval(", "eval() executes arbitrary strings as code"),
    ("exec(", "exec() executes arbitrary strings as code"),
]

PRIVILEGED_CRED_NAME = re.compile(r"(?i)(service[_-]?role|admin|root|master|superuser|sa\b)")

SQL_INTERPOLATION = re.compile(r"\{\{[^}]*\$(?:json|node|input|item)\b[^}]*\}\}")


def _iter_string_params(node) -> list[tuple[str, str, str]]:
    return list(walk_strings(node.parameters, ""))


@rule(
    id="SEC-001", severity="critical", category="security",
    title="Hardcoded secret in workflow definition",
    description="A literal secret (API key, JWT, token, password or connection string) is stored "
    "in node parameters, code, sticky notes or pinned data instead of an n8n credential.",
)
def sec_001(wf: Workflow, ctx: ScanContext) -> list[Finding]:
    r = REGISTRY["SEC-001"]
    findings: list[Finding] = []

    def scan_value(pointer: str, key: str, value: str, node=None, where: str = "parameters"):
        for kind, secret in detect_secrets(value):
            findings.append(make_finding(
                r, wf,
                node_name=node.name if node else None,
                node_type=node.type if node else None,
                path=pointer,
                evidence=f"{kind}: {redact(secret)}",
                fix="Move the secret to an n8n credential and reference it, or use "
                    "={{ $env.MY_SECRET }} with an environment variable.",
                extra={"where": where, "kind": kind},
            ))
        # Fields literally named password/token/secret/apiKey with a literal value.
        if node and is_sensitive_field_name(key) and looks_like_literal_secret_value(value):
            if not any(f.path == pointer and f.node_name == node.name for f in findings):
                findings.append(make_finding(
                    r, wf,
                    node_name=node.name, node_type=node.type, path=pointer,
                    evidence=f"field '{key}' has literal value {redact(value)}",
                    fix="Store this value in an n8n credential instead of a literal parameter.",
                    extra={"where": where, "kind": "named_field"},
                ))

    for node in wf.nodes:
        where = "sticky_note" if node.type == STICKY_TYPE else "parameters"
        for pointer, key, value in _iter_string_params(node):
            scan_value(f"/parameters{pointer}", key, value, node, where)
        if node.notes:
            scan_value("/notes", "notes", node.notes, node, "notes")

    for pointer, key, value in walk_strings(wf.pin_data, ""):
        scan_value(f"/pinData{pointer}", key, value, None, "pinData")

    return findings


def _has_downstream_validation(wf: Workflow, trigger_name: str) -> bool:
    """An If/Switch/Code node downstream that references headers or a secret comparison."""
    marker = re.compile(r"(?i)(headers?\[|headers?\.|x-[\w-]*(secret|token|key|signature)|"
                        r"authorization|hmac|signature|secret|api[_-]?key|token)")
    for node in wf.successors(trigger_name):
        if node.disabled:
            continue
        if node.base_type in {"if", "switch", "filter", "code", "function", "functionItem"}:
            blob = " ".join(v for _, _, v in _iter_string_params(node))
            if marker.search(blob):
                return True
    return False


def _has_downstream_effect(wf: Workflow, trigger_name: str) -> bool:
    return any(
        n.base_type in EFFECT_NODE_TYPES and not n.disabled for n in wf.successors(trigger_name)
    )


@rule(
    id="SEC-002", severity="high", category="security",
    title="Unauthenticated webhook with side effects",
    description="A webhook/form/chat trigger accepts requests without authentication and "
    "downstream nodes perform actions with side effects (DB writes, HTTP calls, mail).",
)
def sec_002(wf: Workflow, ctx: ScanContext) -> list[Finding]:
    r = REGISTRY["SEC-002"]
    findings: list[Finding] = []
    for node in wf.nodes:
        if node.base_type not in WEBHOOK_TRIGGER_TYPES or node.disabled:
            continue
        auth = node.parameters.get("authentication", "none") or "none"
        if auth != "none":
            continue
        if not _has_downstream_effect(wf, node.name):
            continue
        validated = _has_downstream_validation(wf, node.name)
        findings.append(make_finding(
            r, wf,
            severity="medium" if validated else "high",
            node_name=node.name, node_type=node.type,
            path="/parameters/authentication",
            evidence="authentication: none" + (" (manual validation found downstream)" if validated else ""),
            fix="Enable header/basic auth on the trigger, or at minimum validate a shared "
                "secret header before any node with side effects.",
        ))
    return findings


@rule(
    id="SEC-003", severity="medium", category="security",
    title="Private IP or volatile tunnel URL hardcoded",
    description="A private network IP or an ephemeral tunnel domain (ngrok, localtunnel, "
    "trycloudflare) is hardcoded in a URL/host parameter.",
)
def sec_003(wf: Workflow, ctx: ScanContext) -> list[Finding]:
    r = REGISTRY["SEC-003"]
    findings: list[Finding] = []
    for node in wf.nodes:
        if node.type == STICKY_TYPE:
            continue
        for pointer, key, value in _iter_string_params(node):
            if not URLISH_KEY.match(key):
                continue
            m = PRIVATE_IP.search(value) or TUNNEL_URL.search(value)
            if m:
                findings.append(make_finding(
                    r, wf,
                    node_name=node.name, node_type=node.type,
                    path=f"/parameters{pointer}",
                    evidence=m.group(0),
                    fix="Use a stable DNS name or an environment variable; tunnel URLs rotate "
                        "and private IPs break outside the original network.",
                ))
    return findings


@rule(
    id="SEC-004", severity="high", category="security",
    title="Dangerous pattern in Code node",
    description="A Code node uses eval/new Function/child_process/fs/process.env (JS) or "
    "os.system/subprocess/eval/exec (Python).",
)
def sec_004(wf: Workflow, ctx: ScanContext) -> list[Finding]:
    r = REGISTRY["SEC-004"]
    findings: list[Finding] = []
    for node in wf.nodes:
        js = node.parameters.get("jsCode") or node.parameters.get("functionCode") or ""
        py = node.parameters.get("pythonCode") or ""
        for code, patterns, field_name in ((js, DANGEROUS_JS, "jsCode"), (py, DANGEROUS_PY, "pythonCode")):
            if not isinstance(code, str) or not code:
                continue
            for pattern, why in patterns:
                if pattern in code:
                    # console.log of a whole credentials-ish object is info, not high.
                    sev = r.severity
                    if pattern == "process.env" and re.search(
                        r"console\.log\([^)]*process\.env\s*\)", code
                    ):
                        sev = "info"
                    findings.append(make_finding(
                        r, wf, severity=sev,
                        node_name=node.name, node_type=node.type,
                        path=f"/parameters/{field_name}",
                        evidence=f"{pattern} — {why}",
                        fix="Remove the dangerous call or replace it with n8n-native helpers; "
                            "Code nodes should transform data, not touch the host.",
                    ))
    return findings


_READ_SQL = re.compile(r"(?is)^\s*(--[^\n]*\n|\s)*select\b")


def _workflow_is_read_only(wf: Workflow) -> bool:
    db_nodes = [n for n in wf.nodes if n.base_type in DB_NODE_TYPES and not n.disabled]
    if not db_nodes:
        return False
    for n in db_nodes:
        op = str(n.parameters.get("operation", "")).lower()
        if op in {"select", "get", "getall", "read"}:
            continue
        if op == "executequery":
            q = str(n.parameters.get("query", ""))
            if _READ_SQL.match(q.lstrip("={ ")):
                continue
            return False
        return False
    return True


@rule(
    id="SEC-005", severity="medium", category="security",
    title="Over-privileged credential for a read-only workflow",
    description="A credential named like a maximum-privilege role (service_role, admin, root, "
    "master) is used in a workflow that only performs reads.",
)
def sec_005(wf: Workflow, ctx: ScanContext) -> list[Finding]:
    r = REGISTRY["SEC-005"]
    findings: list[Finding] = []
    if not _workflow_is_read_only(wf):
        return findings
    for node in wf.nodes:
        for cred_type, cred in node.credentials.items():
            name = cred.get("name", "") if isinstance(cred, dict) else str(cred)
            if PRIVILEGED_CRED_NAME.search(name):
                findings.append(make_finding(
                    r, wf,
                    node_name=node.name, node_type=node.type,
                    path=f"/credentials/{cred_type}",
                    evidence=f"credential name: {name}",
                    fix="Create a read-only credential (least privilege) for this workflow.",
                ))
    return findings


@rule(
    id="SEC-006", severity="medium", category="security",
    title="Personal credential in active workflow",
    description="An active workflow uses a credential whose name looks personal (bus factor: "
    "the workflow dies when that person leaves or rotates their account).",
)
def sec_006(wf: Workflow, ctx: ScanContext) -> list[Finding]:
    r = REGISTRY["SEC-006"]
    findings: list[Finding] = []
    if not wf.active:
        return findings
    pattern = re.compile(ctx.personal_cred_pattern)
    for node in wf.nodes:
        for cred_type, cred in node.credentials.items():
            name = cred.get("name", "") if isinstance(cred, dict) else str(cred)
            if name and pattern.search(name):
                findings.append(make_finding(
                    r, wf,
                    node_name=node.name, node_type=node.type,
                    path=f"/credentials/{cred_type}",
                    evidence=f"credential name: {name}",
                    fix="Replace with a service account credential owned by the team.",
                ))
    return findings


@rule(
    id="SEC-007", severity="medium", category="security",
    title="TLS certificate validation disabled",
    description="An HTTP Request node has allowUnauthorizedCerts enabled, accepting any "
    "certificate (man-in-the-middle risk).",
)
def sec_007(wf: Workflow, ctx: ScanContext) -> list[Finding]:
    r = REGISTRY["SEC-007"]
    findings: list[Finding] = []
    for node in wf.nodes:
        opts = node.parameters.get("options") or {}
        if node.parameters.get("allowUnauthorizedCerts") is True or (
            isinstance(opts, dict) and opts.get("allowUnauthorizedCerts") is True
        ):
            findings.append(make_finding(
                r, wf,
                node_name=node.name, node_type=node.type,
                path="/parameters/allowUnauthorizedCerts",
                evidence="allowUnauthorizedCerts: true",
                fix="Fix the certificate on the target host or pin the internal CA; do not "
                    "disable TLS validation.",
            ))
    return findings


DOMAIN_RE = re.compile(r"https?://([\w.-]+)")


@rule(
    id="SEC-008", severity="low", category="security",
    title="HTTP request to domain outside allowlist",
    description="An HTTP Request targets a domain that is not in the configured allowlist. "
    "Without an allowlist, external domains are listed as info.",
)
def sec_008(wf: Workflow, ctx: ScanContext) -> list[Finding]:
    r = REGISTRY["SEC-008"]
    findings: list[Finding] = []
    seen: set[tuple[str, str]] = set()
    for node in wf.nodes:
        if node.base_type != "httpRequest" or node.disabled:
            continue
        url = str(node.parameters.get("url", ""))
        m = DOMAIN_RE.search(url)
        if not m:
            continue
        domain = m.group(1).lower()
        if (node.name, domain) in seen:
            continue
        seen.add((node.name, domain))
        if ctx.allowed_domains:
            allowed = any(domain == d or domain.endswith("." + d) for d in ctx.allowed_domains)
            if not allowed:
                findings.append(make_finding(
                    r, wf,
                    node_name=node.name, node_type=node.type,
                    path="/parameters/url", evidence=domain,
                    fix="Add the domain to --allowed-domains if legitimate, or remove the call.",
                ))
        else:
            findings.append(make_finding(
                r, wf, severity="info",
                node_name=node.name, node_type=node.type,
                path="/parameters/url", evidence=f"external domain: {domain}",
                fix="Review that this external destination is expected; configure "
                    "--allowed-domains to enforce an allowlist.",
                confidence="high",
            ))
    return findings


@rule(
    id="SEC-009", severity="high", category="security",
    title="SQL built by string interpolation (SQL injection)",
    description="A database query interpolates $json/$node values directly into the SQL string "
    "via expressions instead of using query parameters (queryReplacement).",
)
def sec_009(wf: Workflow, ctx: ScanContext) -> list[Finding]:
    r = REGISTRY["SEC-009"]
    findings: list[Finding] = []
    for node in wf.nodes:
        if node.base_type not in DB_NODE_TYPES or node.disabled:
            continue
        query = node.parameters.get("query", "")
        if not isinstance(query, str) or not SQL_INTERPOLATION.search(query):
            continue
        opts = node.parameters.get("options") or {}
        has_params = bool(
            node.parameters.get("queryReplacement")
            or (isinstance(opts, dict) and opts.get("queryReplacement"))
        )
        if has_params:
            continue
        m = SQL_INTERPOLATION.search(query)
        findings.append(make_finding(
            r, wf,
            node_name=node.name, node_type=node.type,
            path="/parameters/query",
            evidence=m.group(0)[:80],
            fix="Use query parameters ($1, $2 with queryReplacement) instead of interpolating "
                "values into the SQL string.",
        ))
    return findings
