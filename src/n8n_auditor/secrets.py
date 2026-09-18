"""Secret detectors and evidence redaction.

Detectors return (kind, matched_text) pairs. Values that are n8n expressions
referencing env/credentials, or obvious placeholders, are never reported.
"""
from __future__ import annotations

import base64
import binascii
import re

# Provider-specific API key prefixes. Order matters: more specific first.
PROVIDER_KEY_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("anthropic_api_key", re.compile(r"\bsk-ant-[A-Za-z0-9_-]{16,}")),
    ("openai_api_key", re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}")),
    ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z_-]{30,}")),
    ("github_token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}")),
    ("slack_token", re.compile(r"\bxox[bapors]-[A-Za-z0-9-]{10,}")),
    ("stripe_key", re.compile(r"\b[sr]k_(?:live|test)_[A-Za-z0-9]{16,}")),
    ("aws_access_key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("sendgrid_key", re.compile(r"\bSG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}")),
    ("telegram_bot_token", re.compile(r"\b\d{8,10}:AA[A-Za-z0-9_-]{30,}")),
]

JWT_PATTERN = re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")
BEARER_PATTERN = re.compile(r"\bBearer\s+([A-Za-z0-9._~+/=-]{16,})")
BASIC_PATTERN = re.compile(r"\bBasic\s+([A-Za-z0-9+/=]{8,})")
CONNSTRING_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("connection_string", re.compile(r"(?i)Server\s*=\s*[^;]+;(?:[^;=]+=[^;]*;)*\s*Password\s*=\s*[^;\s]+")),
    ("db_url_with_password", re.compile(r"\b(?:postgres(?:ql)?|mysql|mssql|mongodb(?:\+srv)?|redis|amqp)://[^\s:/@]+:[^\s@]+@[^\s/]+")),
]

SENSITIVE_FIELD_NAMES = re.compile(r"(?i)^(password|pass|pwd|token|secret|api[_-]?key|apikey|auth[_-]?token|access[_-]?token|private[_-]?key|client[_-]?secret)$")

PLACEHOLDER_PATTERN = re.compile(
    r"(?i)^\s*(<[^>]*>|\{\{[^}]*\}\}|\$\{[^}]*\}|x{3,}[A-Za-z0-9_-]*|your[-_ ].*|changeme|change-me|placeholder|dummy|example|test|none|null|\*{3,}|\.{3,}|sk-x{4,}.*|todo|fixme)\s*$"
)

EXPRESSION_PATTERN = re.compile(r"=?\{\{.*(\$env|\$credentials|\$vars|\$secrets)\b.*\}\}", re.DOTALL)


def is_expression_reference(value: str) -> bool:
    """True when the value is an n8n expression pulling from env/credentials/vars."""
    return bool(EXPRESSION_PATTERN.search(value))


def is_placeholder(value: str) -> bool:
    v = value.strip().strip("\"'")
    if PLACEHOLDER_PATTERN.match(v):
        return True
    # Repeated single character ("aaaaaaa", "1111") is a placeholder, not a secret.
    if len(set(v)) <= 2 and len(v) >= 4:
        return True
    return False


def redact(secret: str, keep: int = 6) -> str:
    if len(secret) <= keep:
        return secret[:2] + "…"
    return secret[:keep] + "…"


def _decodes_to_userpass(b64: str) -> bool:
    try:
        decoded = base64.b64decode(b64, validate=True).decode("utf-8", errors="strict")
    except (binascii.Error, UnicodeDecodeError, ValueError):
        return False
    return ":" in decoded and 3 <= decoded.index(":") and len(decoded) >= 5


def detect_secrets(value: str) -> list[tuple[str, str]]:
    """Detect hardcoded secrets in a string value. Returns [(kind, matched_text)]."""
    if not value or len(value) < 8:
        return []
    if is_expression_reference(value):
        return []

    found: list[tuple[str, str]] = []
    spans: list[tuple[int, int]] = []

    def _add(kind: str, match: re.Match) -> None:
        start, end = match.span()
        if any(s <= start < e or s < end <= e for s, e in spans):
            return
        text = match.group(0)
        if is_placeholder(text):
            return
        spans.append((start, end))
        found.append((kind, text))

    for m in JWT_PATTERN.finditer(value):
        _add("jwt", m)
    for kind, pattern in PROVIDER_KEY_PATTERNS:
        for m in pattern.finditer(value):
            _add(kind, m)
    for kind, pattern in CONNSTRING_PATTERNS:
        for m in pattern.finditer(value):
            _add(kind, m)
    for m in BEARER_PATTERN.finditer(value):
        token = m.group(1)
        if not is_placeholder(token) and not token.startswith("{{"):
            _add("bearer_token", m)
    for m in BASIC_PATTERN.finditer(value):
        if _decodes_to_userpass(m.group(1)):
            _add("basic_auth", m)
    return found


def is_sensitive_field_name(name: str) -> bool:
    return bool(SENSITIVE_FIELD_NAMES.match(name))


def looks_like_literal_secret_value(value: str) -> bool:
    """For fields *named* password/token/etc: literal, non-expression, non-placeholder value."""
    if not value or len(value) < 6:
        return False
    if value.startswith("={{") or value.startswith("{{"):
        return False
    if is_placeholder(value):
        return False
    return True
