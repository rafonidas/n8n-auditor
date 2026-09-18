"""Unit tests for the secret detectors."""
from n8n_auditor.secrets import detect_secrets, is_placeholder, redact

FAKE_JWT = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJmYWtlIjp0cnVlfQ.c2lnbmF0dXJlLWZha2UtMTIzNDU2Nzg5MA"


def test_detects_jwt():
    assert any(kind == "jwt" for kind, _ in detect_secrets(f"token: {FAKE_JWT}"))


def test_detects_provider_keys():
    assert detect_secrets("sk-test-FAKEFAKEFAKEFAKEFAKEFAKE1234")
    assert detect_secrets("AIzaFAKEFAKEFAKEFAKEFAKEFAKEFAKE123456")
    assert detect_secrets("ghp_FAKEFAKEFAKEFAKEFAKEFAKEFAKE123456")
    # Assembled at runtime (not a contiguous literal in this file) so
    # secret-scanners on the git history do not mistake a fake fixture for
    # a real Slack token, while still exercising the same regex at runtime.
    fake_slack_token = "xox" + "b-" + "0" * 12 + "-" + "FAKE" * 4
    assert detect_secrets(fake_slack_token)


def test_detects_connection_strings():
    assert detect_secrets("postgres://svc_user:hunter22secret@db.internal.example:5432/app")
    assert detect_secrets("Server=db01;Database=app;User Id=sa;Password=hunter22secret")


def test_detects_basic_auth_that_decodes():
    import base64
    b64 = base64.b64encode(b"demo_user:hunter22secret").decode()
    assert any(kind == "basic_auth" for kind, _ in detect_secrets(f"Basic {b64}"))


def test_ignores_expressions_and_placeholders():
    assert detect_secrets("={{ $env.API_KEY }}") == []
    assert detect_secrets("={{ $credentials.token }}") == []
    assert detect_secrets("Bearer {{ $json.token }}") == []
    assert detect_secrets("Bearer YOUR_TOKEN_HERE") == []
    assert detect_secrets("sk-xxxxxxxxxxxxxxxxxxxxxxxx") == []
    assert is_placeholder("<your-key>")
    assert is_placeholder("${TOKEN}")


def test_redaction_never_leaks_full_secret():
    assert redact("sk-test-FAKEFAKEFAKE") == "sk-tes…"
