"""Startup policy is explicit, validated, and independent of cloud credentials."""

import hashlib
import os

import pytest
from pydantic import ValidationError

from sec_auditor.auth import validate_remote_auth
from sec_auditor.config import Settings


@pytest.fixture(autouse=True)
def clean_settings_environment(monkeypatch):
    for key in os.environ:
        if key.startswith("SEC_AUDITOR_"):
            monkeypatch.delenv(key)


def test_no_scope_is_never_inferred_from_adc_or_a_default_project():
    with pytest.raises(ValidationError, match="at least one"):
        Settings()


@pytest.mark.parametrize(
    "organization", ["organizations/123", "not-numeric", "123/../../456", "123\n", "", "*"]
)
def test_bad_organization_identifiers_are_rejected(organization):
    with pytest.raises(ValidationError):
        Settings(allowed_organizations=[organization])


@pytest.mark.parametrize(
    "project",
    [
        "projects/prod-a",
        "https://evil.example",
        "prod-a/../other",
        "Prod-a",
        "short",
        "a" * 31,
        "*",
    ],
)
def test_bad_project_identifiers_are_rejected(project):
    with pytest.raises(ValidationError):
        Settings(allowed_projects=[project])


def test_valid_explicit_scopes_are_normalized_without_expanding_access():
    settings = Settings(
        allowed_projects=["prod-b", "prod-a", "prod-a", "123456"],
        allowed_organizations=["123", "123"],
    )
    assert settings.allowed_projects == ["123456", "prod-a", "prod-b"]
    assert settings.allowed_organizations == ["123"]
    assert Settings(allowed_projects=["a" * 30]).allowed_projects == ["a" * 30]


def test_json_environment_configuration_and_secret_representations(monkeypatch):
    digest = hashlib.sha256(b"fixture-token").hexdigest()
    monkeypatch.setenv("SEC_AUDITOR_ALLOWED_ORGANIZATIONS", '["123"]')
    monkeypatch.setenv("SEC_AUDITOR_AUTH_MODE", "static")
    monkeypatch.setenv("SEC_AUDITOR_STATIC_TOKENS", '{"agent-a":"' + digest + '"}')
    settings = Settings()
    assert settings.allowed_organizations == ["123"]
    assert settings.static_tokens["agent-a"].get_secret_value() == digest
    assert digest not in repr(settings)
    assert digest not in settings.model_dump_json()
    validate_remote_auth(settings)


def test_environment_files_are_not_implicitly_loaded(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".env").write_text('SEC_AUDITOR_ALLOWED_PROJECTS=["prod-a"]\n')
    with pytest.raises(ValidationError, match="at least one"):
        Settings()


@pytest.mark.parametrize(
    "field,value",
    [
        ("max_concurrency", 0),
        ("max_concurrency", 129),
        ("per_api_concurrency", 0),
        ("requests_per_second", 0),
        ("request_timeout", 121),
        ("max_batch_size", 101),
        ("max_page_size", 1001),
        ("max_scan_seconds", 0),
        ("max_scan_resources", 100001),
        ("max_response_bytes", 1),
        ("max_log_hours", 169),
        ("request_retries", 6),
    ],
)
def test_unbounded_or_invalid_execution_limits_are_rejected(field, value):
    with pytest.raises(ValidationError):
        Settings(allowed_projects=["prod-a"], **{field: value})


def test_remote_http_requires_configured_authentication():
    settings = Settings(allowed_projects=["prod-a"])
    with pytest.raises(ValueError):
        validate_remote_auth(settings)
    with pytest.raises(ValueError):
        validate_remote_auth(Settings(allowed_projects=["prod-a"], auth_mode="static"))


@pytest.mark.parametrize(
    "tokens", [{"agent": "plaintext-token"}, {"": "a" * 64}, {"agent": "g" * 64}]
)
def test_invalid_static_digest_configuration_is_rejected(tokens):
    with pytest.raises(ValidationError):
        Settings(allowed_projects=["prod-a"], auth_mode="static", static_tokens=tokens)


def test_duplicate_static_digests_cannot_ambiguously_name_two_callers():
    digest = hashlib.sha256(b"same-token").hexdigest()
    with pytest.raises(ValidationError):
        Settings(
            allowed_projects=["prod-a"],
            auth_mode="static",
            static_tokens={"agent-a": digest, "agent-b": digest.upper()},
        )


@pytest.mark.parametrize("algorithm", ["none", "HS256", "HS512", "RS256,HS256"])
def test_only_explicit_asymmetric_jwt_algorithms_are_accepted(algorithm):
    with pytest.raises(ValidationError):
        Settings(allowed_projects=["prod-a"], jwt_algorithms=[algorithm])
