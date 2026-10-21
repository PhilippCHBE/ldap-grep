"""Regression coverage for the pre-publication security findings F1-F5."""

from pathlib import Path
from unittest.mock import Mock

import pytest

from ldapgrep.cli import main
from ldapgrep.client import LdapClient, LdapGrepError
from ldapgrep.config import (
    ConfigError, EXAMPLE_CONFIG, PUBLIC_PROFILES, Settings, candidate_config_files,
    load_settings, parse_bool, parse_server_url,
)


@pytest.fixture(autouse=True)
def isolated_environment(monkeypatch, tmp_path):
    import os

    for key in list(os.environ):
        if key.upper().startswith("LDAPGREP_"):
            monkeypatch.delenv(key)
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: home))


@pytest.mark.parametrize("credentials", [
    {"bind_dn": "cn=private", "bind_password": "synthetic"},
    {"bind_password": "synthetic"},
    {"bind_password_file": "must-not-be-read"},
])
def test_missing_target_never_becomes_public(credentials, monkeypatch):
    # A password file is not read in this case: fail on the missing target first.
    if "bind_password_file" in credentials:
        monkeypatch.setattr(Path, "read_text", Mock(side_effect=AssertionError("password file read")))
    s = load_settings(skip_config=True, overrides=credentials)
    assert not s.server and not s.fallback_profile
    with pytest.raises(LdapGrepError, match="No LDAP server"):
        LdapClient(s).connect()


@pytest.mark.parametrize("profile", list(PUBLIC_PROFILES))
def test_public_profiles_ignore_all_environment_overrides(profile, monkeypatch):
    for key, value in {
        "SERVER": "ldaps://private.example", "BIND_DN": "cn=private",
        "PASSWORD": "synthetic", "BIND_PASSWORD_FILE": "must-not-be-read",
        "AUTH": "ntlm", "TLS_VERIFY": "false", "START_TLS": "false",
        "ALLOW_PLAINTEXT_AUTH": "true",
    }.items():
        monkeypatch.setenv("LDAPGREP_" + key, value)
    s = load_settings(profile=profile, skip_config=True)
    preset = PUBLIC_PROFILES[profile]
    assert s.server == preset["server"]
    assert s.bind_dn == preset.get("bind_dn", "")
    assert s.bind_password == preset.get("bind_password", "")
    assert s.auth == preset["auth"]
    assert s.tls_verify and not s.allow_plaintext_auth and not s.bind_password_file
    assert s.start_tls == preset.get("start_tls", False)


@pytest.mark.parametrize("overrides", [
    {"server": "ldaps://other.example"}, {"bind_dn": "cn=private"},
    {"password": "synthetic"}, {"bind_password_file": "secret"},
    {"auth": "simple"}, {"port": 1389}, {"use_ssl": False},
])
def test_public_profiles_reject_target_and_credential_overrides(overrides):
    with pytest.raises(ConfigError, match="public profiles"):
        load_settings(profile="freeipa", skip_config=True, overrides=overrides)


def test_public_profile_password_prompt_is_rejected(capsys, monkeypatch):
    prompt = Mock(side_effect=AssertionError("password prompt"))
    monkeypatch.setattr("ldapgrep.cli.getpass.getpass", prompt)
    assert main(["--profile", "freeipa", "-W", "info"]) == 2
    assert "personal passwords" in capsys.readouterr().err
    prompt.assert_not_called()


def test_public_profile_modified_in_tui_is_rejected():
    s = load_settings(profile="freeipa", skip_config=True)
    s.bind_password = "synthetic-personal-password"
    with pytest.raises(LdapGrepError, match="cannot be changed"):
        LdapClient(s).connect()


def test_local_config_cannot_shadow_personal_config(tmp_path, monkeypatch):
    local = tmp_path / "project"
    local.mkdir()
    evil = local / "ldap-grep.conf"
    evil.write_text("[LDAP]\nserver=ldaps://attacker.example\n", encoding="utf-8")
    monkeypatch.chdir(local)
    # Point __main__ at the untrusted project too: script/parent discovery must stay disabled.
    import __main__
    monkeypatch.setattr(__main__, "__file__", str(local / "tool.py"))
    trusted = Path.home() / ".config" / "ldapgrep" / "ldap-grep.conf"
    trusted.parent.mkdir(parents=True)
    trusted.write_text("[LDAP]\nserver=ldaps://trusted.example\n", encoding="utf-8")
    monkeypatch.setenv("LDAPGREP_PASSWORD", "synthetic")
    assert load_settings().host == "trusted.example"
    assert all(p.parent not in (local, local.parent) for p in candidate_config_files())
    # Explicit selection remains possible for an intentional project-local setup.
    assert load_settings(str(evil)).host == "attacker.example"
    monkeypatch.setenv("LDAPGREP_CONFIG", str(evil))
    assert load_settings().host == "attacker.example"


@pytest.mark.parametrize("auth", ["simple", "ntlm"])
@pytest.mark.parametrize("extra", [[], ["--insecure"]])
def test_plaintext_auth_is_refused_before_socket_or_password_prompt(auth, extra, monkeypatch, capsys):
    server = Mock(side_effect=AssertionError("server created"))
    prompt = Mock(side_effect=AssertionError("password prompt"))
    monkeypatch.setattr("ldapgrep.client.Server", server)
    monkeypatch.setattr("ldapgrep.cli.getpass.getpass", prompt)
    assert main(["--no-config", "-H", "ldap://audit.example", "--auth", auth,
                 "-D", "DOMAIN\\audit", "-W", *extra, "info"]) == 2
    assert "unencrypted" in capsys.readouterr().err
    server.assert_not_called()
    prompt.assert_not_called()


@pytest.mark.parametrize("mode", ["ldaps", "starttls", "anonymous", "explicit_plaintext"])
def test_permitted_transports_and_bind_order(mode, monkeypatch):
    s = Settings(server="ldap://audit.example", bind_dn="cn=audit", bind_password="synthetic")
    if mode == "ldaps":
        s.server = "ldaps://audit.example"
    elif mode == "starttls":
        s.start_tls = True
    elif mode == "anonymous":
        s.auth = "anonymous"
    else:
        s.allow_plaintext_auth = True
    conn = Mock()
    conn.tls_started = mode == "starttls"
    conn.start_tls.return_value = True
    conn.bind.return_value = True
    constructor = Mock(return_value=conn)
    monkeypatch.setattr("ldapgrep.client.Connection", constructor)
    monkeypatch.setattr("ldapgrep.client.Server", Mock())
    monkeypatch.setattr(LdapClient, "_post_connect", Mock())
    LdapClient(s).connect()
    calls = [call[0] for call in conn.method_calls]
    assert calls == (["open", "start_tls", "bind"] if mode == "starttls" else ["open", "bind"])
    assert constructor.call_args.kwargs["auto_referrals"] is False
    if mode == "anonymous":
        assert constructor.call_args.kwargs["password"] is None


@pytest.mark.parametrize("outcome", ["false", "unprotected", "exception"])
def test_starttls_failure_never_falls_through_to_bind(outcome, monkeypatch):
    from ldap3.core.exceptions import LDAPStartTLSError

    conn = Mock()
    conn.tls_started = False
    conn.start_tls.return_value = outcome == "unprotected"
    if outcome == "exception":
        conn.start_tls.side_effect = LDAPStartTLSError("synthetic failure")
    monkeypatch.setattr("ldapgrep.client.Connection", Mock(return_value=conn))
    monkeypatch.setattr("ldapgrep.client.Server", Mock())
    with pytest.raises(LdapGrepError, match="StartTLS failed"):
        LdapClient(Settings(server="ldap://audit.example", start_tls=True,
                            bind_dn="cn=audit", bind_password="synthetic")).connect()
    conn.bind.assert_not_called()


@pytest.mark.parametrize("value,expected", [
    (True, True), (False, False), ("TRUE", True), (" yes ", True), ("on", True),
    ("1", True), ("y", True), ("false", False), ("no", False), ("off", False), ("0", False), ("n", False),
])
def test_boolean_values(value, expected):
    assert parse_bool(value) is expected


@pytest.mark.parametrize("field", ["tls_verify", "start_tls", "use_ssl", "allow_plaintext_auth"])
@pytest.mark.parametrize("value", ["tru", "flase", "true ; comment", "2"])
def test_invalid_security_booleans_fail_closed(field, value, monkeypatch):
    with pytest.raises(ConfigError, match=field):
        load_settings(skip_config=True, overrides={field: value})
    monkeypatch.setenv("LDAPGREP_" + field.upper(), value)
    with pytest.raises(ConfigError, match=field):
        load_settings(skip_config=True)


@pytest.mark.parametrize("server", [
    "https://audit.example", "ftp://audit.example", "ldaps://audit.example:not-a-port",
    "ldap://audit.example:0", "ldap://audit.example:65536", "ldap://audit.example:",
    "ldap://", "ldap://[broken", "ldap://audit.example/base", "ldap://audit.example?tls=false",
    "ldaps://user:synthetic@audit.example",
])
def test_invalid_urls_fail_before_connection(server, monkeypatch):
    with pytest.raises(ConfigError):
        parse_server_url(server)
    constructor = Mock()
    monkeypatch.setattr("ldapgrep.client.Server", constructor)
    with pytest.raises(LdapGrepError):
        LdapClient(Settings(server=server, auth="anonymous")).connect()
    constructor.assert_not_called()


def test_example_configs_load_without_weakening_tls(tmp_path):
    shipped = Path(__file__).resolve().parents[1] / "ldap-grep.conf.example"
    assert shipped.read_text(encoding="utf-8") == EXAMPLE_CONFIG
    for profile in (None, "test"):
        s = load_settings(str(shipped), profile, use_env=False)
        assert s.tls_verify and s.effective_ssl and not s.allow_plaintext_auth
    # Password punctuation must survive: inline comments are not globally stripped.
    path = tmp_path / "password.conf"
    path.write_text("[LDAP]\nserver=ldaps://audit.example\nbind_password=x ; y # z\n", encoding="utf-8")
    assert load_settings(str(path), use_env=False).bind_password == "x ; y # z"
