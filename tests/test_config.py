import os

import pytest

from ldapgrep.config import ConfigError, Settings, load_settings, parse_server_url


def test_parse_server_url():
    assert parse_server_url("ldaps://dc01.example.com:636") == ("dc01.example.com", 636, True)
    assert parse_server_url("ldap://dc01") == ("dc01", None, False)
    assert parse_server_url("dc01.example.com") == ("dc01.example.com", None, False)
    assert parse_server_url("") == ("", None, False)


def test_settings_derived():
    s = Settings(server="ldaps://dc01")
    assert s.effective_ssl is True and s.effective_port == 636
    s = Settings(server="dc01")
    assert s.effective_ssl is False and s.effective_port == 389
    s = Settings(server="ldap://dc01", port=3268)
    assert s.effective_port == 3268
    assert s.display_url == "ldap://dc01:3268"


def test_key_aliases_and_profiles(tmp_path, monkeypatch):
    # alternative key spellings (any casing) map onto the settings fields
    conf = tmp_path / "ldapgrep.conf"
    conf.write_text(
        """
[LDAP]
LDAP_SERVER = ldaps://prod.example.com:636
BASE_DN = DC=example,DC=com
BIND_DN = CN=svc,DC=example,DC=com
BIND_PASSWORD = s3cret
LDAP_TIMEOUT = 7
DEFAULT_GROUP_DN = CN=Staff,DC=example,DC=com
GROUPS_OU = OU=Groups,DC=example,DC=com
user_extra_attributes = employeeID; division, company

[profile:test]
server = ldap://test.example.com
tls_verify = no
""",
        encoding="utf-8",
    )
    for k in list(os.environ):
        if k.startswith("LDAPGREP_"):
            monkeypatch.delenv(k)
    s = load_settings(str(conf))
    assert s.server == "ldaps://prod.example.com:636"
    assert s.base_dn == "DC=example,DC=com"
    assert s.timeout == 7.0
    assert s.default_group_dn == "CN=Staff,DC=example,DC=com"
    assert s.user_extra_attributes == ["employeeID", "division", "company"]
    assert s.tls_verify is True

    t = load_settings(str(conf), profile="test")
    assert t.server == "ldap://test.example.com"
    assert t.base_dn == "DC=example,DC=com"      # inherited from [LDAP]
    assert t.tls_verify is False

    with pytest.raises(ConfigError):
        load_settings(str(conf), profile="missing")


def test_env_and_overrides_win(tmp_path, monkeypatch):
    conf = tmp_path / "x.conf"
    conf.write_text("[LDAP]\nserver = ldap://file\nbind_dn = file\n", encoding="utf-8")
    monkeypatch.setenv("LDAPGREP_SERVER", "ldap://env")
    monkeypatch.setenv("LDAPGREP_PASSWORD", "envpw")
    s = load_settings(str(conf), overrides={"bind_dn": "cli", "timeout": None})
    assert s.server == "ldap://env"
    assert s.bind_password == "envpw"
    assert s.bind_dn == "cli"


def test_password_file(tmp_path, monkeypatch):
    for k in list(os.environ):
        if k.startswith("LDAPGREP_"):
            monkeypatch.delenv(k)
    pw = tmp_path / "pw"
    pw.write_text("filepw\n", encoding="utf-8")
    conf = tmp_path / "x.conf"
    conf.write_text(f"[LDAP]\nserver = ldap://x\nbind_password_file = {pw}\n", encoding="utf-8")
    assert load_settings(str(conf)).bind_password == "filepw"


def test_invalid_values(tmp_path):
    conf = tmp_path / "x.conf"
    conf.write_text("[LDAP]\nserver = ldap://x\ntimeout = abc\n", encoding="utf-8")
    with pytest.raises(ConfigError):
        load_settings(str(conf))
    conf.write_text("[LDAP]\nserver = ldap://x\nauth = kerberos\n", encoding="utf-8")
    with pytest.raises(ConfigError):
        load_settings(str(conf))
    with pytest.raises(ConfigError):
        load_settings(str(tmp_path / "nope.conf"))


def test_skip_config_ignores_files(tmp_path, monkeypatch):
    from ldapgrep.config import load_settings

    cfg = tmp_path / "ldapgrep.conf"
    cfg.write_text("[ldapgrep]\nserver = ldaps://corp.example.com\nbase_dn = DC=corp,DC=example\n", encoding="utf-8")
    monkeypatch.delenv("LDAPGREP_CONFIG", raising=False)
    s = load_settings(str(cfg), None, {"server": "ldap://other"})
    assert s.base_dn == "DC=corp,DC=example" and s.config_server == "ldaps://corp.example.com"
    s2 = load_settings(str(cfg), None, {"server": "ldap://other"}, skip_config=True)
    assert s2.base_dn == "" and s2.config_file == "" and s2.server == "ldap://other"


def test_builtin_public_profiles_and_no_fallback(tmp_path, monkeypatch):
    from ldapgrep.config import all_profiles, load_settings, profile_settings

    monkeypatch.delenv("LDAPGREP_CONFIG", raising=False)
    for k in list(__import__("os").environ):
        if k.upper().startswith("LDAPGREP_"):
            monkeypatch.delenv(k)

    cfg = tmp_path / "ldapgrep.conf"
    cfg.write_text("[LDAP]\nserver = ldaps://corp.example.com\nbase_dn = DC=corp,DC=example\n"
                   "bind_dn = CN=svc,DC=corp,DC=example\n[profile:debian]\nserver = ldap://mine\n", encoding="utf-8")

    # built-in profile: usable with a config file present, and it does NOT inherit the [LDAP] section
    s = load_settings(str(cfg), "freeipa")
    assert s.server.startswith("ldap://ipa.demo1") and s.start_tls and s.base_dn == "" and s.tls_verify is True
    assert s.fallback_profile == "" and s.config_server == ""
    # a profile of the same name in the file shadows the built-in one
    assert load_settings(str(cfg), "debian").server == "ldap://mine"
    assert load_settings(str(cfg), "debian").base_dn == "DC=corp,DC=example"
    # without any config file built-ins still work
    anon = load_settings(None, "debian", skip_config=True)
    assert anon.auth == "anonymous" and anon.server == "ldap://db.debian.org:389"
    assert profile_settings(None, "forumsys").bind_dn.startswith("cn=read-only-admin")
    # Nothing configured: never fill in a public target.
    empty = tmp_path / "empty.conf"
    empty.write_text("[LDAP]\ntimeout = 3\n", encoding="utf-8")
    fb = load_settings(str(empty), None)
    assert fb.fallback_profile == "" and fb.server == "" and fb.timeout == 3
    assert load_settings(str(empty), None, demo=True).fallback_profile == "" and load_settings(str(empty), None, demo=True).server == ""
    names = [n for n, _ in all_profiles(cfg)]
    assert names[:2] == ["LDAP", "debian"] and "forumsys" in names and "freeipa" in names and names.count("debian") == 1


def test_candidate_config_names_prefer_ldap_grep_conf():
    from ldapgrep.config import candidate_config_files

    names = [p.name for p in candidate_config_files()]
    assert names[0] == "ldap-grep.conf" and names[1] == "ldapgrep.conf"
    assert all("getGroupMembers" not in n for n in names)
