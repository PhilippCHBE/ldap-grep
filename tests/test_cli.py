import csv
import io
import json
import os
from pathlib import Path

import pytest

from ldapgrep.cli import main


@pytest.fixture(autouse=True)
def _isolated_env(monkeypatch, tmp_path):
    """No real config file / env may leak into the tests."""
    for k in list(os.environ):
        if k.startswith("LDAPGREP_"):
            monkeypatch.delenv(k)
    monkeypatch.setenv("NO_COLOR", "1")
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path))
    conf = tmp_path / "ldapgrep.conf"
    conf.write_text("[LDAP]\nserver = demo\nbind_dn = demo\nbind_password = demo\n", encoding="utf-8")
    monkeypatch.setenv("LDAPGREP_CONFIG", str(conf))
    monkeypatch.chdir(tmp_path)


def run(capsys, *argv):
    code = main(["--demo", *argv])
    out, err = capsys.readouterr()
    return code, out, err


def test_user_json_and_exit_codes(capsys):
    code, out, _ = run(capsys, "user", "mül", "--format", "json")
    assert code == 0
    data = json.loads(out)
    assert data[0]["name"] == "mmueller"
    assert set(data[0]) >= {"dn", "name", "disabled", "email", "givenName_surname"}
    code, out, _ = run(capsys, "user", "nobody-xyz", "--format", "json")
    assert code == 1 and json.loads(out) == []
    code, _, err = run(capsys, "user", "x")
    assert code == 2 and "at least" in err


def test_broad_wildcard_search_is_blocked_by_default(capsys):
    code, _, err = run(capsys, "user", "*")
    assert code == 2 and "blocked" in err
    code, _, err = run(capsys, "user", "m*")
    assert code == 2 and "blocked" in err
    code, _, err = run(capsys, "groups", "*")
    assert code == 2 and "blocked" in err
    # ... unless an additional LDAP filter narrows it down
    code, out, _ = run(capsys, "user", "*", "--filter", "(department=Legal)", "--format", "list")
    assert code == 0 and len(out.split()) == 3


def test_broad_wildcard_search_warns_when_min_search_length_is_low(capsys, tmp_path, monkeypatch):
    # min_search_length < 2: non-interactive calls proceed with a warning on stderr
    conf = tmp_path / "low.conf"
    conf.write_text("[LDAP]\nserver = demo\nbind_dn = demo\nbind_password = demo\nmin_search_length = 0\n",
                    encoding="utf-8")
    code = main(["--demo", "--config", str(conf), "user", "*", "--count"])
    out, err = capsys.readouterr()
    assert code == 0 and int(out.strip()) >= 30
    assert "whole directory" in err or "every entry" in err


def test_user_and_groups_count(capsys):
    code, out, _ = run(capsys, "user", "moser", "--count")
    assert code == 0 and out.strip() == "2"
    code, out, _ = run(capsys, "user", "nobody-xyz", "--count")
    assert code == 1 and out.strip() == "0"
    code, out, _ = run(capsys, "groups", "it", "--count")
    assert code == 0 and out.strip() == "4"


def test_check_command(capsys):
    code, _, err = run(capsys, "check")
    assert code == 0 and "demo mode" in err
    code = main(["--server", "ldaps://does-not-exist.invalid", "--bind-dn", "x", "--password", "y", "check"])
    out, err = capsys.readouterr()
    assert code == 3 and "FAILED" in out and "does not resolve" in out


def test_export_csv_auto(capsys, tmp_path):
    code, _, err = run(capsys, "user", "moser", "--format", "csv", "--output", "auto")
    assert code == 0
    from ldapgrep.exports import default_export_dir
    files = list(default_export_dir().glob("moser_*.csv"))
    assert len(files) == 1
    with files[0].open(encoding="utf-8", newline="") as stream:
        rows = list(csv.reader(stream))
    assert rows[0][:3] == ["dn", "name", "disabled"] and len(rows) == 3


def test_group_recursive_count_and_formats(capsys):
    code, out, _ = run(capsys, "group", "All Staff", "-r", "--users-only", "--count")
    assert code == 0 and out.strip() == "32"
    code, out, _ = run(capsys, "group", "IT", "--format", "list")
    assert out.split() == ["mjäger", "Developers", "IT-Admins", "IT-ServiceDesk"]
    code, out, _ = run(capsys, "group", "IT", "--format", "table")
    assert "Members of IT (4)" in out
    code, out, _ = run(capsys, "group", "Nope")
    assert code == 1


def test_memberof_compare_search(capsys):
    code, out, _ = run(capsys, "memberof", "mmueller", "-r", "--format", "json")
    rows = json.loads(out)
    assert [r["name"] for r in rows] == ["All Staff", "DL-Newsletter", "Domain Users", "IT", "IT-Admins", "VPN-Users"]
    assert {r["membership"] for r in rows} == {"direct", "nested"}
    code, out, _ = run(capsys, "compare", "mmueller", "afischer", "-r", "--format", "json")
    rows = json.loads(out)
    assert any(r["status"] == "only afischer" and r["group"] == "Management" for r in rows)
    code, out, _ = run(capsys, "search", "(&(objectClass=user)(department=Legal))", "--attrs", "cn", "--format", "list")
    assert code == 0 and len(out.split("\n")) >= 3
    code, out, _ = run(capsys, "search", "(objectClass=group)", "--count")
    assert out.strip() == "17"
    code, _, err = run(capsys, "search", "(broken")
    assert code == 2 and "filter" in err.lower()
    code, _, err = run(capsys, "memberof", "moser")
    assert code == 2 and "ambiguous" in err


def test_from_file_fields_sort(capsys, tmp_path):
    f = tmp_path / "logins.txt"
    f.write_text("mmueller\nafischer\n# comment\nnobody\n", encoding="utf-8")
    code, out, err = run(capsys, "user", "--from-file", str(f), "--format", "csv", "--fields", "name,email", "--sort=-name")
    assert code == 0
    assert list(csv.reader(io.StringIO(out))) == [
        ["name", "email"], ["mmueller", "max.muller@demo.example.com"],
        ["afischer", "anna.fischer@demo.example.com"]]
    assert "no match for 'nobody'" in err


def test_info_schema_tree_config(capsys):
    code, out, _ = run(capsys, "info", "--format", "json")
    info = json.loads(out)[0]
    assert info["flavor"] == "ad" and info["schema_loaded"] is True
    code, out, _ = run(capsys, "schema", "samaccount", "--format", "list")
    assert code == 0
    code, out, _ = run(capsys, "tree", "--depth", "2", "--format", "json")
    assert {r["name"] for r in json.loads(out)} >= {"Company", "Users", "Groups"}
    code, out, _ = run(capsys, "config", "--check", "--format", "json")
    assert json.loads(out)[0]["connection"] == "OK"
    code, out, _ = run(capsys, "whoami")
    assert out.strip().startswith("CN=svc-ldapgrep")


def test_connection_errors(capsys):
    code = main(["--server", "ldaps://does-not-exist.invalid", "--bind-dn", "x", "--password", "y", "user", "test"])
    _, err = capsys.readouterr()
    assert code == 3 and "Cannot connect" in err
    code = main(["--profile", "nope", "--demo", "info"])
    _, err = capsys.readouterr()
    assert code == 2 and "Profile 'nope'" in err


def test_output_dash_means_stdout(capsys, tmp_path, monkeypatch):
    import json
    from ldapgrep.cli import main

    monkeypatch.chdir(tmp_path)
    rc = main(["--demo", "user", "mueller", "--format", "json", "-o", "-"])
    out = capsys.readouterr().out
    assert rc == 0 and json.loads(out)[0]["name"] == "mmueller"
    assert not (tmp_path / "-").exists()
