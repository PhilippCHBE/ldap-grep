"""Security regressions F6-F10; no external directory or live credentials."""

import asyncio
import csv
import io
import json
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from rich.console import Console

from ldapgrep import format as fmt
from ldapgrep.cli import Ctx, build_parser, cmd_tree, main
from ldapgrep.client import BASE, LDAP_FLAVOR, LdapClient, LdapGrepError, Record
from ldapgrep.config import ConfigError, Settings, load_settings


@pytest.mark.parametrize("delimiter", [",", "\t"])
@pytest.mark.parametrize("payload", [
    "=1+1", "+1+1", "-1+1", "@SUM(1)", " =1+1", "\t=1+1", "\r=1+1",
    "\n=1+1", "\x00=1+1", " \x01=1+1", "\u00a0=1+1", "＝1+1",
])
def test_spreadsheet_values_and_headers_are_safe(delimiter, payload):
    row = next(csv.reader(io.StringIO(fmt.to_csv([{payload: payload}], delimiter=delimiter))))
    assert row == ["'" + payload.replace("\x00", "\\x00")]
    rows = list(csv.reader(io.StringIO(fmt.to_csv([{payload: payload}], delimiter=delimiter))))
    assert rows[1] == ["'" + payload.replace("\x00", "\\x00")]


def test_spreadsheet_embedded_nul_is_visible_and_json_preserves_it():
    rows = [{"plain\x00header": "plain\x00value"}]
    decoded = list(csv.reader(io.StringIO(fmt.to_csv(rows))))
    assert decoded == [["plain\\x00header"], ["plain\\x00value"]]
    assert json.loads(fmt.to_json(rows)) == rows


def test_spreadsheet_multivalue_fields_and_raw_json(tmp_path):
    rows = [{"name": ["=1+1", "ordinary"], "description": 'text, with "quotes"'}]
    csv_row = list(csv.DictReader(io.StringIO(fmt.to_csv(rows))))[0]
    assert csv_row["name"] == "'=1+1; ordinary"
    assert csv_row["description"] == rows[0]["description"]
    target = tmp_path / "raw.json"
    fmt.render(rows, "json", output=str(target))
    assert json.loads(target.read_text(encoding="utf-8")) == rows


def directory(graph, **settings):
    """Minimal synchronous LDAP stub, counting each actual search/page."""
    c = LdapClient(Settings(base_dn="dc=example", **settings))
    c.flavor = LDAP_FLAVOR
    conn = SimpleNamespace(receive_timeout=10.0, socket=None, response=[], result={}, check_names=False)
    calls = []

    def search(base, flt, **kwargs):
        calls.append((base, flt, kwargs))
        rec = graph.get(base) if kwargs["search_scope"] == BASE else None
        conn.response = ([{"type": "searchResEntry", "dn": rec.dn,
                           "attributes": {k: v for k, v in rec.items()}}] if rec else [])
        conn.result = {"result": 0}
        return bool(conn.response)

    conn.search = search
    c.conn = conn
    return c, conn, calls


def group(n, members=()):
    return Record.from_ldap3(f"cn=g{n},dc=example", {"cn": [f"g{n}"],
                            "objectClass": ["groupOfNames"], "member": list(members)})


def person(n):
    return Record.from_ldap3(f"cn=u{n},dc=example", {"cn": [f"u{n}"], "objectClass": ["person"]})


@pytest.mark.parametrize("configured_limit", [False, True])
def test_member_limit_stops_fallback_fetches(configured_limit):
    people = [person(i) for i in range(20)]
    root = group(0, [p.dn for p in people])
    c, _, calls = directory({p.dn: p for p in people}, size_limit=1 if configured_limit else 0)
    result = c.group_members(root, ["cn"], limit=0 if configured_limit else 1)
    assert [r.dn for r in result] == [people[0].dn]
    assert len(calls) == 2  # reverse lookup, then only one fallback member
    assert any("incomplete" in w for w in c.warnings)


def test_recursive_limit_applies_after_kind_filter_and_bounds_work():
    user = person(1)
    nested = group(1, [user.dn, person(2).dn])
    root = group(0, [nested.dn])
    c, _, calls = directory({nested.dn: nested, user.dn: user})
    result = c.group_members(root, ["cn"], recursive=True, kind="users", limit=1)
    assert [r.dn for r in result] == [user.dn]
    assert len(calls) == 4


@pytest.mark.parametrize("key,reason", [("group_max_queries", "query"), ("group_max_entries", "entry")])
def test_group_budget_is_global_across_fallbacks(key, reason):
    people = [person(i) for i in range(5)]
    root = group(0, [p.dn for p in people])
    c, _, calls = directory({p.dn: p for p in people}, **{key: 2})
    with pytest.raises(LdapGrepError, match=reason + " budget exhausted; result is incomplete"):
        c.group_members(root, ["cn"])
    assert len(calls) <= (2 if key == "group_max_queries" else 3)


def test_query_budget_counts_pages_and_stops_repeated_cookies():
    c, conn, calls = directory({}, group_max_queries=3)

    def search(*args, **kwargs):
        calls.append(kwargs)
        conn.response = []
        conn.result = {"controls": {"1.2.840.113556.1.4.319": {"value": {"cookie": b"repeat"}}}}

    conn.search = search
    with pytest.raises(LdapGrepError, match="query budget exhausted"):
        c.group_members(group(0), ["cn"])
    assert len(calls) == 3


def test_depth_budget_and_long_iterative_traversal():
    graph = {f"cn=g{i},dc=example": group(i, [f"cn=g{i+1},dc=example"]) for i in range(1050)}
    graph["cn=g1050,dc=example"] = group(1050)
    c, _, _ = directory(graph, group_max_depth=2)
    with pytest.raises(LdapGrepError, match="depth budget exhausted"):
        c.group_members(graph["cn=g0,dc=example"], ["cn"], recursive=True)
    c, _, calls = directory(graph, group_max_depth=1100, group_max_queries=3000)
    assert len(c.group_members(graph["cn=g0,dc=example"], ["cn"], recursive=True)) == 1050
    assert len(calls) < 3000


def test_group_deadline_caps_receive_timeout_and_aborts(monkeypatch):
    clock = [0.0]
    monkeypatch.setattr("ldapgrep.client.time.monotonic", lambda: clock[0])
    c, conn, _ = directory({}, group_max_seconds=1.0)
    observed = []

    def slow_search(*args, **kwargs):
        observed.append(conn.receive_timeout)
        clock[0] = 2.0

    conn.search = slow_search
    with pytest.raises(LdapGrepError, match="time budget exhausted"):
        c.group_members(group(0), ["cn"])
    assert observed == [1.0] and conn.receive_timeout == 10.0


def test_memberof_uses_same_query_budget():
    user = person(1)
    user.set("memberOf", [f"cn=g{i},dc=example" for i in range(6)])
    c, _, calls = directory({}, group_max_queries=2)
    with pytest.raises(LdapGrepError, match="query budget exhausted"):
        c.user_groups(user, recursive=True)
    assert len(calls) == 2


@pytest.mark.parametrize("key,value", [("group_max_queries", 0), ("group_max_depth", -1),
                                      ("group_max_seconds", "nan"), ("group_max_entries", 0)])
def test_group_budgets_cannot_be_disabled(key, value):
    with pytest.raises(ConfigError, match=key):
        load_settings(skip_config=True, use_env=False, overrides={key: value})


def test_tree_and_errors_render_untrusted_markup_as_text(monkeypatch, capsys):
    evil = Record.from_ldap3("ou=evil,dc=example", {"ou": ["[link=https://example.com]evil[/]"],
                            "description": ["[/]\x1b[2J"], "objectClass": ["organizationalUnit"]})
    client = Mock(base_dn="dc=example", warnings=[])
    client.list_containers.return_value = [evil]
    client.__enter__ = Mock(return_value=client)
    client.__exit__ = Mock(return_value=False)
    monkeypatch.setattr("ldapgrep.cli.connect", Mock(return_value=client))
    args = build_parser().parse_args(["--demo", "tree", "--depth", "1", "--format", "table"])
    ctx = Ctx(args, Settings())
    capture = io.StringIO()
    ctx.console = Console(file=capture, force_terminal=True, color_system=None, width=150)
    assert cmd_tree(args, ctx) == 0
    text = capture.getvalue()
    assert "[link=https://example.com]evil[/]" in text and "[/]" in text
    assert "\x1b" not in text and "\\x1b[2J" in text
    monkeypatch.setattr("ldapgrep.cli.connect", Mock(side_effect=LdapGrepError("[/]\x1b[2J")))
    assert main(["--demo", "info"]) == 4
    err = capsys.readouterr().err
    assert "[/]" in err and "\x1b" not in err


@pytest.mark.parametrize("interactive", [True, False])
def test_terminal_controls_are_escaped_without_changing_files_or_pipes(interactive, monkeypatch, tmp_path):
    class Capture(io.StringIO):
        def isatty(self):
            return interactive

    capture = Capture()
    monkeypatch.setattr("ldapgrep.format.sys.stdout", capture)
    rows = [{"dn": "cn=\x1b[2J\x9b31m\u202euser,dc=example"}]
    fmt.render(rows, "dn")
    if interactive:
        assert "\x1b" not in capture.getvalue() and "\x9b" not in capture.getvalue()
        assert "\\x1b[2J" in capture.getvalue() and "\\u202e" in capture.getvalue()
    else:
        assert rows[0]["dn"] in capture.getvalue()
    path = tmp_path / "raw.json"
    fmt.render(rows, "json", output=str(path))
    assert json.loads(path.read_text(encoding="utf-8")) == rows


@pytest.mark.parametrize("server", ["ldaps://audit:synthetic@audit.example", "audit:synthetic@audit.example",
                                   "ldaps://audit:synthetic@@audit.example:bad", "ldaps://audit:synthetic\n@host",
                                   "ldaps://audit:synthetic/part@host"])
def test_url_credentials_hidden_in_every_diagnostic_field(server):
    s = Settings(server=server, config_server=server, bind_password="synthetic")
    for reveal_password in (False, True):
        data = s.to_dict(hide_secrets=not reveal_password)
        assert "synthetic" not in data["server"] and "synthetic" not in data["config_server"]
        assert "[redacted]@" in data["server"]
    assert "synthetic" not in repr(s)
    assert s.to_dict()["bind_password"] == "********"
    assert s.to_dict(hide_secrets=False)["bind_password"] == "synthetic"


def test_cli_config_redacts_overridden_legacy_url(tmp_path, capsys):
    path = tmp_path / "config.conf"
    path.write_text("[LDAP]\nserver=ldaps://audit:synthetic@host\nbind_password=synthetic\n", encoding="utf-8")
    assert main(["--config", str(path), "--server", "ldaps://safe.example", "config", "-f", "json"]) == 0
    output = capsys.readouterr()
    assert "synthetic" not in output.out + output.err
    assert json.loads(output.out)[0]["config_server"] == "ldaps://[redacted]@host"


@pytest.mark.parametrize("no_color", [False, True])
def test_interactive_json_escapes_c1_controls_and_bidi(no_color, monkeypatch):
    class Capture(io.StringIO):
        def isatty(self):
            return True

    capture = Capture()
    monkeypatch.setattr("ldapgrep.format.sys.stdout", capture)
    console = Console(file=capture, force_terminal=True, color_system=None, no_color=no_color)
    fmt.render([{"name": "\x9b31m\u202e"}], "json", console=console)
    assert "\x9b" not in capture.getvalue() and "\u202e" not in capture.getvalue()
    assert "\\u009b" in capture.getvalue() and "\\u202e" in capture.getvalue()
    assert json.loads(capture.getvalue()) == [{"name": "\x9b31m\u202e"}]


def test_reverse_lookup_page_size_honors_small_output_limit():
    c, conn, calls = directory({})

    def search(*args, **kwargs):
        calls.append(kwargs)
        conn.response = [{"type": "searchResEntry", "dn": person(1).dn,
                          "attributes": {"cn": ["u1"], "objectClass": ["person"]}}]
        conn.result = {"controls": {"1.2.840.113556.1.4.319": {"value": {"cookie": b"more"}}}}

    conn.search = search
    assert len(c.group_members(group(0), ["cn"], limit=1)) == 1
    assert len(calls) == 1 and calls[0]["paged_size"] == 1


def test_tui_profile_switch_clears_credentials_and_preserves_initial_custom_settings():
    pytest.importorskip("textual")
    from textual.widgets import Checkbox, Input, Select
    from ldapgrep.tui import LdapGrepApp

    async def scenario():
        app = LdapGrepApp(Settings(server="ldaps://partial.example"))
        async with app.run_test(size=(120, 45)) as pilot:
            await pilot.pause(0.2)
            screen = app.screen
            assert screen.query_one("#server", Input).value == "ldaps://partial.example"
            picker = screen.query_one("#profile", Select)
            picker.value = "profile:freeipa"
            await pilot.pause(0.2)
            screen.query_one("#tls_verify", Checkbox).value = False
            picker.value = "custom"
            await pilot.pause(0.2)
            s = screen._collect()["settings"]
            assert not s.server and not s.bind_dn and not s.bind_password and not s.base_dn
            assert s.tls_verify and not s.start_tls and not s.allow_plaintext_auth
            assert not s.builtin_profile and not s.ca_certs_file and not screen._ready()
            await pilot.press("escape")

    asyncio.run(scenario())
