import pytest

from ldapgrep import format as fmt
from ldapgrep.client import AmbiguousMatch, LdapClient, LdapGrepError, Record, EXIT_NO_MATCH, EXIT_USAGE
from ldapgrep.config import Settings


@pytest.fixture(scope="module")
def client():
    c = LdapClient(Settings(), demo=True).connect()
    yield c
    c.close()


def test_connect_detects_flavor_and_base(client):
    assert client.flavor.name == "ad"
    assert client.base_dn == "DC=demo,DC=example,DC=com"
    assert client.schema_available
    assert client.flavor.supports_in_chain is False     # mock cannot do server side nesting


def test_unknown_attribute_is_skipped_with_warning(client):
    attrs = client.filter_attributes(["cn", "doesNotExist", "sAMAccountName"])
    assert attrs == ["cn", "sAMAccountName"]
    assert any("doesNotExist" in w for w in client.warnings)
    client.warnings.clear()
    # built-in attributes of other flavors are dropped silently
    assert client.filter_attributes(["cn", "nsAccountLock"]) == ["cn"]
    assert client.warnings == []


def test_record_access_never_raises():
    rec = Record.from_ldap3("CN=x", {"cn": ["x"], "mail": [], "photo": [b"\xff\xd8"]})
    assert rec.first("cn") == "x"
    assert rec.first("missing") == ""
    assert rec.first("missing", None) is None
    assert rec.first("mail") == ""
    assert rec.get("nothing") == []
    assert rec.has("MAIL") is False
    assert rec.first("photo").startswith("base64:")
    assert rec.disabled is False and rec.locked is False


def test_user_search_variants(client):
    attrs = fmt.user_attributes("compact", client.settings)
    logins = lambda recs: sorted(r.login for r in recs)  # noqa: E731
    assert logins(client.search_users("mül", attrs)) == ["mmueller"]
    assert logins(client.search_users("mueller", attrs)) == ["mmueller"]         # ue -> ü
    assert logins(client.search_users("Max Müller", attrs)) == ["mmueller"]      # first + last
    assert logins(client.search_users("Müller Max", attrs)) == ["mmueller"]      # last + first
    assert logins(client.search_users("moser", attrs)) == ["fmoser", "smoser"]
    assert logins(client.search_users("ller", attrs, mode="contains")) == ["mmueller", "tkeller"]
    assert logins(client.search_users("*keller", attrs)) == ["tkeller"]
    assert logins(client.search_users("keller", attrs, active_only=True)) == []
    assert logins(client.search_users("max.muller@demo.example.com", attrs)) == ["mmueller"]
    assert logins(client.search_users("E1000", attrs)) == ["mmueller"]           # employeeID
    with pytest.raises(LdapGrepError) as exc:
        client.search_users("x", attrs)
    assert exc.value.exit_code == EXIT_USAGE


def test_is_broad_term():
    from ldapgrep.client import is_broad_term

    assert is_broad_term("*") and is_broad_term("a*") and is_broad_term("*b*") and is_broad_term("?")
    assert not is_broad_term("ab*") and not is_broad_term("meier") and not is_broad_term("CN=x,DC=y")
    assert not is_broad_term("") and not is_broad_term("ab")


def test_broad_search_guard(client):
    attrs = ["cn", "sAMAccountName"]
    # default min_search_length = 2: '*' and 'a*' are blocked, even with allow_broad
    for term in ("*", "m*", "*l*"):
        with pytest.raises(LdapGrepError) as exc:
            client.search_users(term, attrs)
        assert "blocked" in exc.value.message and exc.value.exit_code == EXIT_USAGE
    with pytest.raises(LdapGrepError):
        client.list_groups("i*", attrs)
    # an extra LDAP filter narrows the search -> allowed
    assert client.search_users("*", attrs, extra_filter="(department=Legal)")
    # min_search_length < 2: needs an explicit opt-in
    client.settings.min_search_length = 0
    try:
        with pytest.raises(LdapGrepError) as exc2:
            client.search_users("*", attrs)
        assert "confirmation" in exc2.value.message
        assert len(client.search_users("*", attrs, allow_broad=True)) >= 30
        assert len(client.list_groups("*", attrs, allow_broad=True)) == 16
        with pytest.raises(LdapGrepError):
            client.list_groups("i*", attrs)
    finally:
        client.settings.min_search_length = 2


def test_count_only(client):
    assert client.count_users("mmueller") == 1
    assert client.count_users("moser") == 2
    assert client.count_users("nobody-xyz") == 0
    assert client.count_groups("it") == 4            # IT, IT-Admins, IT-ServiceDesk, Facilities
    assert client.count_groups("") == 16
    client.settings.min_search_length = 0
    try:
        assert client.count_users("*", allow_broad=True) >= 30
    finally:
        client.settings.min_search_length = 2


def test_find_user_and_errors(client):
    u = client.find_user("mmueller")
    assert u.dn.startswith("CN=Max Müller")
    assert client.find_user(u.dn).dn == u.dn
    with pytest.raises(AmbiguousMatch) as exc:
        client.find_user("moser")
    assert len(exc.value.candidates) == 2
    with pytest.raises(LdapGrepError) as exc2:
        client.find_user("nobody-here")
    assert exc2.value.exit_code == EXIT_NO_MATCH


def test_groups(client):
    g = client.find_group("it")                      # case-insensitive exact wins over prefix matches
    assert g.display_name == "IT"
    assert client.find_group(g.dn).dn == g.dn
    with pytest.raises(AmbiguousMatch):
        client.find_group("IT-")
    with pytest.raises(LdapGrepError):
        client.find_group("does-not-exist")

    direct = client.group_members(g, ["cn", "objectClass", "userAccountControl", "sAMAccountName"])
    assert {m.display_name for m in direct} == {"Michael Jäger", "Developers", "IT-Admins", "IT-ServiceDesk"}
    nested_users = client.group_members(g, ["cn", "objectClass", "userAccountControl"], recursive=True, kind="users")
    assert {m.display_name for m in nested_users} >= {"Max Müller", "Anna Fischer", "Lea Brunner", "Michael Jäger"}
    assert all(not m.is_group for m in nested_users)
    everyone = client.group_members("All Staff", ["cn", "objectClass", "userAccountControl"], recursive=True, kind="users")
    assert len(everyone) == 32
    active = client.group_members("All Staff", ["cn", "objectClass", "userAccountControl"], recursive=True, kind="users", active_only=True)
    assert len(active) == 30
    assert client.group_members("Empty-Group", ["cn"]) == []


def test_user_groups_and_primary_group(client):
    direct = [g.display_name for g in client.user_groups("mmueller")]
    assert direct == ["Domain Users", "IT-Admins"]
    nested = [g.display_name for g in client.user_groups("mmueller", recursive=True)]
    assert nested == ["All Staff", "DL-Newsletter", "Domain Users", "IT", "IT-Admins", "VPN-Users"]


def test_list_groups_and_containers(client):
    names = [g.display_name for g in client.list_groups("")]
    assert "All Staff" in names and len(names) == 16
    assert [g.display_name for g in client.list_groups("it*", mode="prefix")] == ["IT", "IT-Admins", "IT-ServiceDesk"] or \
        sorted(g.display_name for g in client.list_groups("it*", mode="prefix")) == ["IT", "IT-Admins", "IT-ServiceDesk"]
    assert [str(c.first_of("ou", "cn")) for c in client.list_containers()] == ["Company", "Users"]


def test_raw_search_errors(client):
    with pytest.raises(LdapGrepError) as exc:
        client.search("(cn=*", ["cn"])
    assert "filter" in exc.value.message.lower() and exc.value.exit_code == EXIT_USAGE
    with pytest.raises(LdapGrepError) as exc:
        client.search("(cn=*)", ["cn"], base="OU=nope,DC=x")
    assert "does not exist" in exc.value.message
    assert client.get_entry("CN=nope,DC=demo,DC=example,DC=com") is None


def test_views_decode_everything(client):
    s = client.settings
    rec = client.find_user("pmeier", None)            # locked user, all attributes
    compact = fmt.user_to_dict(rec, "compact", s)
    assert compact["name"] == "pmeier" and compact["locked"] is True and compact["disabled"] is False
    detail = fmt.user_to_dict(rec, "detail", s)
    assert detail["address"] == "Rue du Rhône 8, 1204 Genève"
    assert detail["accountExpires"] == "never"
    assert detail["objectSid"].startswith("S-1-5-21-")
    assert "-" in detail["objectGUID"] and "{" not in detail["objectGUID"]
    full = fmt.user_to_dict(rec, "full", s)
    assert full["badPwdCount"] == 5 and full["lockoutTime"]
    raw = fmt.record_to_raw(rec, s)
    assert raw["dn"] == rec.dn and isinstance(raw["objectClass"], list)
    disabled = client.find_user("tkeller", None)
    assert fmt.user_to_dict(disabled, "full", s)["lastLogon"] == ""
    assert fmt.user_to_dict(disabled, "compact", s)["disabled"] is True


def test_views_password_status(client):
    s = client.settings
    expired = client.find_user("rweber", None)          # flag "x": PASSWORD_EXPIRED
    assert expired.password_expired is True
    compact = fmt.user_to_dict(expired, "compact", s)
    assert compact["password_expired"] is True
    detail = fmt.user_to_dict(expired, "detail", s)
    assert detail["passwordExpires"] and detail["passwordExpires"] != "never"
    full = fmt.user_to_dict(expired, "full", s)
    assert full["password_expired"] is True and full["passwordExpires"]
    assert "PASSWORD_EXPIRED" in full["account_flags"]

    never = client.find_user("mmueller", None)          # flag "p": DONT_EXPIRE_PASSWORD
    assert never.password_expired is False
    assert fmt.user_to_dict(never, "detail", s)["passwordExpires"] == "never"
    assert "password_expired" not in fmt.user_to_dict(never, "compact", s)


def test_renderers():
    rows = [{"dn": "CN=a", "name": "a", "disabled": False, "memberOf": ["x", "y"]},
            {"dn": "CN=b", "name": "b", "disabled": True, "extra": "ü"}]
    csv_text = fmt.to_csv(rows)
    assert csv_text.splitlines()[0] == "dn,name,disabled,memberOf,extra"
    assert "x; y" in csv_text
    ldif = fmt.to_ldif(rows)
    assert "dn: CN=a" in ldif and "memberOf: x" in ldif and "extra:: " in ldif    # non-ascii -> base64
    yaml = fmt.to_yaml(rows)
    assert "- dn: CN=a" in yaml and "memberOf:" in yaml
    assert fmt.to_list(rows) == "a\nb\n"
    assert fmt.select_fields(rows, ["Name", "nothing"]) == [{"Name": "a", "nothing": ""}, {"Name": "b", "nothing": ""}]
    assert [r["name"] for r in fmt.sort_rows(rows, "-name")] == ["b", "a"]


def test_limit_and_server_size_limit_salvage(client, monkeypatch):
    from ldap3.core import exceptions as ldap_exc

    attrs = ["cn", "sAMAccountName"]
    client.settings.min_search_length = 0
    try:
        assert len(client.search_users("*", attrs, limit=5, allow_broad=True)) == 5
    finally:
        client.settings.min_search_length = 2

    # simulate a real server answering the last page with sizeLimitExceeded (result code 4):
    # ldap3 raises before the generator yields that page -> entries must be salvaged from conn.response
    real_search = client.conn.search
    state = {"calls": 0}

    def flaky_search(*args, **kwargs):
        state["calls"] += 1
        ok = real_search(*args, **kwargs)
        if state["calls"] == 1:
            raise ldap_exc.LDAPSizeLimitExceededResult(result=4, description="sizeLimitExceeded")
        return ok

    monkeypatch.setattr(client.conn, "search", flaky_search)
    client.warnings.clear()
    recs = client.search("(objectClass=group)", ["cn"])
    assert len(recs) > 0                              # partial result instead of nothing
    assert any("size limit" in w for w in client.warnings)


def test_pick_base_dn_skips_operational_contexts():
    from ldapgrep.client import pick_base_dn

    assert pick_base_dn(["dc=debian,dc=org", "cn=log"]) == "dc=debian,dc=org"
    assert pick_base_dn(["cn=config", "cn=schema", "o=example"]) == "o=example"
    assert pick_base_dn(["DC=ForestDnsZones,DC=corp,DC=example", "DC=corp,DC=example"]) == "DC=corp,DC=example"
    assert pick_base_dn(["cn=monitor"]) == "cn=monitor"
    assert pick_base_dn([]) == ""


def test_sanitize_filter_replaces_unknown_classes(client):
    assert client.sanitize_filter("(objectClass=user)") == "(objectClass=user)"
    out = client.sanitize_filter("(|(objectClass=organizationalUnit)(objectClass=noSuchClass))")
    assert out == "(|(objectClass=organizationalUnit)(!(objectClass=*)))"
    assert client.sanitize_filter("(objectClass=*)") == "(objectClass=*)"
    # a filter with an unknown class must not crash the search any more
    assert client.search("(objectClass=noSuchClass)", ["cn"]) == []


def test_is_active_directory_detection():
    from ldapgrep.client import AD_CAPABILITY_OID, is_active_directory

    assert is_active_directory({"defaultnamingcontext": ["DC=x"], "supportedcapabilities": [AD_CAPABILITY_OID]})
    assert is_active_directory({"defaultnamingcontext": ["DC=x"], "domainfunctionality": ["7"]})
    assert is_active_directory({"defaultnamingcontext": ["DC=x"]})                         # AD sends no vendorName
    assert not is_active_directory({"defaultnamingcontext": ["dc=x"], "ipadomainlevel": ["1"]}, "389 Project")
    assert not is_active_directory({"namingcontexts": ["dc=x"]}, "OpenLDAP")


def test_iter_search_deduplicates_repeated_entries(client, monkeypatch):
    plain = client.search("(objectClass=group)", ["cn"])
    real = client.conn.extend.standard.paged_search

    def doubled(*args, **kwargs):
        items = list(real(*args, **kwargs))
        return iter(items + items)

    monkeypatch.setattr(client.conn.extend.standard, "paged_search", doubled)
    recs = client.search("(objectClass=group)", ["cn"])
    assert len(recs) == len({r.dn.lower() for r in recs}) == len(plain) > 0
