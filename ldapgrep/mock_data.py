"""In-memory demo directory (ldap3 MOCK_SYNC) used by `--demo` and the test-suite.

The data is fictional.  It only uses attributes that exist in the offline
AD 2012 R2 schema shipped with ldap3, because the mock validates names.
"""

from __future__ import annotations

import random
import struct
import uuid
import warnings
from datetime import datetime, timedelta, timezone

with warnings.catch_warnings():
    warnings.simplefilter("ignore", DeprecationWarning)
    from ldap3 import MOCK_SYNC, OFFLINE_AD_2012_R2, Connection, Server

BASE_DN = "DC=demo,DC=example,DC=com"
USERS_OU = f"OU=Users,OU=Company,{BASE_DN}"
GROUPS_OU = f"OU=Groups,OU=Company,{BASE_DN}"
SERVICE_OU = f"OU=Service Accounts,OU=Company,{BASE_DN}"
COMPUTERS_OU = f"OU=Computers,OU=Company,{BASE_DN}"
BIND_DN = f"CN=svc-ldapgrep,{SERVICE_OU}"
BIND_PASSWORD = "demo"
DEFAULT_GROUP_DN = f"CN=All Staff,{GROUPS_OU}"
DOMAIN_SID = "S-1-5-21-1004336348-1177238915-682003330"

_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)


def _filetime(dt: datetime | None) -> int:
    if dt is None:
        return 0
    return int((dt - _EPOCH).total_seconds() * 10_000_000)


def _sid(rid: int) -> bytes:
    parts = [int(x) for x in DOMAIN_SID.split("-")[3:]] + [rid]
    return bytes([1, len(parts)]) + (5).to_bytes(6, "big") + b"".join(struct.pack("<I", p) for p in parts)


def _gen_time(dt: datetime) -> str:
    return dt.strftime("%Y%m%d%H%M%S.0Z")


# (login, first, last, dept, title, office, flags)
# flags: d = disabled, l = locked, e = expired account, n = no mail, p = password never expires, x = password expired
PEOPLE = [
    ("mmueller", "Max", "Müller", "IT", "System Administrator", "Bern", "p"),
    ("afischer", "Anna", "Fischer", "IT", "Head of IT", "Bern", ""),
    ("jschmid", "Jonas", "Schmid", "IT", "Network Engineer", "Zürich", ""),
    ("lbrunner", "Lea", "Brunner", "IT", "Service Desk Agent", "Bern", ""),
    ("tkeller", "Tim", "Keller", "IT", "Service Desk Agent", "Zürich", "d"),
    ("sgerber", "Sara", "Gerber", "Finance", "CFO", "Bern", ""),
    ("rweber", "Reto", "Weber", "Finance", "Controller", "Bern", "x"),
    ("nhuber", "Nina", "Huber", "Finance", "Accountant", "Zürich", ""),
    ("pmeier", "Pascal", "Meier", "Finance", "Accountant", "Genève", "l"),
    ("cbaumann", "Claudia", "Baumann", "HR", "Head of HR", "Bern", ""),
    ("dfrei", "David", "Frei", "HR", "HR Business Partner", "Zürich", ""),
    ("ezimmermann", "Elena", "Zimmermann", "HR", "Recruiter", "Bern", ""),
    ("mwyss", "Marco", "Wyss", "Sales", "Head of Sales", "Zürich", ""),
    ("jroth", "Julia", "Roth", "Sales", "Key Account Manager", "Zürich", ""),
    ("fmoser", "Fabian", "Moser", "Sales", "Account Manager", "Genève", ""),
    ("smoser", "Sophie", "Moser", "Sales", "Account Manager", "Bern", ""),
    ("bgraf", "Beat", "Graf", "Sales", "Sales Assistant", "Zürich", "e"),
    ("lhofer", "Laura", "Hofer", "Marketing", "Head of Marketing", "Bern", ""),
    ("kbaumgartner", "Kevin", "Baumgartner", "Marketing", "Content Manager", "Bern", ""),
    ("ischneider", "Isabelle", "Schneider", "Marketing", "Designer", "Zürich", ""),
    ("ostuder", "Oliver", "Studer", "Legal", "General Counsel", "Bern", ""),
    ("vbucher", "Valérie", "Bucher", "Legal", "Legal Counsel", "Genève", ""),
    ("hsteiner", "Hans", "Steiner", "Management", "CEO", "Bern", ""),
    ("ebühler", "Eva", "Bühler", "Management", "Executive Assistant", "Bern", ""),
    ("mjäger", "Michael", "Jäger", "IT", "Security Officer", "Bern", ""),
    ("ahug", "Andrea", "Hug", "IT", "Software Engineer", "Zürich", ""),
    ("plüthi", "Patrick", "Lüthi", "IT", "Software Engineer", "Zürich", ""),
    ("ykoch", "Yvonne", "Koch", "Finance", "Payroll Specialist", "Bern", "n"),
    ("rblaser", "Rolf", "Blaser", "Facilities", "Facility Manager", "Bern", ""),
    ("tzürcher", "Thomas", "Zürcher", "Facilities", "Technician", "Zürich", "d"),
    ("mgonzalez", "María", "González", "Sales", "Account Manager", "Genève", ""),
    ("jdupont", "Jean", "Dupont", "Legal", "Paralegal", "Genève", ""),
]

OFFICES = {
    "Bern": ("Bundesgasse 10", "3011", "Bern", "+41 31 300 10"),
    "Zürich": ("Bahnhofstrasse 42", "8001", "Zürich", "+41 44 200 20"),
    "Genève": ("Rue du Rhône 8", "1204", "Genève", "+41 22 100 30"),
}

# group -> (description, direct members: logins or group names prefixed with '@', category)
GROUPS: dict[str, tuple[str, list[str], str]] = {
    "All Staff": ("Every employee (nested)", ["@IT", "@Finance", "@HR", "@Sales", "@Marketing", "@Legal", "@Management", "@Facilities"], "security"),
    "IT": ("IT department", ["@IT-Admins", "@IT-ServiceDesk", "@Developers", "mjäger"], "security"),
    "IT-Admins": ("Domain and server administrators", ["mmueller", "afischer", "jschmid"], "security"),
    "IT-ServiceDesk": ("First level support", ["lbrunner", "tkeller"], "security"),
    "Developers": ("Software engineering", ["ahug", "plüthi"], "security"),
    "Finance": ("Finance department", ["sgerber", "rweber", "nhuber", "pmeier", "ykoch"], "security"),
    "HR": ("Human resources", ["cbaumann", "dfrei", "ezimmermann"], "security"),
    "Sales": ("Sales department", ["mwyss", "jroth", "fmoser", "smoser", "bgraf", "mgonzalez"], "security"),
    "Marketing": ("Marketing department", ["lhofer", "kbaumgartner", "ischneider"], "security"),
    "Legal": ("Legal department", ["ostuder", "vbucher", "jdupont"], "security"),
    "Management": ("Executive board", ["hsteiner", "ebühler", "sgerber", "afischer"], "security"),
    "Facilities": ("Facility management", ["rblaser", "tzürcher"], "security"),
    "VPN-Users": ("Allowed to use the VPN", ["@IT", "@Sales", "hsteiner"], "security"),
    "DL-Newsletter": ("Internal newsletter distribution list", ["@All Staff"], "distribution"),
    "GL-Zürich-Office": ("Everybody located in Zürich", [p[0] for p in PEOPLE if p[5] == "Zürich"], "security"),
    "Empty-Group": ("A group without members", [], "security"),
}

GROUP_TYPE = {"security": -2147483646, "distribution": 2}  # global security / global distribution


def _group_dn(name: str) -> str:
    return f"CN={name},{GROUPS_OU}"


def _user_dn(first: str, last: str) -> str:
    return f"CN={first} {last},{USERS_OU}"


def build_entries() -> dict[str, dict]:
    rnd = random.Random(42)
    now = datetime(2026, 10, 17, 9, 30, tzinfo=timezone.utc)
    entries: dict[str, dict] = {}

    entries[BASE_DN] = {"objectClass": ["top", "domain", "domainDNS"], "dc": "demo", "name": "demo"}
    for dn, name in (
        (f"OU=Company,{BASE_DN}", "Company"),
        (USERS_OU, "Users"),
        (GROUPS_OU, "Groups"),
        (SERVICE_OU, "Service Accounts"),
        (COMPUTERS_OU, "Computers"),
    ):
        entries[dn] = {"objectClass": ["top", "organizationalUnit"], "ou": name, "name": name,
                       "description": f"{name} container"}

    entries[BIND_DN] = {
        "objectClass": ["top", "person", "organizationalPerson", "user"],
        "cn": "svc-ldapgrep", "name": "svc-ldapgrep", "sAMAccountName": "svc-ldapgrep",
        "userPassword": BIND_PASSWORD, "userAccountControl": 66048,
        "description": "Service account used by ldapgrep (demo)",
        "objectSid": _sid(5000), "whenCreated": _gen_time(now - timedelta(days=700)),
    }
    entries[f"CN=svc-backup,{SERVICE_OU}"] = {
        "objectClass": ["top", "person", "organizationalPerson", "user"],
        "cn": "svc-backup", "name": "svc-backup", "sAMAccountName": "svc-backup",
        "userAccountControl": 66048, "description": "Backup service account",
        "objectSid": _sid(5001), "whenCreated": _gen_time(now - timedelta(days=900)),
    }
    for i, host in enumerate(("WS-BERN-001", "WS-ZRH-002", "SRV-FILE-01")):
        entries[f"CN={host},{COMPUTERS_OU}"] = {
            "objectClass": ["top", "person", "organizationalPerson", "user", "computer"],
            "cn": host, "name": host, "sAMAccountName": f"{host}$", "userAccountControl": 4096,
            "dNSHostName": f"{host.lower()}.demo.example.com", "objectSid": _sid(6000 + i),
            "operatingSystem": "Windows 11 Enterprise" if host.startswith("WS") else "Windows Server 2022",
        }

    login_to_dn = {p[0]: _user_dn(p[1], p[2]) for p in PEOPLE}
    heads = {"IT": "afischer", "Finance": "sgerber", "HR": "cbaumann", "Sales": "mwyss", "Marketing": "lhofer",
             "Legal": "ostuder", "Management": "hsteiner", "Facilities": "cbaumann"}

    member_of: dict[str, list[str]] = {dn: [] for dn in login_to_dn.values()}
    group_members: dict[str, list[str]] = {}
    for gname, (_desc, members, _cat) in GROUPS.items():
        dns = []
        for m in members:
            dn = _group_dn(m[1:]) if m.startswith("@") else login_to_dn[m]
            dns.append(dn)
            member_of.setdefault(dn, []).append(_group_dn(gname))
        group_members[gname] = dns

    for idx, (login, first, last, dept, title, office, flags) in enumerate(PEOPLE):
        dn = login_to_dn[login]
        street, plz, city, tel_prefix = OFFICES[office]
        uac = 512
        if "d" in flags:
            uac |= 2
        if "p" in flags:
            uac |= 0x10000
        if "x" in flags:
            uac |= 0x800000
        created = now - timedelta(days=rnd.randint(30, 2500))
        last_logon = now - timedelta(days=rnd.randint(0, 40), hours=rnd.randint(0, 23)) if "d" not in flags else None
        pwd_set = now - timedelta(days=rnd.randint(1, 180))
        expires = (now - timedelta(days=3)) if "e" in flags else None
        manager = heads.get(dept)
        entry = {
            "objectClass": ["top", "person", "organizationalPerson", "user"],
            "cn": f"{first} {last}", "name": f"{first} {last}", "sn": last, "givenName": first,
            "displayName": f"{last}, {first}" if idx % 2 else f"{first} {last}",
            "sAMAccountName": login, "userPrincipalName": f"{login}@demo.example.com",
            "title": title, "department": dept, "company": "Demo Holding AG",
            "physicalDeliveryOfficeName": office, "streetAddress": street, "postalCode": plz, "l": city, "co": "Switzerland", "c": "CH",
            "telephoneNumber": f"{tel_prefix} {idx:02d}", "employeeID": f"E{1000 + idx}",
            "userAccountControl": uac, "primaryGroupID": 513,
            "accountExpires": _filetime(expires) if expires else 9223372036854775807,
            "lastLogon": _filetime(last_logon), "lastLogonTimestamp": _filetime(last_logon),
            "pwdLastSet": _filetime(pwd_set), "badPwdCount": 0,
            "whenCreated": _gen_time(created), "whenChanged": _gen_time(now - timedelta(days=rnd.randint(0, 20))),
            "objectSid": _sid(1100 + idx), "objectGUID": uuid.uuid5(uuid.NAMESPACE_DNS, login).bytes_le,
            "description": f"{title}, {dept}",
        }
        if "n" not in flags:
            entry["mail"] = f"{_ascii(first).lower()}.{_ascii(last).lower()}@demo.example.com"
        if idx % 3 == 0:
            entry["mobile"] = f"+41 79 {rnd.randint(100, 999)} {rnd.randint(10, 99)} {rnd.randint(10, 99)}"
        if "l" in flags:
            entry["lockoutTime"] = _filetime(now - timedelta(minutes=12))
            entry["badPwdCount"] = 5
        if "p" in flags:
            entry["msDS-UserPasswordExpiryTimeComputed"] = 9223372036854775807
        elif "x" in flags:
            entry["msDS-UserPasswordExpiryTimeComputed"] = _filetime(now - timedelta(days=2))
        else:
            entry["msDS-UserPasswordExpiryTimeComputed"] = _filetime(pwd_set + timedelta(days=90))
        if manager and manager != login:
            entry["manager"] = login_to_dn[manager]
        if member_of.get(dn):
            entry["memberOf"] = sorted(member_of[dn])
        entries[dn] = entry

    for gname, (desc, _members, cat) in GROUPS.items():
        dn = _group_dn(gname)
        entry = {
            "objectClass": ["top", "group"], "cn": gname, "name": gname, "sAMAccountName": gname,
            "description": desc, "groupType": GROUP_TYPE[cat],
            "objectSid": _sid(2000 + list(GROUPS).index(gname)),
            "whenCreated": _gen_time(now - timedelta(days=1000)),
            "managedBy": login_to_dn[heads.get(gname, "afischer")] if gname in heads else login_to_dn["afischer"],
        }
        if group_members[gname]:
            entry["member"] = sorted(group_members[gname])
        if member_of.get(dn):
            entry["memberOf"] = sorted(member_of[dn])
        if cat == "distribution":
            entry["mail"] = f"{gname.lower()}@demo.example.com"
        entries[dn] = entry

    # Domain Users as primary group (not in memberOf, like in real AD)
    entries[f"CN=Domain Users,CN=Users,{BASE_DN}"] = {
        "objectClass": ["top", "group"], "cn": "Domain Users", "name": "Domain Users",
        "sAMAccountName": "Domain Users", "groupType": -2147483646, "objectSid": _sid(513),
        "primaryGroupToken": 513, "description": "All domain users",
    }
    entries[f"CN=Users,{BASE_DN}"] = {"objectClass": ["top", "container"], "cn": "Users", "name": "Users"}
    return entries


def _ascii(text: str) -> str:
    import unicodedata

    return unicodedata.normalize("NFKD", text).encode("ascii", "ignore").decode("ascii")


def build_mock_connection() -> tuple[Server, Connection]:
    server = Server("demo.example.com", get_info=OFFLINE_AD_2012_R2)
    conn = Connection(server, user=BIND_DN, password=BIND_PASSWORD, client_strategy=MOCK_SYNC,
                      raise_exceptions=True, auto_referrals=False, read_only=True)
    for dn, attrs in build_entries().items():
        conn.strategy.add_entry(dn, attrs)
    return server, conn
