"""LDAP client layer built on ldap3.

Design goals:
  * works against Active Directory *and* generic LDAP (OpenLDAP, 389ds, Samba)
  * never crashes on missing attributes: requested attributes are intersected
    with the server schema, values are read through `Record.first()/get()`
  * every ldap3 exception is mapped to `LdapGrepError` with a useful message
  * paged searches everywhere (no 1000 entry limit)
"""

from __future__ import annotations

import logging
import math
import re
import socket
import ssl
import time
import unicodedata
import warnings
from dataclasses import dataclass, field
from collections import deque
from typing import Any, Iterable, Iterator

with warnings.catch_warnings():
    # ldap3 2.9.1 touches deprecated pyasn1 names on import
    warnings.simplefilter("ignore", DeprecationWarning)
    import ldap3
    from ldap3 import ALL, ANONYMOUS, BASE, DSA, LEVEL, NTLM, SIMPLE, SUBTREE, Connection, Server, Tls
    from ldap3.core import exceptions as ldap_exc
    from ldap3.utils.conv import escape_filter_chars
    from ldap3.utils.dn import parse_dn, safe_dn

from . import ad
from .attrs import BUILTIN_ATTRIBUTES
from .config import ConfigError, PUBLIC_PROFILES, Settings

log = logging.getLogger("ldapgrep")

EXIT_OK = 0
EXIT_NO_MATCH = 1
EXIT_USAGE = 2
EXIT_CONNECTION = 3
EXIT_LDAP = 4

AD_CAPABILITY_OID = "1.2.840.113556.1.4.800"
MATCHING_RULE_IN_CHAIN = "1.2.840.113556.1.4.1941"

USER_OBJECT_CLASSES = {"user", "person", "inetorgperson", "organizationalperson", "posixaccount", "account"}
GROUP_OBJECT_CLASSES = {"group", "groupofnames", "groupofuniquenames", "posixgroup", "groupofurls"}
COMPUTER_OBJECT_CLASSES = {"computer"}


class LdapGrepError(Exception):
    """Any error that should end in a clean message instead of a traceback."""

    def __init__(self, message: str, exit_code: int = EXIT_LDAP, hint: str | None = None):
        super().__init__(message)
        self.message = message
        self.exit_code = exit_code
        self.hint = hint

    def __str__(self) -> str:  # pragma: no cover - trivial
        return self.message if not self.hint else f"{self.message}\n  hint: {self.hint}"


class AmbiguousMatch(LdapGrepError):
    def __init__(self, what: str, candidates: list["Record"]):
        self.candidates = candidates
        names = ", ".join(c.display_name for c in candidates[:8])
        more = "" if len(candidates) <= 8 else f" (+{len(candidates) - 8} more)"
        super().__init__(
            f"{what} is ambiguous: {len(candidates)} matches: {names}{more}",
            EXIT_USAGE,
            "Use the full DN or a more specific name.",
        )


class _GroupBudgetError(LdapGrepError):
    pass


@dataclass
class _GroupBudget:
    settings: Settings
    queries: int = 0
    entries: int = 0
    page_size: int | None = None
    started: float = field(default_factory=lambda: time.monotonic())

    def __post_init__(self) -> None:
        for key in ("group_max_queries", "group_max_entries", "group_max_depth", "group_max_seconds"):
            value = getattr(self.settings, key)
            if not math.isfinite(value) or value <= 0:
                raise LdapGrepError(f"{key} must be finite and positive.", EXIT_USAGE)

    def fail(self, reason: str) -> None:
        raise _GroupBudgetError(f"Group traversal {reason} budget exhausted; result is incomplete.", EXIT_LDAP,
                                "Narrow the query or explicitly increase the group_max_* settings.")

    def remaining(self) -> float:
        seconds = self.settings.group_max_seconds - (time.monotonic() - self.started)
        if seconds <= 0:
            self.fail("time")
        return seconds

    def query(self) -> None:
        self.remaining()
        if self.queries >= self.settings.group_max_queries:
            self.fail("query")
        if self.entries >= self.settings.group_max_entries:
            self.fail("entry")
        self.queries += 1

    def entry(self) -> None:
        self.remaining()
        if self.entries >= self.settings.group_max_entries:
            self.fail("entry")
        self.entries += 1

    def depth(self, depth: int) -> None:
        self.remaining()
        if depth > self.settings.group_max_depth:
            self.fail("depth")


# --------------------------------------------------------------------------- #
# Record: case-insensitive, never-raising view on an LDAP entry
# --------------------------------------------------------------------------- #

@dataclass
class Record:
    dn: str
    _attrs: dict[str, tuple[str, list[Any]]] = field(default_factory=dict)  # lower -> (name, values)

    @classmethod
    def from_ldap3(cls, dn: str, attributes: dict[str, Any] | None, raw: dict[str, Any] | None = None) -> "Record":
        rec = cls(dn=dn or "")
        for name, value in (attributes or {}).items():
            values = value if isinstance(value, list) else ([] if value is None else [value])
            rec._attrs[name.lower()] = (name, list(values))
        # raw bytes for attributes ldap3 could not decode at all
        for name, value in (raw or {}).items():
            if name.lower() not in rec._attrs:
                values = value if isinstance(value, list) else [value]
                rec._attrs[name.lower()] = (name, list(values))
        return rec

    # ---- access ---------------------------------------------------------- #
    def has(self, attr: str) -> bool:
        return bool(self._attrs.get(attr.lower(), ("", []))[1])

    def get(self, attr: str) -> list[Any]:
        return list(self._attrs.get(attr.lower(), ("", []))[1])

    def first(self, attr: str, default: Any = "") -> Any:
        values = self._attrs.get(attr.lower(), ("", []))[1]
        if not values:
            return default
        v = values[0]
        if isinstance(v, (bytes, bytearray)):
            return ad.bytes_to_text(bytes(v))
        return v

    def text(self, attr: str, default: str = "") -> str:
        v = self.first(attr, None)
        if v is None:
            return default
        return str(v)

    def first_of(self, *attrs: str, default: Any = "") -> Any:
        for a in attrs:
            if self.has(a):
                return self.first(a)
        return default

    def names(self) -> list[str]:
        return sorted((name for name, _ in self._attrs.values()), key=str.lower)

    def items(self) -> Iterator[tuple[str, list[Any]]]:
        for lower in sorted(self._attrs):
            name, values = self._attrs[lower]
            yield name, list(values)

    def set(self, attr: str, values: list[Any]) -> None:
        self._attrs[attr.lower()] = (attr, list(values))

    # ---- semantics ------------------------------------------------------- #
    @property
    def object_classes(self) -> set[str]:
        return {str(c).lower() for c in self.get("objectClass")}

    @property
    def is_group(self) -> bool:
        return bool(self.object_classes & GROUP_OBJECT_CLASSES)

    @property
    def is_computer(self) -> bool:
        return bool(self.object_classes & COMPUTER_OBJECT_CLASSES)

    @property
    def is_user(self) -> bool:
        return bool(self.object_classes & USER_OBJECT_CLASSES) and not self.is_group and not self.is_computer

    @property
    def rdn_value(self) -> str:
        return rdn_value(self.dn)

    @property
    def login(self) -> str:
        return self.text("sAMAccountName") or self.text("uid") or self.text("userPrincipalName")

    @property
    def display_name(self) -> str:
        return self.text("displayName") or self.text("cn") or self.rdn_value or self.dn

    @property
    def disabled(self) -> bool:
        if self.has("userAccountControl"):
            return ad.is_disabled(self.first("userAccountControl"))
        # OpenLDAP ppolicy / 389ds
        if self.has("pwdAccountLockedTime"):
            return True
        if self.has("nsAccountLock"):
            return str(self.first("nsAccountLock")).lower() == "true"
        return False

    @property
    def locked(self) -> bool:
        return ad.is_locked(self.first("userAccountControl", None), self.first("lockoutTime", None))

    @property
    def password_expired(self) -> bool:
        return ad.is_password_expired(self.first("userAccountControl", None))


def rdn_value(dn: str) -> str:
    try:
        parts = parse_dn(dn, escape=False)
        return parts[0][1] if parts else dn
    except Exception:
        return dn.split(",")[0].split("=", 1)[-1] if dn else dn


def dn_parent(dn: str) -> str:
    try:
        parts = parse_dn(dn, escape=True)
        return ",".join(f"{k}={v}" for k, v, _ in parts[1:])
    except Exception:
        return dn.split(",", 1)[1] if "," in dn else ""


def looks_like_dn(value: str) -> bool:
    v = (value or "").strip()
    if "=" not in v:
        return False
    try:
        parse_dn(v)
        return True
    except Exception:
        return False


def is_broad_term(term: str) -> bool:
    """True for wildcard terms that can match (almost) the whole directory: '*', 'a*', '*x*', '?' ..."""
    t = (term or "").strip()
    if not t or looks_like_dn(t):
        return False
    if "*" not in t and "?" not in t:
        return False
    return len(t.replace("*", "").replace("?", "")) < 2


def ascii_fold(text: str) -> str:
    return unicodedata.normalize("NFKD", text).encode("ascii", "ignore").decode("ascii")


_DE_MAP = {"ä": "ae", "ö": "oe", "ü": "ue", "Ä": "Ae", "Ö": "Oe", "Ü": "Ue", "ß": "ss"}
_DE_REVERSE = (("ae", "ä"), ("oe", "ö"), ("ue", "ü"), ("Ae", "Ä"), ("Oe", "Ö"), ("Ue", "Ü"))


def german_variants(text: str) -> list[str]:
    """'Müller' -> ['Mueller'];  'mueller' -> ['müller'];  umlaut-free text -> []."""
    out: list[str] = []
    if any(ch in text for ch in _DE_MAP):
        out.append("".join(_DE_MAP.get(ch, ch) for ch in text))
    if any(d in text for d, _ in _DE_REVERSE):
        rev = text
        for digraph, umlaut in _DE_REVERSE:
            rev = rev.replace(digraph, umlaut)
        if rev != text:
            out.append(rev)
    return out


# --------------------------------------------------------------------------- #
# pre-flight connectivity check (DNS -> TCP port -> TLS), no LDAP bind
# --------------------------------------------------------------------------- #

@dataclass
class ProbeStep:
    name: str                       # dns | port | tls
    ok: bool
    detail: str = ""
    elapsed: float = 0.0


def probe_server(settings: Settings) -> Iterator[ProbeStep]:
    """Yield connectivity check steps for the configured server; stops after the first failure.
    Nothing is authenticated here - this only tests name resolution, the TCP port and,
    for ldaps://, the TLS handshake."""
    host, port = settings.host, settings.effective_port
    if not host:
        yield ProbeStep("dns", False, "no server configured")
        return

    started = time.perf_counter()
    try:
        infos = socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
        ips = sorted({i[4][0] for i in infos})
        yield ProbeStep("dns", True, f"{host} resolves to {', '.join(ips)}", time.perf_counter() - started)
    except OSError as exc:
        yield ProbeStep("dns", False, f"{host} does not resolve: {exc}", time.perf_counter() - started)
        return

    started = time.perf_counter()
    try:
        sock = socket.create_connection((host, port), timeout=settings.timeout)
    except OSError as exc:
        yield ProbeStep("port", False, f"{host}:{port} is not reachable: {exc}", time.perf_counter() - started)
        return
    yield ProbeStep("port", True, f"{host}:{port} accepts TCP connections", time.perf_counter() - started)

    if not settings.effective_ssl:
        sock.close()
        note = "StartTLS is negotiated inside the LDAP session; tested by the bind" if settings.start_tls \
            else "not used (plain ldap://)"
        yield ProbeStep("tls", True, note)
        return
    started = time.perf_counter()
    try:
        context = ssl.create_default_context(cafile=settings.ca_certs_file or None)
        if not settings.tls_verify:
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
        with context.wrap_socket(sock, server_hostname=host if settings.tls_verify else None) as tls_sock:
            detail = f"handshake OK ({tls_sock.version()})"
            if settings.tls_verify:
                cert = tls_sock.getpeercert()
                names = [v for part in cert.get("subjectAltName", ()) for k, v in [part] if k.lower() == "dns"]
                if names:
                    detail += f", certificate covers {', '.join(names[:3])}"
            else:
                detail += " - certificate NOT verified"
        yield ProbeStep("tls", True, detail, time.perf_counter() - started)
    except (ssl.SSLError, OSError) as exc:
        yield ProbeStep("tls", False, f"TLS handshake failed: {exc}", time.perf_counter() - started)


# --------------------------------------------------------------------------- #
# Flavor specific attribute map
# --------------------------------------------------------------------------- #

@dataclass
class Flavor:
    name: str                       # "ad" | "ldap"
    login_attr: str                 # sAMAccountName | uid
    user_filter: str
    group_filter: str
    member_attrs: tuple[str, ...]   # attributes on the group that list members
    memberof_attr: str              # attribute on the user listing groups ('' if none)
    supports_in_chain: bool = False
    supports_anr: bool = False
    search_attrs: tuple[str, ...] = ()


AD_FLAVOR = Flavor(
    name="ad",
    login_attr="sAMAccountName",
    user_filter="(&(objectClass=user)(!(objectClass=computer)))",
    group_filter="(objectClass=group)",
    member_attrs=("member",),
    memberof_attr="memberOf",
    supports_in_chain=True,
    supports_anr=True,
    search_attrs=("cn", "displayName", "sAMAccountName", "mail", "givenName", "sn", "userPrincipalName",
                  "employeeID", "employeeNumber"),
)

LDAP_FLAVOR = Flavor(
    name="ldap",
    login_attr="uid",
    user_filter="(|(objectClass=inetOrgPerson)(objectClass=posixAccount)(objectClass=person))",
    group_filter="(|(objectClass=groupOfNames)(objectClass=groupOfUniqueNames)(objectClass=posixGroup))",
    member_attrs=("member", "uniqueMember", "memberUid"),
    memberof_attr="memberOf",
    supports_in_chain=False,
    supports_anr=False,
    search_attrs=("cn", "displayName", "uid", "mail", "givenName", "sn", "employeeNumber"),
)


# --------------------------------------------------------------------------- #
# Client
# --------------------------------------------------------------------------- #

# naming contexts that are never the place where users and groups live
_OPERATIONAL_CONTEXTS = ("cn=config", "cn=schema", "cn=monitor", "cn=log", "cn=accesslog", "cn=changelog",
                         "o=netscaperoot", "cn=configuration,", "dc=domaindnszones,", "dc=forestdnszones,")


def is_active_directory(rootdse: dict[str, Any], vendor: str = "") -> bool:
    """Decide from (lower-cased) rootDSE attributes whether the server is Active Directory.
    389ds/FreeIPA also publish defaultNamingContext, so that alone is not enough."""
    caps = {str(c) for c in (rootdse.get("supportedcapabilities") or [])}
    if AD_CAPABILITY_OID in caps:
        return True
    if "forestfunctionality" in rootdse or "domainfunctionality" in rootdse:
        return True
    return "defaultnamingcontext" in rootdse and not vendor


def pick_base_dn(naming_contexts: list[str]) -> str:
    """Choose the search base from the rootDSE naming contexts: skip operational databases
    (config, schema, monitor, accesslog ...), prefer dc= style contexts, then the shortest one."""
    ncs = [x.strip() for x in naming_contexts if x and x.strip()]
    if not ncs:
        return ""
    real = [x for x in ncs if not x.lower().startswith(_OPERATIONAL_CONTEXTS)]
    pool = real or ncs
    dc_style = [x for x in pool if x.lower().startswith("dc=")]
    return sorted(dc_style or pool, key=len)[0]


def _chain(first: Any, rest: Iterator[Any]) -> Iterator[Any]:
    if first is not None:
        yield first
    yield from rest


class LdapClient:
    def __init__(self, settings: Settings, demo: bool = False):
        self.settings = settings
        self.demo = demo
        self.server: Server | None = None
        self.conn: Connection | None = None
        self.flavor: Flavor = AD_FLAVOR
        self.base_dn: str = settings.base_dn
        self.warnings: list[str] = []
        self._warned_attrs: set[str] = set()
        self.quiet_attributes: set[str] = set()
        self._schema_attrs: set[str] | None = None
        self._schema_classes: set[str] = set()
        self._scope_to_base = False      # FreeIPA: ignore memberOf entries outside cn=accounts
        self.connected = False
        self.bound_as: str = ""
        self.last_query: tuple[str, str, str] | None = None   # (base, scope, filter) of the latest search

    # ------------------------------------------------------------------ #
    # connection
    # ------------------------------------------------------------------ #
    def validate_connection_settings(self) -> None:
        """Reject unsafe targets before opening sockets or asking for credentials."""
        if self.demo:
            return
        s = self.settings
        if not s.server:
            raise LdapGrepError("No LDAP server configured.", EXIT_USAGE,
                                "Use --server ldaps://host, an explicit --config FILE, or --demo.")
        try:
            s.host
            s.effective_port
            encrypted = s.effective_ssl or s.start_tls
        except ConfigError as exc:
            raise LdapGrepError(str(exc), EXIT_USAGE) from exc
        if s.builtin_profile:
            preset = PUBLIC_PROFILES.get(s.builtin_profile)
            if preset is None or any(getattr(s, k) != preset.get(k, "")
                                     for k in ("server", "bind_dn", "bind_password", "auth")):
                raise LdapGrepError("Public profile target and credentials cannot be changed. "
                                    "Select Custom for a separate connection.", EXIT_USAGE)
        if s.auth != "anonymous" and not encrypted and not s.allow_plaintext_auth:
            raise LdapGrepError("Refusing authentication over unencrypted LDAP.", EXIT_USAGE,
                                "Use ldaps:// or --starttls. Only for isolated test networks, "
                                "explicitly opt in with --allow-plaintext-auth.")

    def connect(self) -> "LdapClient":
        self.validate_connection_settings()
        if self.demo:
            from . import mock_data

            self.server, self.conn = mock_data.build_mock_connection()
            try:
                self.conn.bind()
            except ldap_exc.LDAPException as exc:  # pragma: no cover
                raise LdapGrepError(f"Demo bind failed: {exc}", EXIT_CONNECTION) from exc
            self.bound_as = mock_data.BIND_DN
            # the offline schema carries a foreign rootDSE -> pin the demo tree explicitly
            self.base_dn = mock_data.BASE_DN
            self.settings.default_group_dn = mock_data.DEFAULT_GROUP_DN
            self.settings.groups_ou = mock_data.GROUPS_OU
            self.settings.users_ou = ""
            self._post_connect(force_flavor=AD_FLAVOR, disable_ad_extensions=True)
            return self

        s = self.settings
        if not s.server:
            raise LdapGrepError(
                "No LDAP server configured.",
                EXIT_USAGE,
                "Use --server ldaps://host, set LDAPGREP_SERVER or create ldap-grep.conf (see `ldapgrep config --example`).",
            )
        if s.auth != "anonymous" and not s.bind_dn:
            raise LdapGrepError("No bind user configured.", EXIT_USAGE,
                                "Use --bind-dn, LDAPGREP_BIND_DN or bind_dn in the config file (or --auth anonymous).")
        if s.auth != "anonymous" and not s.bind_password:
            raise LdapGrepError("No bind password available.", EXIT_USAGE,
                                "Use -W to be prompted, LDAPGREP_PASSWORD, bind_password_file or bind_password in the config.")

        tls = None
        if s.effective_ssl or s.start_tls:
            validate = ssl.CERT_REQUIRED if s.tls_verify else ssl.CERT_NONE
            tls = Tls(validate=validate, ca_certs_file=s.ca_certs_file or None, version=ssl.PROTOCOL_TLS_CLIENT)

        try:
            self.server = Server(
                s.host,
                port=s.effective_port,
                use_ssl=s.effective_ssl,
                tls=tls,
                get_info=ALL if s.load_schema else DSA,
                connect_timeout=s.timeout,
            )
        except ldap_exc.LDAPException as exc:
            raise LdapGrepError(f"Invalid server definition '{s.server}': {exc}", EXIT_USAGE) from exc

        auth = {"simple": SIMPLE, "ntlm": NTLM, "anonymous": ANONYMOUS}[s.auth]
        user = s.bind_dn if auth != ANONYMOUS else None
        password = s.bind_password if auth != ANONYMOUS else None
        if auth == NTLM and "\\" not in (user or ""):
            raise LdapGrepError("NTLM authentication needs bind_dn in the form DOMAIN\\username.", EXIT_USAGE)

        def open_and_bind() -> None:
            self.conn = Connection(
                self.server,
                user=user,
                password=password,
                authentication=auth,
                auto_bind=False,
                auto_referrals=False,
                raise_exceptions=True,
                receive_timeout=s.timeout,
                read_only=True,
                check_names=s.load_schema,
            )
            self.conn.open()
            if s.start_tls and not s.effective_ssl:
                if not self.conn.start_tls() or not self.conn.tls_started:
                    raise ldap_exc.LDAPStartTLSError("StartTLS did not establish a protected connection")
            if not self.conn.bind():
                raise ldap_exc.LDAPBindError("Server did not confirm the bind")

        try:
            try:
                open_and_bind()
            except ldap_exc.LDAPSocketReceiveError as exc:
                # some servers drop the very first TLS connection (seen with the FreeIPA demo): retry once
                log.info("connection dropped by the server (%s); retrying once", exc)
                time.sleep(0.5)
                open_and_bind()
        except ldap_exc.LDAPInvalidCredentialsResult as exc:
            raise LdapGrepError(f"Bind failed for '{s.bind_dn}': invalid credentials.", EXIT_CONNECTION,
                                _ad_bind_hint(str(exc))) from exc
        except ldap_exc.LDAPSocketOpenError as exc:
            msg = str(exc)
            hint = None
            if "CERTIFICATE_VERIFY_FAILED" in msg or "certificate verify failed" in msg.lower():
                hint = "Provide the trusted CA with --ca-file and verify that the configured hostname matches the certificate."
            elif "getaddrinfo" in msg or "Name or service not known" in msg or "11001" in msg:
                hint = "Host name could not be resolved. Check the server name / VPN."
            elif "timed out" in msg.lower() or "10060" in msg:
                hint = "Connection timed out. Check firewall, port (389/636) and --timeout."
            elif "refused" in msg.lower() or "10061" in msg:
                hint = "Connection refused. Is the port right (389 ldap / 636 ldaps)?"
            raise LdapGrepError(f"Cannot connect to {s.display_url}: {msg}", EXIT_CONNECTION, hint) from exc
        except ldap_exc.LDAPInvalidServerError as exc:
            raise LdapGrepError(f"Cannot connect to {s.display_url}: {exc}", EXIT_CONNECTION,
                                "Host name could not be resolved or the port is wrong. Check server name, DNS and VPN.") from exc
        except ldap_exc.LDAPStartTLSError as exc:
            msg = str(exc)
            if "CERTIFICATE_VERIFY_FAILED" in msg or "certificate verify failed" in msg.lower():
                hint = "Provide the trusted CA with --ca-file and verify that the configured hostname matches the certificate."
            else:
                hint = "Server might not support StartTLS; try ldaps:// instead."
            raise LdapGrepError(f"StartTLS failed: {exc}", EXIT_CONNECTION, hint) from exc
        except ldap_exc.LDAPStrongerAuthRequiredResult as exc:
            raise LdapGrepError(f"Server requires a secure connection: {exc}", EXIT_CONNECTION,
                                "Use ldaps://host:636 or --starttls.") from exc
        except ldap_exc.LDAPBindError as exc:
            raise LdapGrepError(f"Bind failed: {exc}", EXIT_CONNECTION) from exc
        except ldap_exc.LDAPException as exc:
            raise LdapGrepError(f"Cannot connect to {s.display_url}: {exc}", EXIT_CONNECTION) from exc
        except OSError as exc:
            raise LdapGrepError(f"Cannot connect to {s.display_url}: {exc}", EXIT_CONNECTION) from exc

        self.bound_as = s.bind_dn or "anonymous"
        forced = {"ad": AD_FLAVOR, "ldap": LDAP_FLAVOR}.get(s.flavor)
        self._post_connect(force_flavor=forced)
        return self

    def _post_connect(self, force_flavor: Flavor | None = None, disable_ad_extensions: bool = False) -> None:
        assert self.server is not None
        self.connected = True
        info = self.server.info
        # rootDSE attribute names come back in server spelling (389ds: 'defaultnamingcontext')
        other = {str(k).lower(): v for k, v in (dict(getattr(info, "other", {}) or {}) if info else {}).items()}
        vendor = " ".join(str(v) for v in (getattr(info, "vendor_name", None) or [])) if info else ""

        detected = AD_FLAVOR if is_active_directory(other, vendor) else LDAP_FLAVOR
        flavor = force_flavor or detected
        if disable_ad_extensions:
            flavor = Flavor(**{**flavor.__dict__, "supports_in_chain": False, "supports_anr": False})
        self.flavor = flavor

        auto_base = not self.base_dn
        if not self.base_dn:
            dnc = other.get("defaultnamingcontext")
            if dnc:
                self.base_dn = str(dnc[0] if isinstance(dnc, list) else dnc)
            elif info is not None and getattr(info, "naming_contexts", None):
                ncs = [str(x) for x in info.naming_contexts]
                self.base_dn = pick_base_dn(ncs)
            if not self.base_dn:
                raise LdapGrepError("Base DN could not be auto-detected.", EXIT_USAGE,
                                    "Set base_dn in the config or pass --base-dn DC=example,DC=com.")
            log.info("Auto-detected base DN: %s", self.base_dn)

        schema = getattr(self.server, "schema", None)
        if schema is not None and getattr(schema, "attribute_types", None):
            self._schema_attrs = {str(k).lower() for k in schema.attribute_types.keys()}
            classes: set[str] = set()
            for key, info in (getattr(schema, "object_classes", None) or {}).items():
                classes.add(str(key).lower())
                for alias in getattr(info, "name", None) or []:
                    classes.add(str(alias).lower())
            self._schema_classes = classes
            log.debug("Schema loaded: %d attribute types, %d object classes",
                      len(self._schema_attrs), len(self._schema_classes))
        else:
            self._schema_attrs = None
            if self.conn is not None:
                # without a schema ldap3 cannot validate names -> disable client side checks
                self.conn.check_names = False
            log.info("Schema not loaded; attribute names cannot be validated client side "
                     "(servers simply ignore unknown attributes in the request).")

        # FreeIPA: users/groups live under cn=accounts; cn=compat mirrors them (duplicates) and
        # cn=pbac holds thousands of groupOfNames permissions -> narrow the default base.
        if any(k.startswith("ipa") for k in other):
            if auto_base:
                accounts = f"cn=accounts,{self.base_dn}"
                try:
                    if self.get_entry(accounts, ["cn"]) is not None:
                        log.info("FreeIPA detected; using %s as search base", accounts)
                        self.base_dn = accounts
                except LdapGrepError:
                    pass
            # explicit or detected base inside cn=accounts -> hide memberOf entries outside it
            self._scope_to_base = "cn=accounts," in (self.base_dn.lower() + ",")

    def close(self) -> None:
        if self.conn is not None:
            try:
                self.conn.unbind()
            except Exception:  # pragma: no cover
                pass
        self.connected = False

    def __enter__(self) -> "LdapClient":
        return self.connect()

    def __exit__(self, *exc: Any) -> None:
        self.close()

    # ------------------------------------------------------------------ #
    # schema helpers
    # ------------------------------------------------------------------ #
    @property
    def schema_available(self) -> bool:
        return self._schema_attrs is not None

    def schema_attribute_names(self) -> list[str]:
        schema = getattr(self.server, "schema", None)
        if schema is None or not getattr(schema, "attribute_types", None):
            return []
        return sorted((str(k) for k in schema.attribute_types.keys()), key=str.lower)

    def known_attribute(self, attr: str) -> bool:
        if self._schema_attrs is None or attr in ("*", "+"):
            return True
        return attr.lower() in self._schema_attrs

    def filter_attributes(self, attrs: Iterable[str] | None) -> list[str] | None:
        """Drop attributes the server does not know (warning once per attribute)."""
        if attrs is None:
            return None
        wanted: list[str] = []
        seen: set[str] = set()
        for a in attrs:
            if not a or a.lower() in seen:
                continue
            seen.add(a.lower())
            if self.known_attribute(a):
                wanted.append(a)
            elif a.lower() in BUILTIN_ATTRIBUTES or a.lower() in self.quiet_attributes:
                log.debug("attribute %s not in schema (built-in, skipped silently)", a)
            elif a.lower() not in self._warned_attrs:
                self._warned_attrs.add(a.lower())
                msg = f"Attribute '{a}' is not defined in the server schema and was skipped."
                self.warnings.append(msg)
                log.warning(msg)
        return wanted or ["cn"]

    def filter_known(self, attrs: Iterable[str]) -> list[str]:
        return [a for a in attrs if self.known_attribute(a)]

    # ------------------------------------------------------------------ #
    # raw search
    # ------------------------------------------------------------------ #
    def search(
        self,
        search_filter: str,
        attributes: Iterable[str] | None = None,
        base: str | None = None,
        scope: str = SUBTREE,
        limit: int = 0,
        _budget: _GroupBudget | None = None,
    ) -> list[Record]:
        return list(self.iter_search(search_filter, attributes, base, scope, limit, _budget))

    _CLASS_TERM = re.compile(r"\(\s*objectClass\s*=\s*([^()*]+?)\s*\)", re.IGNORECASE)
    _NEVER = "(!(objectClass=*))"

    def sanitize_filter(self, search_filter: str) -> str:
        """Replace ``(objectClass=X)`` terms whose class the server schema does not know by a term
        that never matches.  ldap3 validates class names client side (check_names) and would otherwise
        reject the whole filter, e.g. ``(objectClass=container)`` on OpenLDAP.  Semantics are kept:
        a server without that class would not match such an entry either."""
        if not self._schema_classes or self.conn is None or not getattr(self.conn, "check_names", False):
            return search_filter

        def repl(match: re.Match[str]) -> str:
            name = match.group(1).strip()
            if name.lower() in self._schema_classes:
                return match.group(0)
            log.info("Object class %r is unknown to the server schema; treated as 'no match'", name)
            return self._NEVER

        return self._CLASS_TERM.sub(repl, search_filter)

    def _paged(self, base: str, search_filter: str, scope: str, attrs: list[str], page: int,
               budget: _GroupBudget | None = None):
        if budget is not None:
            # Count actual LDAP pages, not just calls to a paging generator.
            cookie = None
            while True:
                budget.query()
                original_timeout = self.conn.receive_timeout
                self.conn.receive_timeout = min(original_timeout or self.settings.timeout, budget.remaining())
                sock = self.conn.socket
                socket_timeout = sock.gettimeout() if isinstance(sock, socket.socket) else None
                if isinstance(sock, socket.socket):
                    sock.settimeout(min(socket_timeout or self.settings.timeout, budget.remaining()))
                try:
                    self.conn.search(base, search_filter, search_scope=scope, attributes=attrs,
                                     paged_size=min(page, budget.page_size or page,
                                                    self.settings.group_max_entries - budget.entries),
                                     paged_cookie=cookie, time_limit=max(1, math.ceil(budget.remaining())))
                finally:
                    self.conn.receive_timeout = original_timeout
                    if isinstance(sock, socket.socket) and sock.fileno() >= 0:
                        sock.settimeout(socket_timeout)
                budget.remaining()
                yield from self.conn.response or []
                cookie = (self.conn.result.get("controls", {}).get("1.2.840.113556.1.4.319", {})
                          .get("value", {}).get("cookie"))
                if not cookie:
                    return
        # NOTE: no server side size_limit here - with raise_exceptions=True ldap3 would raise
        # sizeLimitExceeded *before* yielding the last page.  We stop client side instead.
        yield from self.conn.extend.standard.paged_search(
            search_base=base,
            search_filter=search_filter,
            search_scope=scope,
            attributes=attrs,
            paged_size=page,
            generator=True,
        )

    def iter_search(
        self,
        search_filter: str,
        attributes: Iterable[str] | None = None,
        base: str | None = None,
        scope: str = SUBTREE,
        limit: int = 0,
        _budget: _GroupBudget | None = None,
    ) -> Iterator[Record]:
        if self.conn is None:
            raise LdapGrepError("Not connected.", EXIT_CONNECTION)
        base = base or self.base_dn
        search_filter = self.sanitize_filter(search_filter)
        attrs = self.filter_attributes(attributes)
        if attrs is None:
            attrs = ["*"]
        limit = int(limit or self.settings.size_limit or 0)
        self.last_query = (base, scope, search_filter)
        log.debug("search base=%s scope=%s filter=%s attrs=%s", base, scope, search_filter, attrs)

        count = 0
        yielded: set[str] = set()
        try:
            page = max(10, int(self.settings.page_size or 500))
            if limit:
                page = min(page, limit)
            try:
                gen = self._paged(base, search_filter, scope, attrs, page, _budget)
                first = next(gen, None)
            except (ldap_exc.LDAPObjectClassError, ldap_exc.LDAPAttributeError) as exc:
                # ldap3 rejected the filter client side (name unknown to the schema).  A real server
                # would simply not match such a term -> let the server decide from now on.
                if not getattr(self.conn, "check_names", False):
                    raise
                msg = (f"Filter uses a name unknown to the server schema ({exc}); "
                       "client side filter validation disabled, the server decides what matches.")
                self.warnings.append(msg)
                log.warning(msg)
                self.conn.check_names = False
                gen = self._paged(base, search_filter, scope, attrs, page, _budget)
                first = next(gen, None)
            for item in _chain(first, gen):
                if item.get("type") != "searchResEntry":
                    continue
                if _budget is not None:
                    _budget.entry()
                dn_key = str(item.get("dn", "")).lower()
                if dn_key in yielded:          # some servers (389ds compat plugin) repeat entries
                    continue
                rec = Record.from_ldap3(item.get("dn", ""), item.get("attributes"), item.get("raw_attributes"))
                if self._scope_to_base and rec.has("memberOf"):
                    rec.set("memberOf", [d for d in rec.get("memberOf") if self._in_base(str(d))])
                yield rec
                yielded.add(dn_key)
                count += 1
                if limit and count >= limit:
                    break
        except ldap_exc.LDAPNoSuchObjectResult as exc:
            raise LdapGrepError(f"Search base does not exist: {base}", EXIT_USAGE,
                                "Check base_dn / groups_ou / --base in your configuration.") from exc
        except (ldap_exc.LDAPSizeLimitExceededResult, ldap_exc.LDAPAdminLimitExceededResult,
                ldap_exc.LDAPTimeLimitExceededResult) as exc:
            # the server cut the result: salvage the entries of the page that came with the error
            for item in self._salvage_response():
                if _budget is not None:
                    _budget.entry()
                dn = str(item.get("dn", ""))
                if dn.lower() in yielded:
                    continue
                yield Record.from_ldap3(dn, item.get("attributes"), item.get("raw_attributes"))
                yielded.add(dn.lower())
                count += 1
                if limit and count >= limit:
                    break
            kind = {"LDAPSizeLimitExceededResult": "size", "LDAPAdminLimitExceededResult": "administrative",
                    "LDAPTimeLimitExceededResult": "time"}.get(type(exc).__name__, "server")
            msg = f"Server {kind} limit reached after {count} entries; result is incomplete."
            self.warnings.append(msg)
            log.warning(msg)
        except ldap_exc.LDAPInvalidDnError as exc:
            raise LdapGrepError(f"Invalid DN: {base} ({exc})", EXIT_USAGE) from exc
        except (ldap_exc.LDAPInvalidFilterError, ldap_exc.LDAPInvalidScopeError) as exc:
            raise LdapGrepError(f"Invalid LDAP filter: {search_filter} ({exc})", EXIT_USAGE) from exc
        except ldap_exc.LDAPAttributeError as exc:
            raise LdapGrepError(f"Attribute problem: {exc}", EXIT_USAGE,
                                "Use `ldapgrep schema` to list attributes the server knows.") from exc
        except ldap_exc.LDAPOperationsErrorResult as exc:
            hint = None
            if "bind must be completed" in str(exc).lower():
                hint = "This server does not allow anonymous queries; configure a bind user."
            raise LdapGrepError(f"LDAP operations error: {exc}", EXIT_LDAP, hint) from exc
        except ldap_exc.LDAPInsufficientAccessRightsResult as exc:
            raise LdapGrepError(f"Insufficient access rights: {exc}", EXIT_LDAP) from exc
        except ldap_exc.LDAPReferralResult as exc:  # pragma: no cover - depends on server
            raise LdapGrepError(f"Referral received: {exc}", EXIT_LDAP,
                                "Search a more specific base (e.g. the domain, not the forest root).") from exc
        except ldap_exc.LDAPSocketReceiveError as exc:
            raise LdapGrepError(f"Connection lost while reading results: {exc}", EXIT_CONNECTION) from exc
        except ldap_exc.LDAPException as exc:
            raise LdapGrepError(f"LDAP error: {type(exc).__name__}: {exc}", EXIT_LDAP) from exc

    def _salvage_response(self) -> list[dict[str, Any]]:
        """Entries ldap3 collected for the page that ended with a limit error."""
        try:
            response = getattr(self.conn, "response", None) or []
            return [r for r in response if isinstance(r, dict) and r.get("type") == "searchResEntry"]
        except Exception:  # pragma: no cover
            return []

    def get_entry(self, dn: str, attributes: Iterable[str] | None = None,
                  _budget: _GroupBudget | None = None) -> Record | None:
        try:
            res = self.search("(objectClass=*)", attributes, base=dn, scope=BASE, limit=1, _budget=_budget)
        except LdapGrepError as exc:
            if exc.exit_code == EXIT_USAGE and "does not exist" in exc.message:
                return None
            raise
        return res[0] if res else None

    # ------------------------------------------------------------------ #
    # filters
    # ------------------------------------------------------------------ #
    @staticmethod
    def escape(value: str) -> str:
        return escape_filter_chars(value)

    def _term_variants(self, term: str) -> list[str]:
        term = term.strip()
        variants = [term]
        for v in [ascii_fold(term), *german_variants(term)]:
            if v and v not in variants:
                variants.append(v)
        return variants

    def _match(self, attr: str, value: str, mode: str) -> str:
        v = self.escape(value)
        if mode == "exact":
            return f"({attr}={v})"
        if mode == "contains":
            return f"({attr}=*{v}*)"
        return f"({attr}={v}*)"

    def user_search_filter(self, term: str, mode: str = "prefix", extra_attrs: Iterable[str] = ()) -> str:
        """Build an OR filter over the common 'name like' attributes.

        * 'Max Müller' additionally matches givenName/sn combinations and
          displayName='Max Müller*'
        * umlauts are matched as typed and ASCII-folded
        * a term containing '@' is primarily an e-mail / UPN
        * '*' and '?' typed by the user are kept as wildcards
        """
        term = term.strip()
        if looks_like_dn(term):
            return f"(distinguishedName={self.escape(term)})" if self.flavor.name == "ad" else f"(entryDN={self.escape(term)})"

        attrs = [a for a in (*self.flavor.search_attrs, *extra_attrs) if self.known_attribute(a)]
        if not attrs:
            attrs = ["cn"]
        clauses: list[str] = []
        user_wildcards = "*" in term or "?" in term
        for variant in self._term_variants(term):
            if user_wildcards:
                v = self.escape(variant).replace("\\2a", "*").replace("\\3f", "?")
                clauses += [f"({a}={v})" for a in attrs]
                continue
            clauses += [self._match(a, variant, mode) for a in attrs]
            if mode != "exact" and self.flavor.supports_anr and " " not in variant:
                clauses.append(f"(anr={self.escape(variant)})")
            words = variant.split()
            if len(words) >= 2 and self.known_attribute("givenName") and self.known_attribute("sn"):
                first, last = words[0], " ".join(words[1:])
                clauses.append(f"(&{self._match('givenName', first, mode)}{self._match('sn', last, mode)})")
                clauses.append(f"(&{self._match('sn', first, mode)}{self._match('givenName', last, mode)})")
        return "(|" + "".join(clauses) + ")"

    def group_search_filter(self, term: str, mode: str = "prefix") -> str:
        term = term.strip()
        attrs = [a for a in ("cn", "name", "sAMAccountName", "displayName", "mail") if self.known_attribute(a)]
        clauses = []
        for variant in self._term_variants(term):
            clauses += [self._match(a, variant, mode) for a in attrs]
        return "(|" + "".join(clauses) + ")"

    @staticmethod
    def and_filters(*parts: str) -> str:
        parts = tuple(p for p in parts if p)
        if len(parts) == 1:
            return parts[0]
        return "(&" + "".join(parts) + ")"

    # ------------------------------------------------------------------ #
    # users
    # ------------------------------------------------------------------ #
    def _guard_broad(self, term: str, narrowed: bool, allow_broad: bool) -> None:
        """Protect large directories from accidental full dumps ('*', 'a*', ...).

        min_search_length >= 2 (the default) blocks such terms outright; below that the
        caller must confirm interactively and pass allow_broad=True.  A narrowing LDAP
        filter (--filter) counts as a deliberate restriction and lifts the guard."""
        if narrowed or not is_broad_term(term):
            return
        min_len = max(0, int(self.settings.min_search_length or 0))
        if min_len >= 2:
            raise LdapGrepError(
                f"'{term}': broad wildcard searches are blocked (min_search_length = {min_len}).",
                EXIT_USAGE,
                "Use at least 2 characters before the wildcard. To allow '*' searches anyway set "
                "min_search_length = 0 in the config - the CLI / GUI then asks for confirmation.",
            )
        if not allow_broad:
            raise LdapGrepError(
                f"'{term}' can match every entry of the directory and needs confirmation.",
                EXIT_USAGE,
                "Confirm the prompt of the CLI / GUI (or pass allow_broad=True when using ldapgrep as a library).",
            )

    def _user_query(
        self,
        term: str,
        mode: str,
        base: str | None,
        active_only: bool,
        extra_filter: str,
        include_computers: bool,
        allow_broad: bool,
    ) -> tuple[str, str]:
        """(filter, base) for user searches; shared by search_users and count_users."""
        min_len = max(0, int(self.settings.min_search_length or 0))
        bare = term.strip().replace("*", "").replace("?", "")
        list_all = term.strip() == "*"
        self._guard_broad(term, narrowed=bool(extra_filter), allow_broad=allow_broad)
        if not list_all and len(bare) < min_len and not looks_like_dn(term):
            raise LdapGrepError(f"Search term must have at least {min_len} characters.", EXIT_USAGE)
        base_filter = self.flavor.user_filter
        if self.flavor.name == "ad" and include_computers:
            base_filter = "(objectClass=user)"
        flt = self.and_filters(base_filter, "" if list_all else self.user_search_filter(term, mode), extra_filter)
        if active_only and self.flavor.name == "ad" and self.known_attribute("userAccountControl"):
            flt = self.and_filters(flt, "(!(userAccountControl:1.2.840.113556.1.4.803:=2))") \
                if self.flavor.supports_in_chain else flt
        return flt, base or self.settings.users_ou or self.base_dn

    def search_users(
        self,
        term: str,
        attributes: Iterable[str] | None,
        mode: str = "prefix",
        base: str | None = None,
        active_only: bool = False,
        limit: int = 0,
        extra_filter: str = "",
        include_computers: bool = False,
        allow_broad: bool = False,
        _budget: _GroupBudget | None = None,
    ) -> list[Record]:
        flt, base = self._user_query(term, mode, base, active_only, extra_filter, include_computers, allow_broad)
        results = self.search(flt, attributes, base=base, limit=limit, _budget=_budget)
        if active_only:
            results = [r for r in results if not r.disabled]
        return results

    def count_users(
        self,
        term: str,
        mode: str = "prefix",
        base: str | None = None,
        active_only: bool = False,
        extra_filter: str = "",
        include_computers: bool = False,
        allow_broad: bool = False,
    ) -> int:
        """Only the number of matching users; no attributes are requested or parsed."""
        flt, base = self._user_query(term, mode, base, active_only, extra_filter, include_computers, allow_broad)
        return self.count(flt, base=base)

    def find_user(self, identifier: str, attributes: Iterable[str] | None = None,
                  _budget: _GroupBudget | None = None) -> Record:
        """Resolve a login name, mail, UPN, DN or display name to exactly one user."""
        ident = identifier.strip()
        if looks_like_dn(ident):
            rec = self.get_entry(ident, attributes, _budget=_budget)
            if rec is None:
                raise LdapGrepError(f"User not found: {ident}", EXIT_NO_MATCH)
            return rec
        exact_attrs = [a for a in (self.flavor.login_attr, "mail", "userPrincipalName", "cn", "displayName")
                       if self.known_attribute(a)]
        flt = self.and_filters(self.flavor.user_filter,
                               "(|" + "".join(f"({a}={self.escape(ident)})" for a in exact_attrs) + ")")
        res = self.search(flt, attributes, base=self.settings.users_ou or self.base_dn, limit=10, _budget=_budget)
        if len(res) == 1:
            return res[0]
        if len(res) > 1:
            # several entries match exactly on *some* attribute (e.g. uid=joerg and cn=Joerg on another
            # entry): the login name, then mail / UPN decide
            for attr in (self.flavor.login_attr, "mail", "userPrincipalName"):
                hits = [r for r in res if ident.lower() in (v.lower() for v in r.get(attr) if isinstance(v, str))]
                if len(hits) == 1:
                    return hits[0]
            raise AmbiguousMatch(f"User '{ident}'", res)
        res = self.search_users(ident, attributes, mode="prefix", limit=10, _budget=_budget)
        if len(res) == 1:
            return res[0]
        if not res:
            raise LdapGrepError(f"User not found: {ident}", EXIT_NO_MATCH)
        raise AmbiguousMatch(f"User '{ident}'", res)

    # ------------------------------------------------------------------ #
    # groups
    # ------------------------------------------------------------------ #
    def find_group(self, identifier: str, attributes: Iterable[str] | None = None,
                   _budget: _GroupBudget | None = None) -> Record:
        ident = identifier.strip()
        attrs = list(attributes) if attributes is not None else ["cn", "objectClass", "description", "groupType"]
        if looks_like_dn(ident):
            rec = self.get_entry(ident, attrs, _budget=_budget)
            if rec is None:
                raise LdapGrepError(f"Group not found: {ident}", EXIT_NO_MATCH)
            return rec
        for mode in ("exact", "prefix"):
            flt = self.and_filters(self.flavor.group_filter, self.group_search_filter(ident, mode))
            res = self.search(flt, attrs, base=self.base_dn, limit=25, _budget=_budget)
            if len(res) == 1:
                return res[0]
            if len(res) > 1:
                exact = [r for r in res if r.text("cn").lower() == ident.lower() or r.login.lower() == ident.lower()]
                if len(exact) == 1:
                    return exact[0]
                raise AmbiguousMatch(f"Group '{ident}'", res)
        raise LdapGrepError(f"Group not found: {ident}", EXIT_NO_MATCH)

    def _group_query(self, pattern: str, mode: str, base: str | None, scope: str,
                     allow_broad: bool) -> tuple[str, str, str]:
        """(filter, base, scope) for group listings; shared by list_groups and count_groups."""
        self._guard_broad(pattern, narrowed=False, allow_broad=allow_broad)
        flt = self.flavor.group_filter
        if pattern and pattern != "*":
            flt = self.and_filters(flt, self.group_search_filter(pattern, mode))
        return flt, base or self.settings.groups_ou or self.base_dn, scope

    def list_groups(
        self,
        pattern: str = "",
        attributes: Iterable[str] | None = None,
        base: str | None = None,
        scope: str = SUBTREE,
        limit: int = 0,
        mode: str = "contains",
        allow_broad: bool = False,
    ) -> list[Record]:
        flt, base, scope = self._group_query(pattern, mode, base, scope, allow_broad)
        return self.search(flt, attributes, base=base, scope=scope, limit=limit)

    def count_groups(
        self,
        pattern: str = "",
        mode: str = "contains",
        base: str | None = None,
        scope: str = SUBTREE,
        allow_broad: bool = False,
    ) -> int:
        """Only the number of matching groups; no attributes are requested or parsed."""
        flt, base, scope = self._group_query(pattern, mode, base, scope, allow_broad)
        return self.count(flt, base=base, scope=scope)

    def group_members(
        self,
        group: Record | str,
        attributes: Iterable[str] | None,
        recursive: bool = False,
        active_only: bool = False,
        kind: str = "all",
        limit: int = 0,
        _visited: set[str] | None = None,
    ) -> list[Record]:
        """Bounded, iterative group expansion; an output limit stops further fetching."""
        budget = _GroupBudget(self.settings)
        grp = group if isinstance(group, Record) else self.find_group(group, _budget=budget)
        attrs = list(attributes) if attributes is not None else []
        for needed in ("objectClass", "userAccountControl", self.flavor.login_attr):
            if attrs and needed not in attrs and needed != "*":
                attrs.append(needed)
        limit = max(0, int(limit or self.settings.size_limit or 0))
        budget.page_size = limit or None
        members: list[Record] = []
        seen: set[str] = set()
        visited = set(_visited or ())
        queue = deque([(grp, 0)])
        while queue:
            current, depth = queue.popleft()
            if current.dn.lower() in visited:
                continue
            budget.depth(depth)
            visited.add(current.dn.lower())
            for member in self._direct_members(current, attrs, recursive, budget):
                budget.remaining()
                key = member.dn.lower()
                if key in seen:
                    continue
                seen.add(key)
                if recursive and not self.flavor.supports_in_chain and member.is_group and key not in visited:
                    queue.append((member, depth + 1))
                if kind == "users" and member.is_group:
                    continue
                if kind == "groups" and not member.is_group:
                    continue
                if active_only and not member.is_group and member.disabled:
                    continue
                members.append(member)
                if limit:
                    budget.page_size = max(1, limit - len(members))
                if limit and len(members) >= limit:
                    self.warnings.append("Group result limit reached; result may be incomplete.")
                    return sorted(members, key=lambda r: (r.is_group, r.display_name.lower()))
        return sorted(members, key=lambda r: (r.is_group, r.display_name.lower()))

    def _direct_members(self, grp: Record, attrs: list[str], recursive: bool,
                        budget: _GroupBudget) -> Iterator[Record]:
        found = False
        if self.flavor.memberof_attr and self.known_attribute(self.flavor.memberof_attr):
            if recursive and self.flavor.supports_in_chain:
                flt = f"({self.flavor.memberof_attr}:{MATCHING_RULE_IN_CHAIN}:={self.escape(grp.dn)})"
            else:
                flt = f"({self.flavor.memberof_attr}={self.escape(grp.dn)})"
            for rec in self.iter_search(flt, attrs or None, base=self.base_dn, _budget=budget):
                found = True
                yield rec
            if found or self.flavor.name == "ad":
                return
        yield from self._members_via_member_attribute(grp, attrs, budget)

    def _members_via_member_attribute(self, grp: Record, attrs: list[str],
                                     budget: _GroupBudget) -> Iterator[Record]:
        """Fetch fallback members lazily so stopping iteration stops LDAP work."""
        full = grp if any(grp.has(a) for a in self.flavor.member_attrs) else self.get_entry(
            grp.dn, [a for a in self.flavor.member_attrs if self.known_attribute(a)] + ["cn"], _budget=budget)
        if full is None:
            return
        seen: set[str] = set()
        for attr in self.flavor.member_attrs:
            for value in full.get(attr):
                budget.remaining()
                sval = str(value)
                if sval.lower() in seen:
                    continue
                seen.add(sval.lower())
                if attr.lower() == "memberuid":
                    yield from self.iter_search(f"({self.flavor.login_attr}={self.escape(sval)})",
                                                attrs or None, limit=1, _budget=budget)
                else:
                    rec = self.get_entry(sval, attrs or None, _budget=budget)
                    if rec is not None:
                        yield rec

    def user_groups(self, user: Record | str, recursive: bool = False,
                    attributes: Iterable[str] | None = None) -> list[Record]:
        """Groups a user belongs to.  Recursive = include groups of groups."""
        budget = _GroupBudget(self.settings)
        usr = user if isinstance(user, Record) else self.find_user(
            user, ["cn", "memberOf", "primaryGroupID", "objectClass"], _budget=budget)
        attrs = list(attributes) if attributes is not None else ["cn", "description", "groupType", "objectClass", "mail"]
        groups: list[Record] = []

        if recursive and self.flavor.supports_in_chain:
            flt = self.and_filters(self.flavor.group_filter,
                                   f"(member:{MATCHING_RULE_IN_CHAIN}:={self.escape(usr.dn)})")
            groups = self.search(flt, attrs, base=self.base_dn, _budget=budget)
        else:
            dns = [str(d) for d in usr.get(self.flavor.memberof_attr)] if self.flavor.memberof_attr else []
            if self._scope_to_base:
                # FreeIPA memberOf also lists permissions, roles, sudo/HBAC rules -> only real groups
                dns = [d for d in dns if self._in_base(d)]
            if not dns and not usr.has(self.flavor.memberof_attr):
                # memberOf not returned (not requested or not supported) -> search groups by member
                clauses = "".join(f"({a}={self.escape(usr.dn)})" for a in self.flavor.member_attrs if a.lower() != "memberuid")
                if usr.login and "memberUid" in self.flavor.member_attrs and self.known_attribute("memberUid"):
                    clauses += f"(memberUid={self.escape(usr.login)})"
                if clauses:
                    groups = self.search(self.and_filters(self.flavor.group_filter, f"(|{clauses})"), attrs, _budget=budget)
            else:
                groups = self._fetch_dns(dns, attrs, budget)
            if recursive:
                visited = {g.dn.lower() for g in groups}
                queue = [(g, 1) for g in groups]
                while queue:
                    g, depth = queue.pop()
                    budget.depth(depth)
                    parents = self._fetch_dns([str(d) for d in g.get(self.flavor.memberof_attr)], attrs, budget) \
                        if g.has(self.flavor.memberof_attr) else \
                        self.search(self.and_filters(self.flavor.group_filter,
                                                     "(|" + "".join(f"({a}={self.escape(g.dn)})" for a in self.flavor.member_attrs if a.lower() != "memberuid") + ")"),
                                    attrs, _budget=budget)
                    for p in parents:
                        if p.dn.lower() not in visited:
                            visited.add(p.dn.lower())
                            groups.append(p)
                            queue.append((p, depth + 1))

        # AD primary group (Domain Users) is not in memberOf
        if self.flavor.name == "ad" and usr.has("primaryGroupID") and self.known_attribute("primaryGroupToken"):
            rid = ad.to_int(usr.first("primaryGroupID"))
            if rid:
                try:
                    pg = self.search(f"(&(objectClass=group)(primaryGroupToken={rid}))", attrs, limit=1, _budget=budget)
                except _GroupBudgetError:
                    raise
                except LdapGrepError:
                    pg = []
                for p in pg:
                    if p.dn.lower() not in {g.dn.lower() for g in groups}:
                        p.set("primaryGroup", [True])
                        groups.append(p)
        if self._scope_to_base:
            groups = [g for g in groups if self._in_base(g.dn)]
        groups.sort(key=lambda r: r.display_name.lower())
        return groups

    def _fetch_dns(self, dns: list[str], attrs: list[str], budget: _GroupBudget) -> list[Record]:
        out: list[Record] = []
        if not dns:
            return out
        if self.flavor.name == "ad" and self.known_attribute("distinguishedName"):
            # batch lookup: 50 DNs per query
            for i in range(0, len(dns), 50):
                chunk = dns[i : i + 50]
                flt = "(|" + "".join(f"(distinguishedName={self.escape(d)})" for d in chunk) + ")"
                out += self.search(flt, attrs, base=self.base_dn, _budget=budget)
            if len(out) >= len(dns) * 0.5 or not dns:
                return out
            out = []
        for d in dns:
            rec = self.get_entry(d, attrs, _budget=budget)
            if rec is not None:
                out.append(rec)
            else:
                budget.entry()
                out.append(Record.from_ldap3(d, {"cn": [rdn_value(d)], "objectClass": ["group"]}))
        return out

    # ------------------------------------------------------------------ #
    # structure / meta
    # ------------------------------------------------------------------ #
    def _in_base(self, dn: str) -> bool:
        return dn.lower().endswith("," + self.base_dn.lower())

    def list_containers(self, base: str | None = None) -> list[Record]:
        base = base or self.base_dn
        flt = ("(|(objectClass=organizationalUnit)(objectClass=container)(objectClass=builtinDomain)"
               "(objectClass=nsContainer))")
        res = self.search(flt, ["ou", "cn", "name", "description", "objectClass"], base=base, scope=LEVEL)
        res = [r for r in res if r.dn.lower() != base.lower()]
        res.sort(key=lambda r: str(r.first_of("ou", "cn", "name")).lower())
        return res

    def count(self, search_filter: str, base: str | None = None, scope: str = SUBTREE) -> int:
        """Count matches only: requests no attributes ('1.1'), so entries are not decoded."""
        return sum(1 for _ in self.iter_search(search_filter, ["1.1"] if self.schema_available is False else ["objectClass"],
                                               base=base, scope=scope))

    def whoami(self) -> str:
        if self.conn is None:
            return ""
        try:
            res = self.conn.extend.standard.who_am_i()
            if res:
                return str(res)
        except Exception:
            pass
        return self.bound_as

    def server_info(self) -> dict[str, Any]:
        info = self.server.info if self.server is not None else None
        other = dict(getattr(info, "other", {}) or {}) if info else {}

        def one(key: str) -> Any:
            v = other.get(key)
            if isinstance(v, list):
                return v[0] if len(v) == 1 else v
            return v

        data: dict[str, Any] = {
            "server": self.settings.display_url if not self.demo else "demo (in-memory mock)",
            "bound_as": self.bound_as,
            "flavor": self.flavor.name,
            "base_dn": self.base_dn,
            "schema_loaded": self.schema_available,
            "schema_attribute_count": len(self._schema_attrs or []),
            "nested_group_queries": "server side (LDAP_MATCHING_RULE_IN_CHAIN)" if self.flavor.supports_in_chain else "client side recursion",
            "vendor": getattr(info, "vendor_name", None) if info else None,
            "vendor_version": getattr(info, "vendor_version", None) if info else None,
            "naming_contexts": list(getattr(info, "naming_contexts", []) or []) if info else [],
            "supported_ldap_versions": list(getattr(info, "supported_ldap_versions", []) or []) if info else [],
            "supported_sasl_mechanisms": list(getattr(info, "supported_sasl_mechanisms", []) or []) if info else [],
        }
        for key in ("dnsHostName", "defaultNamingContext", "rootDomainNamingContext", "configurationNamingContext",
                    "schemaNamingContext", "domainFunctionality", "forestFunctionality",
                    "domainControllerFunctionality", "currentTime", "serverName", "isGlobalCatalogReady", "ldapServiceName"):
            if key in other:
                data[key] = one(key)
        data["warnings"] = list(self.warnings)
        return {k: v for k, v in data.items() if v not in (None, [], "")}


def _ad_bind_hint(message: str) -> str | None:
    """Translate AD's sub error codes (data 52e etc.) to plain English."""
    m = message.lower()
    table = {
        "data 525": "user not found",
        "data 52e": "wrong password",
        "data 530": "login not permitted at this time",
        "data 531": "login not permitted from this workstation",
        "data 532": "password expired",
        "data 533": "account disabled",
        "data 701": "account expired",
        "data 773": "user must reset password",
        "data 775": "account locked out",
    }
    for code, text in table.items():
        if code in m:
            return f"AD reports: {text} ({code.replace('data ', '0x')})."
    return "Check bind_dn (DN, user@domain or DOMAIN\\user with --auth ntlm) and the password."
