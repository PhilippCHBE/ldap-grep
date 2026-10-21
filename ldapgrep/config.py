"""Configuration handling.

Precedence (lowest to highest):
    built-in defaults
    config file          ([LDAP] section = default profile, [profile:NAME] = named profiles)
    environment          (LDAPGREP_SERVER, LDAPGREP_BASE_DN, LDAPGREP_BIND_DN, LDAPGREP_PASSWORD, ...)
    command line         (--server, --base-dn, --bind-dn, --password, ...)

Config file lookup order (first hit wins unless --config / LDAPGREP_CONFIG is given):
    ~/.config/ldapgrep/ldap-grep.conf (or ldapgrep.conf)
    ~/.ldap-grep.conf               (or ~/.ldapgrep.conf)
    /etc/ldap-grep.conf             (or /etc/ldapgrep.conf; Unix only)

Project-local files require an explicit --config or LDAPGREP_CONFIG.
"""

from __future__ import annotations

import configparser
import math
import os
from dataclasses import dataclass, field, fields
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

DEFAULT_PROFILE = "LDAP"
ENV_PREFIX = "LDAPGREP_"


class ConfigError(Exception):
    """Raised for unusable configuration (exit code 2)."""


@dataclass
class Settings:
    """All tunables of ldapgrep.  Field names double as config keys."""

    server: str = field(default="", repr=False)  # ldap://host[:port] | ldaps://host[:port] | host
    port: int | None = None
    use_ssl: bool | None = None       # derived from the URL scheme when None
    start_tls: bool = False
    tls_verify: bool = True
    allow_plaintext_auth: bool = False  # explicit opt-in for isolated test networks only
    ca_certs_file: str = ""
    base_dn: str = ""                 # auto-detected from rootDSE when empty
    bind_dn: str = ""                 # DN, UPN (user@domain) or DOMAIN\\user for NTLM
    bind_password: str = field(default="", repr=False)
    bind_password_file: str = ""
    auth: str = "simple"              # simple | ntlm | anonymous
    timeout: float = 10.0
    page_size: int = 500
    size_limit: int = 0               # 0 = unlimited (paged)
    group_max_queries: int = 1000
    group_max_entries: int = 10000
    group_max_depth: int = 64
    group_max_seconds: float = 60.0
    default_group_dn: str = ""
    groups_ou: str = ""               # where `groups` looks by default; falls back to base_dn
    users_ou: str = ""                # where `user` looks by default; falls back to base_dn
    flavor: str = "auto"              # auto | ad | ldap
    load_schema: bool = True          # read the server schema (attribute validation; costs seconds on big ADs)
    user_extra_attributes: list[str] = field(default_factory=list)
    group_extra_attributes: list[str] = field(default_factory=list)
    date_format: str = "%d.%m.%Y %H:%M:%S"
    min_search_length: int = 2
    # bookkeeping
    config_file: str = ""
    fallback_profile: str = ""        # retained for compatibility; automatic public fallback was removed
    config_server: str = field(default="", repr=False)  # original server, for sanity warnings
    profile: str = DEFAULT_PROFILE
    builtin_profile: str = ""         # public presets never inherit ambient credentials

    # ------------------------------------------------------------------ #
    # derived helpers
    # ------------------------------------------------------------------ #
    @property
    def host(self) -> str:
        return parse_server_url(self.server)[0]

    @property
    def effective_port(self) -> int:
        host, port, ssl = parse_server_url(self.server)
        if self.port is not None:
            if not 1 <= int(self.port) <= 65535:
                raise ConfigError("port must be between 1 and 65535.")
            return int(self.port)
        if port is not None:
            return port
        return 636 if self.effective_ssl else 389

    @property
    def effective_ssl(self) -> bool:
        if self.use_ssl is not None:
            return bool(self.use_ssl)
        return parse_server_url(self.server)[2]

    @property
    def display_url(self) -> str:
        if not self.server:
            return "(not configured)"
        scheme = "ldaps" if self.effective_ssl else "ldap"
        return f"{scheme}://{self.host}:{self.effective_port}"

    def to_dict(self, hide_secrets: bool = True) -> dict[str, Any]:
        data = {}
        for f in fields(self):
            v = getattr(self, f.name)
            if hide_secrets and f.name == "bind_password" and v:
                v = "********"
            if f.name in ("server", "config_server"):
                v = redact_server_url(v)
            data[f.name] = v
        return data


def redact_server_url(value: str) -> str:
    """Also redact malformed/rejected URLs without parsing or exposing userinfo."""
    prefix, separator, rest = value.partition("://")
    if not separator:
        prefix, rest = "", value
    if "@" in rest:
        rest = "[redacted]@" + rest.rsplit("@", 1)[1]
    return (prefix + separator if separator else "") + rest


# ---------------------------------------------------------------------- #
# key aliases: alternative spellings -> Settings field
# ---------------------------------------------------------------------- #
KEY_ALIASES: dict[str, str] = {
    "ldap_server": "server",
    "server": "server",
    "url": "server",
    "host": "server",
    "port": "port",
    "use_ssl": "use_ssl",
    "ssl": "use_ssl",
    "start_tls": "start_tls",
    "starttls": "start_tls",
    "tls_verify": "tls_verify",
    "verify": "tls_verify",
    "allow_plaintext_auth": "allow_plaintext_auth",
    "ca_certs_file": "ca_certs_file",
    "ca_file": "ca_certs_file",
    "ca_cert": "ca_certs_file",
    "base_dn": "base_dn",
    "base": "base_dn",
    "bind_dn": "bind_dn",
    "user": "bind_dn",
    "username": "bind_dn",
    "bind_password": "bind_password",
    "password": "bind_password",
    "bind_password_file": "bind_password_file",
    "password_file": "bind_password_file",
    "auth": "auth",
    "authentication": "auth",
    "ldap_timeout": "timeout",
    "timeout": "timeout",
    "page_size": "page_size",
    "size_limit": "size_limit",
    "group_max_queries": "group_max_queries",
    "group_max_entries": "group_max_entries",
    "group_max_depth": "group_max_depth",
    "group_max_seconds": "group_max_seconds",
    "default_group_dn": "default_group_dn",
    "default_group": "default_group_dn",
    "groups_ou": "groups_ou",
    "users_ou": "users_ou",
    "flavor": "flavor",
    "flavour": "flavor",
    "server_type": "flavor",
    "load_schema": "load_schema",
    "schema": "load_schema",
    "user_extra_attributes": "user_extra_attributes",
    "user_attributes": "user_extra_attributes",
    "group_extra_attributes": "group_extra_attributes",
    "group_attributes": "group_extra_attributes",
    "date_format": "date_format",
    "min_search_length": "min_search_length",
}

_BOOL_FIELDS = {"use_ssl", "start_tls", "tls_verify", "load_schema", "allow_plaintext_auth"}
_INT_FIELDS = {"port", "page_size", "size_limit", "min_search_length",
               "group_max_queries", "group_max_entries", "group_max_depth"}
_FLOAT_FIELDS = {"timeout", "group_max_seconds"}
_LIST_FIELDS = {"user_extra_attributes", "group_extra_attributes"}


def parse_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    text = str(value).strip().lower()
    if text in ("1", "true", "yes", "on", "y"):
        return True
    if text in ("0", "false", "no", "off", "n"):
        return False
    raise ConfigError("Boolean settings must be true/false, yes/no, on/off or 1/0.")


def parse_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, (list, tuple)):
        return [str(x).strip() for x in value if str(x).strip()]
    parts = str(value).replace(";", ",").replace("\n", ",").split(",")
    return [p.strip() for p in parts if p.strip()]


def parse_server_url(server: str) -> tuple[str, int | None, bool]:
    """'ldaps://host:636' -> ('host', 636, True); bare 'host' -> ('host', None, False)."""
    s = (server or "").strip()
    if not s:
        return "", None, False
    if "://" not in s:
        s = "ldap://" + s
    try:
        u = urlparse(s)
        scheme = u.scheme.lower()
        host = u.hostname or ""
        port = u.port
    except ValueError as exc:
        raise ConfigError("Invalid LDAP server host or port.") from exc
    if scheme not in ("ldap", "ldaps"):
        raise ConfigError("Server URL scheme must be ldap:// or ldaps://.")
    if u.username is not None or u.password is not None:
        raise ConfigError("Server URLs must not contain credentials; use bind_dn and a password source.")
    if (not host or any(c.isspace() or ord(c) < 32 for c in host)
            or u.netloc.endswith(":") or u.path not in ("", "/") or u.query or u.fragment):
        raise ConfigError("Invalid LDAP server URL; specify only a host and optional port.")
    if port is not None and not 1 <= port <= 65535:
        raise ConfigError("Server port must be between 1 and 65535.")
    return host, port, scheme == "ldaps"


def coerce(field_name: str, value: Any) -> Any:
    if value is None:
        return None
    if field_name in _BOOL_FIELDS:
        try:
            return parse_bool(value)
        except ConfigError as exc:
            raise ConfigError(f"Invalid boolean setting '{field_name}': {exc}") from exc
    if field_name in _INT_FIELDS:
        try:
            return int(str(value).strip())
        except ValueError as exc:
            raise ConfigError(f"'{field_name}' must be an integer, got {value!r}") from exc
    if field_name in _FLOAT_FIELDS:
        try:
            return float(str(value).strip())
        except ValueError as exc:
            raise ConfigError(f"'{field_name}' must be a number, got {value!r}") from exc
    if field_name in _LIST_FIELDS:
        return parse_list(value)
    return str(value).strip()


def apply_mapping(settings: Settings, mapping: dict[str, Any]) -> None:
    """Apply a dict of raw key/values (any alias casing) onto settings."""
    for raw_key, raw_value in mapping.items():
        key = KEY_ALIASES.get(str(raw_key).strip().lower())
        if key is None:
            continue
        if raw_value is None or (isinstance(raw_value, str) and raw_value.strip() == ""):
            continue
        setattr(settings, key, coerce(key, raw_value))


# ---------------------------------------------------------------------- #
# file discovery
# ---------------------------------------------------------------------- #

CONFIG_NAMES = ("ldap-grep.conf", "ldapgrep.conf")


def candidate_config_files() -> list[Path]:
    home = Path.home()
    names = CONFIG_NAMES                      # ldap-grep.conf first, ldapgrep.conf as alternative
    candidates = [
        *(home / ".config" / "ldapgrep" / n for n in names),
        *(home / f".{n}" for n in names),
        *(Path("/etc") / n for n in names if os.name != "nt"),
    ]
    seen: set[Path] = set()
    unique: list[Path] = []
    for c in candidates:
        try:
            key = c.resolve()
        except OSError:
            key = c
        if key not in seen:
            seen.add(key)
            unique.append(c)
    return unique


def find_config_file(explicit: str | None = None) -> Path | None:
    if explicit:
        p = Path(explicit).expanduser()
        if not p.is_file():
            raise ConfigError(f"Config file not found: {p}")
        return p
    env = os.environ.get(ENV_PREFIX + "CONFIG")
    if env:
        p = Path(env).expanduser()
        if not p.is_file():
            raise ConfigError(f"Config file from {ENV_PREFIX}CONFIG not found: {p}")
        return p
    for c in candidate_config_files():
        if c.is_file():
            return c
    return None


# Built-in profiles for public test servers (see README "Trying it against public test servers").
# A profile of the same name in the config file wins.  They never inherit the [LDAP] section.
PUBLIC_PROFILES: dict[str, dict[str, Any]] = {
    "forumsys": {
        "server": "ldap://ldap.forumsys.com:389",
        "bind_dn": "cn=read-only-admin,dc=example,dc=com",
        "bind_password": "password",
        "base_dn": "dc=example,dc=com",
        "auth": "simple",
    },
    "debian": {
        "server": "ldap://db.debian.org:389",
        "auth": "anonymous",
        "base_dn": "dc=debian,dc=org",
    },
    "freeipa": {
        # port 636 of the demo drops connections now and then; StartTLS on 389 is reliable
        "server": "ldap://ipa.demo1.freeipa.org:389",
        "start_tls": True,
        "bind_dn": "uid=admin,cn=users,cn=accounts,dc=demo1,dc=freeipa,dc=org",
        "bind_password": "Secret123",
        "auth": "simple",
    },
}


def all_profiles(path: Path | None) -> list[tuple[str, str]]:
    """(name, source) for every selectable profile: config file ones first, then built-ins
    that are not shadowed by the file."""
    out: list[tuple[str, str]] = []
    if path:
        out += [(n, "config") for n in list_profiles(path)]
    taken = {n.lower() for n, _ in out}
    out += [(n, "built-in") for n in PUBLIC_PROFILES if n not in taken]
    return out


def profile_settings(path: Path | None, name: str) -> "Settings":
    """Settings of one profile (file or built-in), without environment and command line."""
    skip = name.lower() in PUBLIC_PROFILES and not (path and name.lower() in {n.lower() for n in list_profiles(path)})
    return load_settings(str(path) if path else None, name, use_env=False, skip_config=skip, demo=True)


def list_profiles(path: Path | None) -> list[str]:
    if not path:
        return [DEFAULT_PROFILE]
    cp = configparser.ConfigParser(interpolation=None)
    try:
        cp.read(path, encoding="utf-8")
    except (configparser.Error, OSError):
        return [DEFAULT_PROFILE]
    names = []
    if cp.has_section(DEFAULT_PROFILE):
        names.append(DEFAULT_PROFILE)
    for s in cp.sections():
        if s.lower().startswith("profile:"):
            names.append(s.split(":", 1)[1].strip())
    return names or [DEFAULT_PROFILE]


def read_config_file(path: Path, profile: str | None) -> dict[str, Any]:
    cp = configparser.ConfigParser(interpolation=None)
    try:
        cp.read(path, encoding="utf-8")
    except configparser.Error as exc:
        raise ConfigError(f"Cannot parse config file {path}: {exc}") from exc
    except OSError as exc:
        raise ConfigError(f"Cannot read config file {path}: {exc}") from exc

    data: dict[str, Any] = {}
    # [LDAP] (or [ldapgrep]) acts as the default profile and as the base of named profiles
    for base_section in (DEFAULT_PROFILE, "ldapgrep", "default"):
        for sec in cp.sections():
            if sec.lower() == base_section.lower():
                data.update(cp.items(sec))
    if profile and profile.upper() != DEFAULT_PROFILE:
        wanted = f"profile:{profile}".lower()
        match = next((s for s in cp.sections() if s.lower() == wanted), None)
        if match is None:
            available = ", ".join(list_profiles(path))
            raise ConfigError(f"Profile '{profile}' not found in {path}. Available: {available}; "
                              f"built-in: {', '.join(PUBLIC_PROFILES)}")
        data.update(cp.items(match))
    return data


def read_env() -> dict[str, Any]:
    data = {}
    for k, v in os.environ.items():
        if k.upper().startswith(ENV_PREFIX) and k.upper() != ENV_PREFIX + "CONFIG":
            data[k[len(ENV_PREFIX):].lower()] = v
    return data


def load_settings(
    config_path: str | None = None,
    profile: str | None = None,
    overrides: dict[str, Any] | None = None,
    use_env: bool = True,
    skip_config: bool = False,
    demo: bool = False,
) -> Settings:
    """Build the effective Settings object.

    skip_config=True ignores every config file (--no-config).  A profile name that the config file
    does not define but PUBLIC_PROFILES does selects that built-in profile (without the [LDAP] section).
    Public presets ignore environment overrides and reject identity/target overrides. Missing
    servers stay unconfigured: the TUI asks for a target and the client refuses to connect.
    """
    settings = Settings()
    path = None if skip_config else find_config_file(config_path)
    builtin = None
    if profile and profile.lower() in PUBLIC_PROFILES:
        in_file = bool(path) and profile.lower() in {n.lower() for n in list_profiles(path)}
        if not in_file:
            builtin = profile.lower()
    if builtin:
        apply_mapping(settings, PUBLIC_PROFILES[builtin])
        settings.builtin_profile = builtin
        restricted = {"server", "port", "use_ssl", "bind_dn", "bind_password", "bind_password_file", "auth"}
        for key, value in (overrides or {}).items():
            if KEY_ALIASES.get(key.lower()) in restricted and value is not None:
                raise ConfigError("Built-in public profiles cannot be combined with target or credential overrides. "
                                  "Use a separate explicit configuration for a custom connection.")
        if path:
            settings.config_file = str(path)      # for information only; nothing of it is applied
    elif path:
        settings.config_file = str(path)
        apply_mapping(settings, read_config_file(path, profile))
        settings.config_server = str(settings.server or "")
    elif profile and profile.upper() != DEFAULT_PROFILE:
        raise ConfigError(f"Profile '{profile}' requested but no config file was found. "
                          f"Built-in profiles: {', '.join(PUBLIC_PROFILES)}")
    if use_env and not builtin:
        apply_mapping(settings, read_env())
    if overrides:
        apply_mapping(settings, {k: v for k, v in overrides.items() if v is not None})
    settings.profile = profile or DEFAULT_PROFILE

    # password file
    if settings.server and not settings.bind_password and settings.bind_password_file and not demo:
        pf = Path(settings.bind_password_file).expanduser()
        try:
            settings.bind_password = pf.read_text(encoding="utf-8").strip()
        except OSError as exc:
            raise ConfigError(f"Cannot read password file {pf}: {exc}") from exc

    settings.auth = (settings.auth or "simple").lower()
    if settings.auth not in ("simple", "ntlm", "anonymous"):
        raise ConfigError(f"auth must be simple, ntlm or anonymous (got {settings.auth!r})")
    settings.flavor = (settings.flavor or "auto").lower()
    if settings.flavor not in ("auto", "ad", "ldap"):
        raise ConfigError(f"flavor must be auto, ad or ldap (got {settings.flavor!r})")
    for key in ("group_max_queries", "group_max_entries", "group_max_depth", "group_max_seconds"):
        value = getattr(settings, key)
        if not math.isfinite(value) or value <= 0:
            raise ConfigError(f"{key} must be a finite positive number.")
    if settings.server and not demo:
        # Validate before any DNS/TCP connection, password prompt or diagnostics.
        parse_server_url(settings.server)
        settings.effective_port
    return settings


EXAMPLE_CONFIG = """\
# ldapgrep configuration
# Keys are case-insensitive. Common alternative spellings (host, base, username, ...) work too.
# Precedence: this file < environment (LDAPGREP_*) < command line options.

[LDAP]
# ldap://host:389, ldaps://host:636 or just a host name
server = ldaps://dc01.example.com:636

# Leave empty to auto-detect from the server (rootDSE defaultNamingContext).
base_dn = DC=example,DC=com

# Bind identity: a DN, a UPN (user@example.com) or DOMAIN\\user together with auth = ntlm.
bind_dn = CN=svc-ldapgrep,OU=Service Accounts,DC=example,DC=com

# Password options (pick one; or omit all and you will be prompted):
#   bind_password      = secret
#   bind_password_file = /etc/ldapgrep.secret
#   environment:         LDAPGREP_PASSWORD=secret
bind_password =

# simple | ntlm | anonymous
auth = simple
# Use false only for isolated test servers (or --insecure).
tls_verify = true
# PEM bundle with your internal CA
ca_certs_file =
# Upgrade ldap:// to TLS before authentication.
start_tls = false
# Unsafe: enable only for isolated plaintext test networks.
allow_plaintext_auth = false

timeout = 10
page_size = 500

# Shared budgets per group/memberof traversal, including paged requests.
# All must be positive; exhausting a budget returns an explicit incomplete-result error.
group_max_queries = 1000
group_max_entries = 10000
group_max_depth = 64
group_max_seconds = 60

# Optional defaults
default_group_dn = CN=All Staff,OU=Groups,DC=example,DC=com
groups_ou = OU=Groups,DC=example,DC=com
users_ou =

# auto | ad | ldap   (ldap = OpenLDAP / 389ds / Samba without AD schema)
flavor = auto

# Reading the schema lets ldapgrep validate attribute names and decode values nicely,
# but costs a few seconds per call on large directories. Set false (or use --no-schema) to skip it.
load_schema = true

# Company specific attributes that should be shown in --view detail/full
user_extra_attributes = employeeID, division, company, manager
group_extra_attributes = managedBy, info

date_format = %d.%m.%Y %H:%M:%S
min_search_length = 2

# Additional environments: select with --profile test
[profile:test]
server = ldaps://dc-test.example.com
base_dn = DC=test,DC=example,DC=com
bind_dn = CN=svc-ldapgrep,OU=Service Accounts,DC=test,DC=example,DC=com
tls_verify = true

# Built-in profiles for public test servers need no entry here:
#   --profile forumsys   ldap.forumsys.com (OpenLDAP, read-only demo account)
#   --profile debian     db.debian.org (OpenLDAP, anonymous)
#   --profile freeipa    ipa.demo1.freeipa.org (FreeIPA demo, self-signed certificate)
# No server configured: no connection is made; use --demo for an offline demonstration.
# Public profiles ignore LDAPGREP_* overrides. Forumsys requires --allow-plaintext-auth;
# FreeIPA requires a trusted CA (--ca-file), or explicitly --insecure for its demo certificate.
# A [profile:forumsys] section in this file would replace the built-in one.
"""
