"""Decoders for Active Directory specific value encodings.

Everything in here is defensive: a value that cannot be decoded is returned
unchanged (or as an empty string / None), never raised.  Values may arrive
already decoded by ldap3 (int, datetime, str) when the server schema was
readable, or as raw str/bytes when it was not - both are handled.
"""

from __future__ import annotations

import base64
import struct
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Iterable

# --------------------------------------------------------------------------- #
# userAccountControl
# --------------------------------------------------------------------------- #

UAC_FLAGS: dict[int, str] = {
    0x0001: "SCRIPT",
    0x0002: "ACCOUNTDISABLE",
    0x0008: "HOMEDIR_REQUIRED",
    0x0010: "LOCKOUT",
    0x0020: "PASSWD_NOTREQD",
    0x0040: "PASSWD_CANT_CHANGE",
    0x0080: "ENCRYPTED_TEXT_PWD_ALLOWED",
    0x0100: "TEMP_DUPLICATE_ACCOUNT",
    0x0200: "NORMAL_ACCOUNT",
    0x0800: "INTERDOMAIN_TRUST_ACCOUNT",
    0x1000: "WORKSTATION_TRUST_ACCOUNT",
    0x2000: "SERVER_TRUST_ACCOUNT",
    0x10000: "DONT_EXPIRE_PASSWORD",
    0x20000: "MNS_LOGON_ACCOUNT",
    0x40000: "SMARTCARD_REQUIRED",
    0x80000: "TRUSTED_FOR_DELEGATION",
    0x100000: "NOT_DELEGATED",
    0x200000: "USE_DES_KEY_ONLY",
    0x400000: "DONT_REQ_PREAUTH",
    0x800000: "PASSWORD_EXPIRED",
    0x1000000: "TRUSTED_TO_AUTH_FOR_DELEGATION",
    0x4000000: "PARTIAL_SECRETS_ACCOUNT",
}

UAC_ACCOUNTDISABLE = 0x0002
UAC_LOCKOUT = 0x0010
UAC_DONT_EXPIRE_PASSWORD = 0x10000
UAC_PASSWORD_EXPIRED = 0x800000


def to_int(value: Any, default: int | None = None) -> int | None:
    """Best effort int conversion for LDAP values (int, str, bytes, list)."""
    if isinstance(value, (list, tuple)):
        value = value[0] if value else None
    if value is None or value == "":
        return default
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    if isinstance(value, bytes):
        try:
            value = value.decode("utf-8", "ignore")
        except Exception:  # pragma: no cover - extremely defensive
            return default
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return default


def decode_uac(value: Any) -> list[str]:
    """Return the symbolic flag names set in a userAccountControl value."""
    uac = to_int(value)
    if uac is None:
        return []
    return [name for bit, name in UAC_FLAGS.items() if uac & bit]


def is_disabled(uac_value: Any) -> bool:
    """True when ACCOUNTDISABLE is set.  Missing/invalid value -> False (enabled)."""
    uac = to_int(uac_value)
    return bool(uac & UAC_ACCOUNTDISABLE) if uac is not None else False


def is_locked(uac_value: Any, lockout_time: Any = None) -> bool:
    """AD rarely sets the LOCKOUT bit; lockoutTime != 0 is the reliable signal."""
    uac = to_int(uac_value)
    if uac is not None and uac & UAC_LOCKOUT:
        return True
    lt = filetime_to_datetime(lockout_time)
    return lt is not None


def is_password_expired(uac_value: Any) -> bool:
    """True when PASSWORD_EXPIRED is set.  Missing/invalid value -> False."""
    uac = to_int(uac_value)
    return bool(uac & UAC_PASSWORD_EXPIRED) if uac is not None else False


# --------------------------------------------------------------------------- #
# groupType
# --------------------------------------------------------------------------- #

GROUP_TYPE_SCOPES = {
    0x00000001: "builtin-local",
    0x00000002: "global",
    0x00000004: "domain-local",
    0x00000008: "universal",
}
GROUP_TYPE_SECURITY = 0x80000000


def decode_group_type(value: Any) -> dict[str, str]:
    """Return {'scope': 'global', 'category': 'security'} for an AD groupType."""
    gt = to_int(value)
    if gt is None:
        return {}
    gt &= 0xFFFFFFFF
    scope = next((n for bit, n in GROUP_TYPE_SCOPES.items() if gt & bit), "unknown")
    category = "security" if gt & GROUP_TYPE_SECURITY else "distribution"
    return {"scope": scope, "category": category}


# --------------------------------------------------------------------------- #
# Timestamps
# --------------------------------------------------------------------------- #

FILETIME_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)
FILETIME_NEVER = 0x7FFFFFFFFFFFFFFF
# ldap3 maps FILETIME_NEVER to this when the schema is loaded
_LDAP3_NEVER_YEAR = 9999


def filetime_to_datetime(value: Any) -> datetime | None:
    """Convert a Windows FILETIME (100ns ticks since 1601) to an aware datetime.

    Returns None for 0 / empty / unparsable / 'never' values.
    Accepts ints, numeric strings, bytes, lists, and datetimes (passed through).
    """
    if isinstance(value, (list, tuple)):
        value = value[0] if value else None
    if value is None:
        return None
    if isinstance(value, datetime):
        if value.year >= _LDAP3_NEVER_YEAR or value.year <= 1601:
            return None
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    ft = to_int(value)
    if ft is None or ft <= 0 or ft >= FILETIME_NEVER:
        return None
    try:
        return FILETIME_EPOCH + timedelta(microseconds=ft // 10)
    except (OverflowError, ValueError):
        return None


def is_never(value: Any) -> bool:
    """True for accountExpires style 'never expires' sentinels (0 or max int)."""
    if isinstance(value, (list, tuple)):
        value = value[0] if value else None
    if isinstance(value, datetime):
        return value.year >= _LDAP3_NEVER_YEAR
    ft = to_int(value)
    return ft is None or ft == 0 or ft >= FILETIME_NEVER


def generalized_time_to_datetime(value: Any) -> datetime | None:
    """Parse an LDAP GeneralizedTime such as '20240101120000.0Z' or '20240101120000Z'."""
    if isinstance(value, (list, tuple)):
        value = value[0] if value else None
    if value is None:
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if isinstance(value, bytes):
        value = value.decode("ascii", "ignore")
    s = str(value).strip()
    if not s:
        return None
    # strip fractional seconds and trailing Z / offset
    main = s
    tz = timezone.utc
    if main.endswith("Z"):
        main = main[:-1]
    elif len(main) > 5 and main[-5] in "+-" and main[-4:].isdigit():
        sign = 1 if main[-5] == "+" else -1
        hh, mm = int(main[-4:-2]), int(main[-2:])
        tz = timezone(sign * timedelta(hours=hh, minutes=mm))
        main = main[:-5]
    main = main.split(".")[0].split(",")[0]
    for fmt in ("%Y%m%d%H%M%S", "%Y%m%d%H%M", "%Y%m%d%H"):
        try:
            return datetime.strptime(main, fmt).replace(tzinfo=tz)
        except ValueError:
            continue
    return None


def format_datetime(dt: datetime | None, fmt: str = "%d.%m.%Y %H:%M:%S", local: bool = True) -> str:
    """Format an aware datetime; '' for None.  Converts to local time by default."""
    if dt is None:
        return ""
    try:
        if local and dt.tzinfo is not None:
            dt = dt.astimezone()
        return dt.strftime(fmt)
    except (ValueError, OverflowError, OSError):
        return dt.isoformat()


# --------------------------------------------------------------------------- #
# Binary identifiers
# --------------------------------------------------------------------------- #

def sid_to_str(value: Any) -> str:
    """Convert a binary objectSid to 'S-1-5-21-...'.  Strings are returned as-is."""
    if isinstance(value, (list, tuple)):
        value = value[0] if value else None
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    if not isinstance(value, (bytes, bytearray)) or len(value) < 8:
        return str(value)
    try:
        revision = value[0]
        sub_count = value[1]
        authority = int.from_bytes(value[2:8], "big")
        subs = struct.unpack("<%dI" % sub_count, value[8 : 8 + 4 * sub_count])
        return "S-%d-%d%s" % (revision, authority, "".join("-%d" % s for s in subs))
    except (struct.error, IndexError, ValueError):
        return base64.b64encode(bytes(value)).decode("ascii")


def guid_to_str(value: Any) -> str:
    """Convert a binary objectGUID to canonical UUID text."""
    if isinstance(value, (list, tuple)):
        value = value[0] if value else None
    if value is None:
        return ""
    if isinstance(value, uuid.UUID):
        return str(value)
    if isinstance(value, str):
        return value.strip("{}")
    if isinstance(value, (bytes, bytearray)) and len(value) == 16:
        try:
            return str(uuid.UUID(bytes_le=bytes(value)))
        except ValueError:
            pass
    if isinstance(value, (bytes, bytearray)):
        return base64.b64encode(bytes(value)).decode("ascii")
    return str(value)


def bytes_to_text(value: bytes) -> str:
    """UTF-8 if it decodes cleanly, otherwise base64 (for photos, certificates...)."""
    try:
        text = value.decode("utf-8")
    except UnicodeDecodeError:
        return "base64:" + base64.b64encode(value).decode("ascii")
    # control characters are a strong hint for binary content
    if any(ord(c) < 32 and c not in "\t\r\n" for c in text):
        return "base64:" + base64.b64encode(value).decode("ascii")
    return text


# attributes whose values are binary SIDs / GUIDs on AD
SID_ATTRIBUTES = {"objectsid", "sidhistory", "tokengroups", "tokengroupsglobalanduniversal", "securityidentifier"}
GUID_ATTRIBUTES = {"objectguid", "msexchmailboxguid", "ms-ds-consistencyguid", "msds-consistencyguid"}
FILETIME_ATTRIBUTES = {
    "accountexpires", "badpasswordtime", "lastlogon", "lastlogontimestamp", "lastlogoff",
    "lockouttime", "pwdlastset", "lastpwdset", "msds-userpasswordexpirytimecomputed",
    "msds-lastsuccessfulinteractivelogontime", "msds-lastfailedinteractivelogontime",
}
GENERALIZED_TIME_ATTRIBUTES = {
    "whencreated", "whenchanged", "createtimestamp", "modifytimestamp", "dschorepropagationdata",
    "msexchwhenmailboxcreated",
}
NEVER_ATTRIBUTES = {"accountexpires", "msds-userpasswordexpirytimecomputed"}


def decode_value(attr: str, value: Any, date_format: str = "%d.%m.%Y %H:%M:%S") -> Any:
    """Decode a single LDAP value into something JSON friendly and human readable."""
    a = attr.lower()
    if a in SID_ATTRIBUTES:
        return sid_to_str(value)
    if a in GUID_ATTRIBUTES:
        return guid_to_str(value)
    if a in FILETIME_ATTRIBUTES:
        if a in NEVER_ATTRIBUTES and is_never(value):
            return "never"
        dt = filetime_to_datetime(value)
        if dt:
            return format_datetime(dt, date_format)
        return "" if (isinstance(value, datetime) or to_int(value) in (0, None)) else str(value)
    if a in GENERALIZED_TIME_ATTRIBUTES or isinstance(value, datetime):
        dt = generalized_time_to_datetime(value)
        return format_datetime(dt, date_format) if dt else str(value)
    if isinstance(value, (bytes, bytearray)):
        return bytes_to_text(bytes(value))
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float, str)) or value is None:
        return value
    return str(value)


def decode_values(attr: str, values: Iterable[Any], date_format: str = "%d.%m.%Y %H:%M:%S") -> list[Any]:
    return [decode_value(attr, v, date_format) for v in values]
