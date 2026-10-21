"""Views (record -> dict) and renderers (dicts -> json / table / csv / ldif / ...)."""

from __future__ import annotations

import base64
import csv
import io
import json
import os
import re
import sys
from datetime import datetime
from typing import Any, Iterable, Sequence

from rich.console import Console
from rich.table import Table
from rich.text import Text

from . import ad
from .client import Record, dn_parent, rdn_value
from .config import Settings
from .display import terminal_text
from .exports import write_private

VIEWS = ("compact", "detail", "full", "raw")
FORMATS = ("json", "table", "csv", "tsv", "ldif", "list", "dn", "yaml")

# --------------------------------------------------------------------------- #
# attribute sets
# --------------------------------------------------------------------------- #

from .attrs import GROUP_ATTRS_COMPACT, GROUP_ATTRS_DETAIL, USER_ATTRS_COMPACT, USER_ATTRS_DETAIL  # noqa: E402


def user_attributes(view: str, settings: Settings, include_memberof: bool = False,
                    extra: Iterable[str] = ()) -> list[str] | None:
    if view == "raw":
        return None
    attrs = list(USER_ATTRS_COMPACT if view == "compact" else USER_ATTRS_DETAIL)
    if view != "compact":
        attrs += list(settings.user_extra_attributes)
    attrs += list(extra)
    if include_memberof:
        attrs += ["memberOf", "primaryGroupID"]
    return _dedupe(attrs)


def group_attributes(view: str, settings: Settings, with_members: bool = False, extra: Iterable[str] = ()) -> list[str] | None:
    if view == "raw":
        return None
    attrs = list(GROUP_ATTRS_COMPACT if view == "compact" else GROUP_ATTRS_DETAIL)
    if view != "compact":
        attrs += list(settings.group_extra_attributes)
    if with_members:
        attrs += ["member", "uniqueMember", "memberUid"]
    attrs += list(extra)
    return _dedupe(attrs)


def _dedupe(items: Iterable[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for i in items:
        if i and i.lower() not in seen:
            seen.add(i.lower())
            out.append(i)
    return out


# --------------------------------------------------------------------------- #
# record -> dict
# --------------------------------------------------------------------------- #

def _dec(rec: Record, attr: str, settings: Settings) -> str:
    v = rec.first(attr, None)
    if v is None:
        return ""
    out = ad.decode_value(attr, v, settings.date_format)
    return "" if out is None else str(out)


def _join(*parts: str, sep: str) -> str:
    return sep.join(p for p in parts if p)


def group_names(rec: Record, short: bool = True) -> list[str]:
    names = [str(g) for g in rec.get("memberOf")]
    if short:
        names = [rdn_value(g) for g in names]
    return sorted(names, key=str.lower)


def user_to_dict(rec: Record, view: str, settings: Settings, include_memberof: bool = False,
                 groups: Sequence[Record] | None = None) -> dict[str, Any]:
    """Convert a user record to the requested view.

    compact/full use stable key names ("name", "email", "givenName_surname", ...)
    that existing scripts can rely on.
    """
    if view == "raw":
        return record_to_raw(rec, settings)

    d = _dec
    login = rec.text("sAMAccountName") or rec.text("uid")
    given, surname = rec.text("givenName"), rec.text("sn")
    tel, mob = rec.text("telephoneNumber"), rec.text("mobile")
    office, dept = rec.text("physicalDeliveryOfficeName"), rec.text("department")

    if view == "full":
        info: dict[str, Any] = {
            "dn": rec.dn,
            "name": login,
            "email": rec.text("mail"),
            "surname": surname,
            "given_name": given,
            "display_name": rec.text("displayName") or rec.text("cn"),
            "username": login,
            "upn": rec.text("userPrincipalName"),
            "telephone": tel,
            "mobile": mob,
            "title": rec.text("title"),
            "department": dept,
            "office": office,
            "company": rec.text("company"),
            "employee_id": rec.text("employeeID") or rec.text("employeeNumber"),
            "manager": rdn_value(rec.text("manager")) if rec.has("manager") else "",
            "streetAddress": rec.text("streetAddress"),
            "postalCode": rec.text("postalCode"),
            "l": rec.text("l"),
            "country": rec.text("co") or rec.text("c"),
            "description": rec.text("description"),
            "disabled": rec.disabled,
            "locked": rec.locked,
            "password_expired": rec.password_expired,
            "password_never_expires": bool(ad.to_int(rec.first("userAccountControl"), 0) & ad.UAC_DONT_EXPIRE_PASSWORD),
            "account_flags": decode_flags(rec),
            "accountExpires": d(rec, "accountExpires", settings),
            "lastLogon": d(rec, "lastLogon", settings) or d(rec, "lastLogonTimestamp", settings),
            "pwdLastSet": d(rec, "pwdLastSet", settings),
            "passwordExpires": d(rec, "msDS-UserPasswordExpiryTimeComputed", settings),
            "badPasswordTime": d(rec, "badPasswordTime", settings),
            "badPwdCount": ad.to_int(rec.first("badPwdCount"), 0) if rec.has("badPwdCount") else "",
            "lockoutTime": d(rec, "lockoutTime", settings),
            "whenCreated": d(rec, "whenCreated", settings),
            "whenChanged": d(rec, "whenChanged", settings),
            "objectSid": d(rec, "objectSid", settings),
            "objectGUID": d(rec, "objectGUID", settings),
        }
        for extra in settings.user_extra_attributes:
            if rec.has(extra):
                vals = ad.decode_values(extra, rec.get(extra), settings.date_format)
                info[extra] = vals[0] if len(vals) == 1 else vals
        if include_memberof or groups is not None:
            info["memberOf"] = [g.dn for g in groups] if groups is not None else group_names(rec, short=False)
        return info

    # compact & detail
    info = {"dn": rec.dn, "name": login, "disabled": rec.disabled}
    if rec.text("mail"):
        info["email"] = rec.text("mail")
    full_name = _join(given, surname, sep=", ") if (given or surname) else (rec.text("displayName") or rec.text("cn"))
    if full_name:
        info["givenName_surname"] = full_name
    phones = _join(mob, tel, sep=" / ")
    if phones:
        info["mobile_telephone"] = phones
    od = _join(office, dept, sep=" / ")
    if od:
        info["office_department"] = od
    if rec.text("title"):
        info["title"] = rec.text("title")
    if rec.locked:
        info["locked"] = True
    if rec.password_expired:
        info["password_expired"] = True

    if view == "detail":
        street, plz, city = rec.text("streetAddress"), rec.text("postalCode"), rec.text("l")
        if street or plz or city:
            info["address"] = _join(street, _join(plz, city, sep=" "), sep=", ")
        for key, attr in (("upn", "userPrincipalName"), ("employee_id", "employeeID"), ("company", "company"),
                          ("division", "division"), ("description", "description")):
            if rec.text(attr):
                info[key] = rec.text(attr)
        if rec.has("manager"):
            info["manager"] = rdn_value(rec.text("manager"))
        for extra in settings.user_extra_attributes:
            if rec.has(extra):
                vals = ad.decode_values(extra, rec.get(extra), settings.date_format)
                info[extra] = vals[0] if len(vals) == 1 else vals
        flags = decode_flags(rec)
        if flags:
            info["account_flags"] = flags
        for attr in ("accountExpires", "lastLogon", "lastLogonTimestamp", "pwdLastSet", "msDS-UserPasswordExpiryTimeComputed", "badPasswordTime", "lockoutTime", "whenCreated"):
            val = d(rec, attr, settings)
            if val:
                key = "passwordExpires" if attr == "msDS-UserPasswordExpiryTimeComputed" else attr
                info[key] = val
        if rec.has("badPwdCount") and ad.to_int(rec.first("badPwdCount"), 0):
            info["badPwdCount"] = ad.to_int(rec.first("badPwdCount"), 0)
        for attr in ("objectSid", "objectGUID"):
            val = d(rec, attr, settings)
            if val:
                info[attr] = val

    if include_memberof or groups is not None:
        if groups is not None:
            info["memberOf"] = sorted((g.display_name for g in groups), key=str.lower)
        else:
            info["memberOf"] = group_names(rec, short=True)
    return info


def decode_flags(rec: Record) -> list[str]:
    if not rec.has("userAccountControl"):
        return []
    flags = ad.decode_uac(rec.first("userAccountControl"))
    return [f for f in flags if f not in ("NORMAL_ACCOUNT",)]


def group_to_dict(rec: Record, view: str, settings: Settings, member_count: int | None = None) -> dict[str, Any]:
    if view == "raw":
        return record_to_raw(rec, settings)
    gt = ad.decode_group_type(rec.first("groupType")) if rec.has("groupType") else {}
    info: dict[str, Any] = {
        "dn": rec.dn,
        "name": rec.text("cn") or rec.text("name") or rec.rdn_value,
    }
    if rec.text("description"):
        info["description"] = rec.text("description")
    if gt:
        info["type"] = f"{gt['category']}/{gt['scope']}"
    if rec.text("mail"):
        info["email"] = rec.text("mail")
    if member_count is not None:
        info["member_count"] = member_count
    elif any(rec.has(a) for a in ("member", "uniqueMember", "memberUid")):
        info["member_count"] = sum(len(rec.get(a)) for a in ("member", "uniqueMember", "memberUid"))
    if rec.has("primaryGroup"):
        info["primary_group"] = True
    if view in ("detail", "full"):
        info["ou"] = dn_parent(rec.dn)
        if rec.has("managedBy"):
            info["managed_by"] = rdn_value(rec.text("managedBy"))
        if rec.text("info"):
            info["info"] = rec.text("info")
        if rec.has("gidNumber"):
            info["gidNumber"] = rec.first("gidNumber")
        for attr in ("whenCreated", "whenChanged", "objectSid"):
            val = _dec(rec, attr, settings)
            if val:
                info[attr] = val
        if rec.has("memberOf"):
            info["memberOf"] = group_names(rec, short=(view != "full"))
        for extra in settings.group_extra_attributes:
            if rec.has(extra):
                vals = ad.decode_values(extra, rec.get(extra), settings.date_format)
                info[extra] = vals[0] if len(vals) == 1 else vals
        if view == "full":
            members = []
            for a in ("member", "uniqueMember", "memberUid"):
                members += [str(m) for m in rec.get(a)]
            if members:
                info["members"] = sorted(members, key=str.lower)
    return info


def member_to_dict(rec: Record, view: str, settings: Settings, include_memberof: bool = False) -> dict[str, Any]:
    """Group members may be users, groups, computers or contacts."""
    if view == "raw":
        return record_to_raw(rec, settings)
    if rec.is_group:
        d = group_to_dict(rec, view, settings)
        d["type"] = "group" if "type" not in d else f"group ({d['type']})"
        return d
    d = user_to_dict(rec, view, settings, include_memberof)
    if rec.is_computer:
        d["type"] = "computer"
    return d


def record_to_raw(rec: Record, settings: Settings) -> dict[str, Any]:
    out: dict[str, Any] = {"dn": rec.dn}
    for name, values in rec.items():
        out[name] = ad.decode_values(name, values, settings.date_format)
    return out


def container_to_dict(rec: Record) -> dict[str, Any]:
    return {
        "dn": rec.dn,
        "name": str(rec.first_of("ou", "cn", "name")),
        "type": next((c for c in ("organizationalUnit", "container", "builtinDomain") if c.lower() in rec.object_classes), "object"),
        "description": rec.text("description"),
    }


# --------------------------------------------------------------------------- #
# rendering
# --------------------------------------------------------------------------- #

def flatten_value(v: Any, sep: str = "; ") -> str:
    if v is None:
        return ""
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, (list, tuple)):
        return sep.join(flatten_value(x, sep) for x in v)
    if isinstance(v, dict):
        return json.dumps(v, ensure_ascii=False, default=str)
    if isinstance(v, datetime):
        return ad.format_datetime(v)
    return str(v)


def collect_keys(rows: Sequence[dict[str, Any]], fields: Sequence[str] | None = None) -> list[str]:
    if fields:
        return list(fields)
    keys: list[str] = []
    seen: set[str] = set()
    for r in rows:
        for k in r:
            if k not in seen:
                seen.add(k)
                keys.append(k)
    return keys


def select_fields(rows: Sequence[dict[str, Any]], fields: Sequence[str] | None) -> list[dict[str, Any]]:
    if not fields:
        return list(rows)
    lower_fields = [f.lower() for f in fields]
    out = []
    for r in rows:
        lower_map = {k.lower(): k for k in r}
        out.append({f: r.get(lower_map.get(lf, f), "") for f, lf in zip(fields, lower_fields)})
    return out


def sort_rows(rows: list[dict[str, Any]], key: str | None) -> list[dict[str, Any]]:
    if not key:
        return rows
    reverse = key.startswith("-")
    k = key.lstrip("-+")
    lower = k.lower()

    def sort_key(r: dict[str, Any]) -> tuple[int, str]:
        match = next((kk for kk in r if kk.lower() == lower), None)
        v = r.get(match) if match else None
        return (1 if v in (None, "", []) else 0, flatten_value(v).lower())

    return sorted(rows, key=sort_key, reverse=reverse)


def to_json(rows: Any) -> str:
    return json.dumps(rows, indent=2, ensure_ascii=False, default=str)


def to_csv(rows: Sequence[dict[str, Any]], fields: Sequence[str] | None = None, delimiter: str = ",") -> str:
    """Spreadsheet-safe CSV/TSV; JSON/LDIF preserve unmodified values."""
    keys = collect_keys(rows, fields)
    buf = io.StringIO()
    w = csv.writer(buf, delimiter=delimiter, lineterminator="\n")
    w.writerow([spreadsheet_cell(k) for k in keys])
    for r in rows:
        w.writerow([spreadsheet_cell(r.get(k)) for k in keys])
    return buf.getvalue()


def spreadsheet_cell(value: Any) -> str:
    text = flatten_value(value)
    stripped = text.lstrip("".join(chr(c) for c in range(33)) + "\x7f\x85\xa0")
    if ((text and (ord(text[0]) < 32 or 127 <= ord(text[0]) < 160))
            or stripped.lstrip().startswith(("=", "+", "-", "@", "＝", "＋", "－", "＠"))):
        return "'" + text
    return text


_LDIF_SAFE = re.compile(r"^[\x01-\x09\x0b-\x0c\x0e-\x1f\x21-\x39\x3b\x3d-\x7f][\x01-\x09\x0b-\x0c\x0e-\x7f]*$")


def _ldif_line(attr: str, value: Any) -> str:
    s = flatten_value(value)
    if s.startswith("base64:"):
        return f"{attr}:: {s[7:]}"
    if s == "" or _LDIF_SAFE.match(s):
        return f"{attr}: {s}"
    return f"{attr}:: {base64.b64encode(s.encode('utf-8')).decode('ascii')}"


def to_ldif(rows: Sequence[dict[str, Any]]) -> str:
    out: list[str] = []
    for r in rows:
        dn = r.get("dn", "")
        out.append(_ldif_line("dn", dn))
        for k, v in r.items():
            if k == "dn":
                continue
            values = v if isinstance(v, list) else [v]
            for val in values:
                if val in (None, ""):
                    continue
                out.append(_ldif_line(k, val))
        out.append("")
    return "\n".join(out)


def to_yaml(rows: Any, indent: int = 0) -> str:
    """Minimal YAML emitter (no dependency on PyYAML)."""
    pad = "  " * indent
    lines: list[str] = []

    def scalar(v: Any) -> str:
        if v is None:
            return "null"
        if isinstance(v, bool):
            return "true" if v else "false"
        if isinstance(v, (int, float)):
            return str(v)
        s = str(v)
        if s == "" or re.search(r"[:#\[\]{}&*!|>'\"%@`,\n]|^\s|\s$", s) or s.lower() in ("yes", "no", "true", "false", "null", "~"):
            return json.dumps(s, ensure_ascii=False)
        return s

    if isinstance(rows, list):
        for item in rows:
            if isinstance(item, dict):
                first = True
                for k, v in item.items():
                    prefix = f"{pad}- " if first else f"{pad}  "
                    first = False
                    if isinstance(v, (list, dict)) and v:
                        lines.append(f"{prefix}{k}:")
                        lines.append(to_yaml(v, indent + 2))
                    else:
                        lines.append(f"{prefix}{k}: {scalar(v if not isinstance(v, (list, dict)) else '')}")
                if first:
                    lines.append(f"{pad}- {{}}")
            else:
                lines.append(f"{pad}- {scalar(item)}")
    elif isinstance(rows, dict):
        for k, v in rows.items():
            if isinstance(v, (list, dict)) and v:
                lines.append(f"{pad}{k}:")
                lines.append(to_yaml(v, indent + 1))
            else:
                lines.append(f"{pad}{k}: {scalar(v if not isinstance(v, (list, dict)) else '')}")
    else:
        lines.append(f"{pad}{scalar(rows)}")
    return "\n".join(l for l in lines if l != "")


def to_list(rows: Sequence[dict[str, Any]], key_candidates: Sequence[str] = ("name", "dn")) -> str:
    out = []
    for r in rows:
        for k in key_candidates:
            if r.get(k):
                out.append(flatten_value(r[k]))
                break
    return "\n".join(out) + ("\n" if out else "")


def build_table(rows: Sequence[dict[str, Any]], fields: Sequence[str] | None = None, title: str | None = None,
                max_width: int | None = None) -> Table:
    keys = collect_keys(rows, fields)
    if not fields and "dn" in keys:
        keys = [k for k in keys if k != "dn"] + ["dn"]   # the long DN reads best as the last column
    table = Table(title=Text(terminal_text(title)) if title else None,
                  show_lines=False, header_style="bold cyan", title_style="bold",
                  expand=False, pad_edge=False, row_styles=["", "dim"] if len(rows) > 12 else None)
    for k in keys:
        justify = "right" if k in ("member_count", "badPwdCount") else "left"
        table.add_column(Text(terminal_text(k)), overflow="fold", justify=justify,
                         max_width=max_width if k == "dn" else None)
    for r in rows:
        cells = []
        for k in keys:
            v = r.get(k)
            cells.append(style_cell(k, v))
        table.add_row(*cells)
    return table


def style_cell(key: str, v: Any) -> Text:
    if v is None or v == "" or v == []:
        return Text("-", style="dim")
    if isinstance(v, bool):
        if key in ("disabled", "locked", "password_expired"):
            return Text("yes", style="bold red") if v else Text("no", style="green")
        return Text("yes" if v else "no", style="bold" if v else "dim")
    if isinstance(v, list):
        return Text("\n".join(terminal_text(flatten_value(x)) for x in v))
    if key in ("dn", "ou"):
        return Text(terminal_text(v), style="dim")
    if key == "type":
        s = terminal_text(v)
        return Text(s, style="magenta" if "group" in s else ("yellow" if "computer" in s else ""))
    if key in ("email", "upn", "mail"):
        return Text(terminal_text(v), style="blue")
    if key == "account_flags":
        return Text(terminal_text(flatten_value(v)), style="yellow")
    return Text(terminal_text(flatten_value(v)))


def make_console(no_color: bool = False, stderr: bool = False) -> Console:
    if os.environ.get("NO_COLOR"):
        no_color = True
    return Console(stderr=stderr, no_color=no_color, highlight=False, soft_wrap=False, emoji=False)


def comment_header(comment: str) -> str:
    """'# ...' lines for formats that allow comments (everything except json)."""
    return "\n".join("# " + line for line in comment.strip().splitlines()) + "\n\n"


def render(rows: list[dict[str, Any]], fmt: str, *, fields: Sequence[str] | None = None, title: str | None = None,
           console: Console | None = None, output: str | None = None, sort: str | None = None,
           comment: str | None = None) -> None:
    """Render rows in the requested format to stdout or a file.
    comment (used by the GUI export) is prepended as '# ...' lines; json has no comments and skips it."""
    console = console or make_console()
    rows = sort_rows(select_fields(rows, fields), sort)
    header = comment_header(comment) if comment and fmt != "json" else ""

    if fmt == "table":
        if output:
            tmp = Console(file=io.StringIO(), no_color=True, width=200, emoji=False, highlight=False)
            tmp.print(build_table(rows, None, title))
            _write(output, header + tmp.file.getvalue())  # type: ignore[attr-defined]
        else:
            console.print(build_table(rows, None, title, max_width=max(40, console.width // 2)))
        return

    if fmt == "json":
        text = to_json(rows)
    elif fmt == "csv":
        text = to_csv(rows)
    elif fmt == "tsv":
        text = to_csv(rows, delimiter="\t")
    elif fmt == "ldif":
        text = to_ldif(rows)
    elif fmt == "yaml":
        text = to_yaml(rows)
    elif fmt == "list":
        text = to_list(rows)
    elif fmt == "dn":
        text = to_list(rows, ("dn",))
    else:
        raise ValueError(f"unknown format {fmt}")

    text = header + text
    if output:
        _write(output, text)
        return
    unsafe_json = fmt == "json" and console.is_terminal and terminal_text(text, multiline=True) != text
    if unsafe_json:
        text = json.dumps(rows, indent=2, ensure_ascii=True, default=str)
    if fmt == "json" and console.is_terminal and not console.no_color:
        console.print_json(text, ensure_ascii=unsafe_json)
    else:
        _print_plain(text)


def _print_plain(text: str) -> None:
    try:
        if sys.stdout.isatty():
            text = terminal_text(text, multiline=True)
        sys.stdout.write(text if text.endswith("\n") or not text else text + "\n")
        sys.stdout.flush()
    except BrokenPipeError:
        try:
            sys.stdout = open(os.devnull, "w")
        except OSError:
            pass


def _write(path: str, text: str) -> None:
    write_private(path, text)


def auto_filename(base: str, ext: str) -> str:
    ts = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
    safe = re.sub(r"[^A-Za-z0-9_.-]+", "_", base).strip("_")[:60] or "ldapgrep"
    return f"{safe}_{ts}.{ext}"
