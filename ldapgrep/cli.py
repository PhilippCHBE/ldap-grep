"""Command line interface.

    ldapgrep user meier --memberof
    ldapgrep group "IT-Admins" --recursive --format table
    ldapgrep groups "vpn*" --count-members
    ldapgrep memberof jdoe --recursive
    ldapgrep compare jdoe asmith
    ldapgrep search "(&(objectClass=user)(title=*Engineer*))" --attrs cn,mail
    ldapgrep check
    ldapgrep tui

Exit codes: 0 = matches found, 1 = no match, 2 = usage/config error,
            3 = connection/authentication error, 4 = LDAP error.
"""

from __future__ import annotations

import argparse
import getpass
import logging
import errno
import os
import sys
from typing import Any, Sequence

from rich.markup import escape
from rich.text import Text

from . import __version__
from . import format as fmt
from .client import (
    EXIT_CONNECTION,
    EXIT_LDAP,
    EXIT_NO_MATCH,
    EXIT_OK,
    EXIT_USAGE,
    LdapClient,
    LdapGrepError,
    Record,
    is_broad_term,
    probe_server,
)
from .config import (EXAMPLE_CONFIG, ConfigError, Settings, all_profiles, candidate_config_files, load_settings,
                     parse_server_url)
from .display import terminal_text
from .exports import default_export_dir

log = logging.getLogger("ldapgrep")

SUBCOMMANDS = ("user", "group", "groups", "memberof", "compare", "search", "info", "whoami",
               "schema", "tree", "config", "check", "tui")


# --------------------------------------------------------------------------- #
# argument parsing
# --------------------------------------------------------------------------- #

def _csv_list(value: str) -> list[str]:
    return [v.strip() for v in value.replace(";", ",").split(",") if v.strip()]


def build_common(suppress: bool) -> argparse.ArgumentParser:
    """Shared options.  Sub-parsers use suppress=True so they never override values parsed globally."""
    common = argparse.ArgumentParser(add_help=False, argument_default=argparse.SUPPRESS if suppress else None)
    g = common.add_argument_group("connection")
    g.add_argument("--config", metavar="FILE", help="config file (default: auto-discovered ldap-grep.conf, see `config`)")
    g.add_argument("--no-config", dest="no_config", action="store_true",
                   help="ignore all config files (connection from command line / environment only)")
    g.add_argument("--profile", "-P", metavar="NAME",
                   help="config profile ([profile:NAME] section) or a built-in public one: forumsys, debian, freeipa")
    g.add_argument("--server", "-H", metavar="URL", help="ldap://host[:port] or ldaps://host[:port]")
    g.add_argument("--base-dn", "-b", dest="base_dn", metavar="DN", help="search base (auto-detected when omitted)")
    g.add_argument("--bind-dn", "-D", dest="bind_dn", metavar="DN", help="bind DN / user@domain / DOMAIN\\user")
    g.add_argument("--password", "-w", dest="bind_password", metavar="PW", help="bind password (prefer -W or LDAPGREP_PASSWORD)")
    g.add_argument("--ask-password", "-W", action="store_true", help="prompt for the bind password")
    g.add_argument("--auth", choices=("simple", "ntlm", "anonymous"), help="authentication method")
    g.add_argument("--insecure", "-k", action="store_true", help="do not verify the TLS certificate")
    g.add_argument("--ca-file", dest="ca_certs_file", metavar="PEM", help="CA bundle for TLS verification")
    g.add_argument("--starttls", action="store_true", help="upgrade a plain ldap:// connection with StartTLS")
    g.add_argument("--allow-plaintext-auth", action="store_true",
                   help="allow unencrypted authentication (isolated test networks only)")
    g.add_argument("--timeout", type=float, metavar="SEC", help="network timeout in seconds")
    g.add_argument("--page-size", dest="page_size", type=int, metavar="N", help="paged search page size")
    g.add_argument("--flavor", choices=("auto", "ad", "ldap"), help="force server type")
    g.add_argument("--no-schema", action="store_true", help="do not read the server schema (faster start, no attribute validation)")
    g.add_argument("--demo", action="store_true", help="use a built-in demo directory instead of a real server")

    o = common.add_argument_group("output")
    o.add_argument("--format", "-f", choices=fmt.FORMATS, help="output format (default: table on a terminal, json when piped/redirected)")
    o.add_argument("--fields", type=_csv_list, metavar="A,B,C", help="only output these fields (also sets column order)")
    o.add_argument("--sort", metavar="FIELD", help="sort by field; descending with --sort=-FIELD")
    o.add_argument("--output", "-o", metavar="FILE", help="write to FILE instead of stdout ('auto' = timestamped name, '-' = stdout)")
    o.add_argument("--limit", "-n", type=int, default=argparse.SUPPRESS if suppress else 0, metavar="N", help="stop after N results")
    o.add_argument("--no-color", action="store_true", help="disable colors (also honours NO_COLOR)")
    o.add_argument("--quiet", "-q", action="store_true", help="suppress warnings")
    o.add_argument("--verbose", "-v", action="count", default=argparse.SUPPRESS if suppress else 0, help="more diagnostics on stderr (-vv for ldap3 debug)")
    return common


def build_parser() -> argparse.ArgumentParser:
    common = build_common(suppress=True)
    p = argparse.ArgumentParser(
        prog="ldapgrep",
        description="grep your company's Active Directory / LDAP: users, groups, memberships.",
        epilog="Run `ldapgrep <command> --help` for command specific options. "
               "No command + interactive terminal = console GUI.",
        parents=[build_common(suppress=False)],
    )
    p.add_argument("--version", action="version", version=f"ldapgrep {__version__}")
    sp = p.add_subparsers(dest="command", metavar="<command>")

    def view_arg(parser: argparse.ArgumentParser, default: str = "compact") -> None:
        parser.add_argument("--view", choices=fmt.VIEWS, default=default,
                            help="compact (default) | detail | full | raw (all attributes)")
        parser.add_argument("--full", dest="view", action="store_const", const="full", help=argparse.SUPPRESS)
        parser.add_argument("--detail", dest="view", action="store_const", const="detail", help=argparse.SUPPRESS)
        parser.add_argument("--all-attributes", "--all", dest="view", action="store_const", const="raw", help=argparse.SUPPRESS)
        parser.add_argument("--attrs", type=_csv_list, metavar="A,B", help="additional attributes to request")

    u = sp.add_parser("user", parents=[common], help="search users by login, name, mail, UPN, employee id or DN")
    u.add_argument("term", nargs="*", help="search term(s); 'Max Müller' matches first+last name")
    u.add_argument("--from-file", metavar="FILE", help="read one term per line from FILE ('-' = stdin)")
    mode = u.add_mutually_exclusive_group()
    mode.add_argument("--exact", "-x", dest="mode", action="store_const", const="exact", help="exact match")
    mode.add_argument("--contains", "-c", dest="mode", action="store_const", const="contains", help="substring match (*term*)")
    u.set_defaults(mode="prefix")
    u.add_argument("--memberof", "-m", action="store_true", help="include the user's groups")
    u.add_argument("--recursive", "-r", action="store_true", help="with --memberof: include nested groups")
    u.add_argument("--active", "-a", action="store_true", help="only enabled accounts")
    u.add_argument("--disabled", action="store_true", help="only disabled accounts")
    u.add_argument("--locked", action="store_true", help="only locked accounts")
    u.add_argument("--base", metavar="DN", help="restrict search to this OU")
    u.add_argument("--filter", metavar="LDAPFILTER", help="additional LDAP filter, e.g. (department=IT)")
    u.add_argument("--computers", action="store_true", help="include computer accounts (AD)")
    u.add_argument("--count", action="store_true", help="only print the number of matching users (no entries are read)")
    view_arg(u)

    gm = sp.add_parser("group", parents=[common], help="list members of a group (default group when omitted)")
    gm.add_argument("name", nargs="?", help="group name, sAMAccountName or DN")
    gm.add_argument("--recursive", "-r", action="store_true", help="resolve nested groups")
    gm.add_argument("--active", "-a", action="store_true", help="only enabled accounts")
    kind = gm.add_mutually_exclusive_group()
    kind.add_argument("--users-only", dest="kind", action="store_const", const="users", help="skip nested groups in the output")
    kind.add_argument("--groups-only", dest="kind", action="store_const", const="groups", help="only nested groups")
    gm.set_defaults(kind="all")
    gm.add_argument("--memberof", "-m", action="store_true", help="include each member's groups")
    gm.add_argument("--count", action="store_true", help="only print the number of members")
    gm.add_argument("--show", action="store_true", help="show the group object itself instead of its members")
    view_arg(gm)

    gl = sp.add_parser("groups", parents=[common], help="list / search groups")
    gl.add_argument("pattern", nargs="?", default="", help="name pattern (substring; use * for wildcards)")
    gl.add_argument("--base", metavar="DN", help="OU to search (default: groups_ou or base_dn)")
    gl.add_argument("--one-level", action="store_true", help="do not descend into sub-OUs")
    gl.add_argument("--count-members", "-C", action="store_true", help="add member_count (reads member attribute)")
    gl.add_argument("--empty", action="store_true", help="only groups without members")
    gl.add_argument("--exact", "-x", dest="mode", action="store_const", const="exact", help="exact name match")
    gl.add_argument("--prefix", dest="mode", action="store_const", const="prefix", help="prefix match")
    gl.set_defaults(mode="contains")
    gl.add_argument("--count", action="store_true", help="only print the number of matching groups (no entries are read)")
    view_arg(gl)

    mo = sp.add_parser("memberof", parents=[common], help="groups a user belongs to")
    mo.add_argument("user", help="login, mail, UPN, display name or DN")
    mo.add_argument("--recursive", "-r", action="store_true", help="include nested groups")
    view_arg(mo)

    cp = sp.add_parser("compare", parents=[common], help="compare the group memberships of two users")
    cp.add_argument("user1")
    cp.add_argument("user2")
    cp.add_argument("--recursive", "-r", action="store_true", help="include nested groups")

    se = sp.add_parser("search", parents=[common], help="raw LDAP filter search")
    se.add_argument("filter", help="LDAP filter, e.g. (&(objectClass=user)(title=*Engineer*))")
    se.add_argument("--base", metavar="DN", help="search base")
    se.add_argument("--scope", choices=("base", "one", "sub"), default="sub")
    se.add_argument("--attrs", type=_csv_list, metavar="A,B", help="attributes to return (default: all)")
    se.add_argument("--count", action="store_true", help="only print the number of entries")

    sp.add_parser("info", parents=[common], help="server information (rootDSE, flavor, schema)")
    sp.add_parser("whoami", parents=[common], help="show the identity the server sees")

    sc = sp.add_parser("schema", parents=[common], help="list attribute names known to the server")
    sc.add_argument("pattern", nargs="?", default="", help="substring filter")

    tr = sp.add_parser("tree", parents=[common], help="show the OU / container tree")
    tr.add_argument("base", nargs="?", help="start DN (default: base_dn)")
    tr.add_argument("--depth", "-d", type=int, default=3, help="levels to descend (default 3)")
    tr.add_argument("--counts", action="store_true", help="count users/groups per container (slow)")

    cf = sp.add_parser("config", parents=[common], help="show the effective configuration")
    cf.add_argument("--example", action="store_true", help="print an example config file")
    cf.add_argument("--check", action="store_true", help="connect and report")
    cf.add_argument("--show-password", action="store_true", help=argparse.SUPPRESS)

    sp.add_parser("check", parents=[common],
                  help="test the connection step by step before querying: DNS, TCP port, TLS, bind")
    sp.add_parser("tui", parents=[common], help="interactive console GUI (needs the 'textual' package)")
    return p


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #

class Ctx:
    def __init__(self, args: argparse.Namespace, settings: Settings):
        self.args = args
        self.settings = settings
        self.console = fmt.make_console(no_color=args.no_color)
        self.err = fmt.make_console(no_color=args.no_color, stderr=True)
        self.format = args.format or ("table" if self.console.is_terminal else "json")
        self.output: str | None = args.output

    def warn(self, msg: str) -> None:
        if not self.args.quiet:
            self.err.print(f"[yellow]warning:[/] {escape(terminal_text(msg))}")

    def note(self, msg: str) -> None:
        if not self.args.quiet:
            self.err.print(Text(terminal_text(msg), style="dim"))

    def emit(self, rows: list[dict[str, Any]], title: str, name_for_file: str = "ldapgrep") -> int:
        output = self.output
        if output == "-":
            output = None                       # '-' = stdout, the usual convention for pipes
        if output == "auto":
            ext = {"json": "json", "csv": "csv", "tsv": "tsv", "ldif": "ldif", "yaml": "yaml", "table": "txt"}.get(self.format, "txt")
            output = str(default_export_dir() / fmt.auto_filename(name_for_file, ext))
        try:
            fmt.render(rows, self.format, fields=self.args.fields, title=f"{title} ({len(rows)})",
                       console=self.console, output=output, sort=self.args.sort)
        except OSError as exc:
            if not output and exc.errno in (errno.EPIPE, errno.EINVAL):
                raise BrokenPipeError(str(exc)) from exc        # `| head` closed the pipe
            raise LdapGrepError(f"Cannot write output: {exc}", EXIT_USAGE) from exc
        if output:
            self.note(f"{len(rows)} entries written to {output}")
        return EXIT_OK if rows else EXIT_NO_MATCH


def settings_from_args(args: argparse.Namespace) -> Settings:
    overrides = {
        "server": args.server,
        "base_dn": args.base_dn,
        "bind_dn": args.bind_dn,
        "bind_password": args.bind_password,
        "auth": args.auth,
        "ca_certs_file": args.ca_certs_file,
        "timeout": args.timeout,
        "page_size": args.page_size,
        "flavor": args.flavor,
    }
    if args.insecure:
        overrides["tls_verify"] = False
    if getattr(args, "no_schema", False):
        overrides["load_schema"] = False
    if args.starttls:
        overrides["start_tls"] = True
    if args.allow_plaintext_auth:
        overrides["allow_plaintext_auth"] = True
    settings = load_settings(args.config, args.profile, overrides, skip_config=getattr(args, "no_config", False),
                             demo=bool(args.demo))
    if settings.builtin_profile and args.ask_password:
        raise ConfigError("Do not supply personal passwords to built-in public test profiles.")
    if args.demo:
        settings.server = settings.server or "demo"
    return settings


def _warn_config_mismatch(args: argparse.Namespace, settings: Settings, ctx: Ctx) -> None:
    """-H points to another host than the config file: its DN settings most likely do not fit."""
    if not (args.server and settings.config_server) or getattr(args, "quiet", False):
        return
    try:
        cli_host = parse_server_url(args.server)[0].lower()
        cfg_host = parse_server_url(settings.config_server)[0].lower()
    except ConfigError:
        # The effective target was already validated; rejected legacy URL values
        # are only shown through the redacted configuration diagnostics.
        return
    dn_keys = [k for k in ("base_dn", "users_ou", "groups_ou", "default_group_dn") if getattr(settings, k, "")]
    if cli_host and cfg_host and cli_host != cfg_host and dn_keys and not args.base_dn:
        ctx.warn(f"{settings.config_file} was written for {cfg_host} but you connect to "
                 f"{cli_host}; its {', '.join(dn_keys)} still apply. Use --no-config or --base-dn if that is wrong.")


def _silence_stdout() -> None:
    """Point fd 1 at the null device so the interpreter's final flush cannot fail (exit code 120)."""
    try:
        os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
    except (OSError, ValueError):
        pass


def _flush_stdout() -> None:
    """Flush now so a closed pipe (`| head`) is handled here and not at interpreter exit.
    On Windows a broken pipe surfaces as OSError(EINVAL), not BrokenPipeError."""
    try:
        sys.stdout.flush()
    except (OSError, ValueError):
        _silence_stdout()


def ensure_password(args: argparse.Namespace, settings: Settings, ctx: Ctx) -> None:
    if args.demo or settings.auth == "anonymous":
        return
    if args.ask_password or (not settings.bind_password and sys.stdin.isatty() and sys.stderr.isatty()):
        who = settings.bind_dn or "bind user"
        try:
            settings.bind_password = getpass.getpass(f"Password for {terminal_text(who)}: ")
        except (EOFError, KeyboardInterrupt):
            raise LdapGrepError("No password entered.", EXIT_USAGE)


def connect(args: argparse.Namespace, settings: Settings, ctx: Ctx) -> LdapClient:
    client = LdapClient(settings, demo=args.demo)
    client.validate_connection_settings()
    ensure_password(args, settings, ctx)
    client.connect()
    if args.verbose:
        ctx.note(f"connected to {client.server_info().get('server')} as {client.bound_as} "
                 f"(flavor={client.flavor.name}, base={client.base_dn})")
    return client


def flush_warnings(client: LdapClient, ctx: Ctx) -> None:
    for w in client.warnings:
        ctx.warn(w)
    client.warnings.clear()


def read_terms(args: argparse.Namespace) -> list[str]:
    terms = list(args.term or [])
    if args.from_file:
        try:
            fh = sys.stdin if args.from_file == "-" else open(args.from_file, encoding="utf-8")
            with fh:
                terms += [line.strip() for line in fh if line.strip() and not line.startswith("#")]
        except OSError as exc:
            raise LdapGrepError(f"Cannot read {args.from_file}: {exc}", EXIT_USAGE) from exc
    if not terms:
        raise LdapGrepError("Please provide a search term (or --from-file).", EXIT_USAGE)
    return terms


def confirm_broad_search(terms: list[str], narrowed: bool, settings: Settings, ctx: Ctx) -> bool:
    """Decide once whether broad wildcard searches ('*', 'a*', ...) may run.

    With min_search_length >= 2 the client blocks them outright; below that an interactive
    user is asked first, a non-interactive call is warned about.  Returns the allow_broad
    flag for the client."""
    if narrowed or settings.min_search_length >= 2:
        return False
    broad = next((t for t in terms if is_broad_term(t)), None)
    if broad is None:
        return False
    msg = (f"'{broad}' can match every entry of the directory "
           f"(min_search_length = {settings.min_search_length}).")
    if sys.stdin.isatty() and sys.stderr.isatty():
        ctx.warn(msg)
        try:
            answer = input("Really query the whole directory? [y/N] ")
        except (EOFError, KeyboardInterrupt):
            answer = ""
        if answer.strip().lower() not in ("y", "yes"):
            raise LdapGrepError("Aborted - no search was sent to the server.", EXIT_USAGE)
        return True
    ctx.warn(f"{msg} Proceeding (non-interactive call).")
    return True


# --------------------------------------------------------------------------- #
# commands
# --------------------------------------------------------------------------- #

def cmd_user(args: argparse.Namespace, ctx: Ctx) -> int:
    terms = read_terms(args)
    allow_broad = confirm_broad_search(terms, narrowed=bool(args.filter), settings=ctx.settings, ctx=ctx)
    if args.count:
        with connect(args, ctx.settings, ctx) as client:
            total = sum(client.count_users(term, mode=args.mode, base=args.base, active_only=args.active,
                                           extra_filter=args.filter or "", include_computers=args.computers,
                                           allow_broad=allow_broad) for term in terms)
            flush_warnings(client, ctx)
        print(total)
        return EXIT_OK if total else EXIT_NO_MATCH
    with connect(args, ctx.settings, ctx) as client:
        attrs = fmt.user_attributes(args.view, ctx.settings, args.memberof, args.attrs or [])
        if args.locked:
            attrs = None if attrs is None else attrs + ["lockoutTime"]
        rows: list[dict[str, Any]] = []
        seen: set[str] = set()
        for term in terms:
            if len(terms) > 1 and " " not in term and "*" not in term and args.mode == "prefix":
                mode = "exact"   # bulk lookups from files are usually exact logins
            else:
                mode = args.mode
            found = client.search_users(term, attrs, mode=mode, base=args.base, active_only=args.active,
                                        limit=args.limit, extra_filter=args.filter or "",
                                        include_computers=args.computers, allow_broad=allow_broad)
            if mode == "exact" and not found and len(terms) > 1:
                found = client.search_users(term, attrs, mode="prefix", base=args.base, active_only=args.active,
                                            limit=args.limit, extra_filter=args.filter or "",
                                            include_computers=args.computers)
            if args.disabled:
                found = [r for r in found if r.disabled]
            if args.locked:
                found = [r for r in found if r.locked]
            for rec in found:
                if rec.dn.lower() in seen:
                    continue
                seen.add(rec.dn.lower())
                groups = client.user_groups(rec, recursive=True) if (args.memberof and args.recursive) else None
                rows.append(fmt.user_to_dict(rec, args.view, ctx.settings, args.memberof, groups))
            if not found and len(terms) > 1:
                ctx.warn(f"no match for '{term}'")
        flush_warnings(client, ctx)
    return ctx.emit(rows, f"Users matching {', '.join(terms[:3])}{'...' if len(terms) > 3 else ''}", "_".join(terms[:2]))


def cmd_group(args: argparse.Namespace, ctx: Ctx) -> int:
    with connect(args, ctx.settings, ctx) as client:
        name = args.name or ctx.settings.default_group_dn   # demo mode sets its own default after connect
        if not name:
            raise LdapGrepError("No group given and no default_group_dn configured.", EXIT_USAGE,
                                "Pass a group name/DN or set default_group_dn in the config.")
        grp = client.find_group(name, fmt.group_attributes("detail", ctx.settings, with_members=args.show))
        if args.show:
            rows = [fmt.group_to_dict(grp, "full" if args.view == "compact" else args.view, ctx.settings)]
            flush_warnings(client, ctx)
            return ctx.emit(rows, f"Group {grp.display_name}", grp.display_name)
        attrs = fmt.user_attributes(args.view, ctx.settings, args.memberof, args.attrs or [])
        if attrs is not None:
            attrs += fmt.GROUP_ATTRS_COMPACT
        members = client.group_members(grp, attrs, recursive=args.recursive, active_only=args.active,
                                       kind=args.kind, limit=args.limit)
        flush_warnings(client, ctx)
        if args.count:
            print(len(members))
            return EXIT_OK if members else EXIT_NO_MATCH
        rows = [fmt.member_to_dict(m, args.view, ctx.settings, args.memberof) for m in members]
    title = f"Members of {grp.display_name}" + (" (recursive)" if args.recursive else "")
    return ctx.emit(rows, title, grp.display_name)


def cmd_groups(args: argparse.Namespace, ctx: Ctx) -> int:
    from ldap3 import LEVEL, SUBTREE

    allow_broad = confirm_broad_search([args.pattern], narrowed=False, settings=ctx.settings, ctx=ctx)
    scope = LEVEL if args.one_level else SUBTREE
    if args.count:
        with connect(args, ctx.settings, ctx) as client:
            n = client.count_groups(args.pattern, mode=args.mode, base=args.base, scope=scope, allow_broad=allow_broad)
            flush_warnings(client, ctx)
        print(n)
        return EXIT_OK if n else EXIT_NO_MATCH
    with connect(args, ctx.settings, ctx) as client:
        attrs = fmt.group_attributes(args.view, ctx.settings, with_members=args.count_members or args.empty, extra=args.attrs or [])
        groups = client.list_groups(args.pattern, attrs, base=args.base, scope=scope,
                                    limit=args.limit, mode=args.mode, allow_broad=allow_broad)
        if args.empty:
            groups = [g for g in groups if not any(g.has(a) for a in ("member", "uniqueMember", "memberUid"))]
        groups.sort(key=lambda g: g.display_name.lower())
        rows = []
        for g in groups:
            count = None
            if args.count_members or args.empty:
                count = sum(len(g.get(a)) for a in ("member", "uniqueMember", "memberUid"))
            rows.append(fmt.group_to_dict(g, args.view, ctx.settings, count))
        flush_warnings(client, ctx)
    return ctx.emit(rows, f"Groups {args.pattern or ''}".strip(), f"groups_{args.pattern or 'all'}")


def cmd_memberof(args: argparse.Namespace, ctx: Ctx) -> int:
    with connect(args, ctx.settings, ctx) as client:
        user = client.find_user(args.user, ["cn", "displayName", "sAMAccountName", "uid", "memberOf", "primaryGroupID", "objectClass"])
        attrs = fmt.group_attributes(args.view, ctx.settings, extra=args.attrs or [])
        groups = client.user_groups(user, recursive=args.recursive, attributes=attrs)
        direct = {str(d).lower() for d in user.get("memberOf")}
        rows = []
        for g in groups:
            row = fmt.group_to_dict(g, args.view, ctx.settings)
            if args.recursive:
                row["membership"] = "direct" if g.dn.lower() in direct or g.has("primaryGroup") else "nested"
            rows.append(row)
        flush_warnings(client, ctx)
    return ctx.emit(rows, f"Groups of {user.display_name}" + (" (recursive)" if args.recursive else ""), f"memberof_{user.login or 'user'}")


def cmd_compare(args: argparse.Namespace, ctx: Ctx) -> int:
    with connect(args, ctx.settings, ctx) as client:
        base_attrs = ["cn", "displayName", "sAMAccountName", "uid", "memberOf", "primaryGroupID", "objectClass"]
        u1 = client.find_user(args.user1, base_attrs)
        u2 = client.find_user(args.user2, base_attrs)
        g1 = {g.dn.lower(): g for g in client.user_groups(u1, recursive=args.recursive)}
        g2 = {g.dn.lower(): g for g in client.user_groups(u2, recursive=args.recursive)}
        rows = []
        for dn in sorted(set(g1) | set(g2), key=lambda d: (g1.get(d) or g2.get(d)).display_name.lower()):
            g = g1.get(dn) or g2.get(dn)
            in1, in2 = dn in g1, dn in g2
            rows.append({
                "group": g.display_name,
                u1.login or u1.display_name: in1,
                u2.login or u2.display_name: in2,
                "status": "both" if in1 and in2 else (f"only {u1.login or 'user1'}" if in1 else f"only {u2.login or 'user2'}"),
                "dn": g.dn,
            })
        flush_warnings(client, ctx)
    ctx.note(f"{u1.display_name}: {len(g1)} groups, {u2.display_name}: {len(g2)} groups, common: {len(set(g1) & set(g2))}")
    return ctx.emit(rows, f"Group comparison {u1.login} vs {u2.login}", f"compare_{u1.login}_{u2.login}")


def cmd_search(args: argparse.Namespace, ctx: Ctx) -> int:
    from ldap3 import BASE, LEVEL, SUBTREE

    scope = {"base": BASE, "one": LEVEL, "sub": SUBTREE}[args.scope]
    with connect(args, ctx.settings, ctx) as client:
        attrs = args.attrs if args.attrs else None
        if args.count:
            n = sum(1 for _ in client.iter_search(args.filter, ["objectClass"], base=args.base, scope=scope, limit=args.limit))
            flush_warnings(client, ctx)
            print(n)
            return EXIT_OK if n else EXIT_NO_MATCH
        records = client.search(args.filter, attrs, base=args.base, scope=scope, limit=args.limit)
        rows = [fmt.record_to_raw(r, ctx.settings) for r in records]
        if attrs and not args.fields and ctx.format in ("table", "csv", "tsv"):
            # flatten single values for tabular output
            rows = [{k: (v[0] if isinstance(v, list) and len(v) == 1 else v) for k, v in r.items()} for r in rows]
        flush_warnings(client, ctx)
    return ctx.emit(rows, f"Search {args.filter}", "search")


def cmd_info(args: argparse.Namespace, ctx: Ctx) -> int:
    with connect(args, ctx.settings, ctx) as client:
        info = client.server_info()
        info["whoami"] = client.whoami()
    if ctx.format in ("json", "yaml"):
        fmt.render([info] if ctx.format == "yaml" else [info], ctx.format, console=ctx.console, output=ctx.output)
        return EXIT_OK
    rows = [{"key": k, "value": v} for k, v in info.items()]
    return ctx.emit(rows, "Server information", "info")


def cmd_whoami(args: argparse.Namespace, ctx: Ctx) -> int:
    with connect(args, ctx.settings, ctx) as client:
        who = client.whoami()
    fmt._print_plain(who)
    return EXIT_OK


def cmd_schema(args: argparse.Namespace, ctx: Ctx) -> int:
    with connect(args, ctx.settings, ctx) as client:
        names = client.schema_attribute_names()
        if not names:
            raise LdapGrepError("The server did not expose its schema (or the bind user may not read it).", EXIT_LDAP)
        pat = args.pattern.lower()
        names = [n for n in names if pat in n.lower()]
        rows = [{"attribute": n} for n in names]
    if ctx.format == "table":
        ctx.console.print(Text("\n".join(terminal_text(n) for n in names)))
        return EXIT_OK if names else EXIT_NO_MATCH
    return ctx.emit(rows, "Schema attributes", "schema")


def cmd_tree(args: argparse.Namespace, ctx: Ctx) -> int:
    from rich.tree import Tree

    with connect(args, ctx.settings, ctx) as client:
        start = args.base or client.base_dn
        root = Tree(Text(terminal_text(start), style="bold"))
        rows: list[dict[str, Any]] = []

        def walk(dn: str, node: Tree, depth: int) -> None:
            if depth <= 0:
                return
            for c in client.list_containers(dn):
                d = fmt.container_to_dict(c)
                d["depth"] = args.depth - depth + 1
                label = Text(terminal_text(d["name"]), style="cyan")
                if args.counts:
                    users = client.count(client.flavor.user_filter, base=c.dn)
                    groups = client.count(client.flavor.group_filter, base=c.dn)
                    d["users"], d["groups"] = users, groups
                    label.append(f" ({users} users, {groups} groups)", style="dim")
                if d["description"]:
                    label.append(" - " + terminal_text(d["description"]), style="dim italic")
                rows.append(d)
                child = node.add(label)
                walk(c.dn, child, depth - 1)

        walk(start, root, args.depth)
        flush_warnings(client, ctx)
    if ctx.format == "table" and not ctx.output:
        ctx.console.print(root)
        return EXIT_OK if rows else EXIT_NO_MATCH
    return ctx.emit(rows, f"Tree below {start}", "tree")


def cmd_config(args: argparse.Namespace, ctx: Ctx) -> int:
    if args.example:
        print(EXAMPLE_CONFIG)
        return EXIT_OK
    s = ctx.settings
    data = s.to_dict(hide_secrets=not args.show_password)
    data["effective_url"] = s.display_url
    data["config_file"] = s.config_file or "(none found)"
    data["config_search_path"] = [str(p) for p in candidate_config_files()]
    data["profiles"] = [f"{n} ({src})" for n, src in
                        all_profiles(__import__("pathlib").Path(s.config_file) if s.config_file else None)]
    data["env_overrides"] = sorted(k for k in os.environ if k.upper().startswith("LDAPGREP_") and k.upper() != "LDAPGREP_PASSWORD")
    if "LDAPGREP_PASSWORD" in os.environ:
        data["env_overrides"].append("LDAPGREP_PASSWORD (set)")
    if args.check:
        try:
            with connect(args, s, ctx) as client:
                data["connection"] = "OK"
                data["bound_as"] = client.whoami()
                data["flavor"] = client.flavor.name
                data["detected_base_dn"] = client.base_dn
                data["schema_loaded"] = client.schema_available
                flush_warnings(client, ctx)
        except LdapGrepError as exc:
            data["connection"] = f"FAILED: {exc.message}"
            if exc.hint:
                data["hint"] = exc.hint
    if ctx.format in ("json", "yaml"):
        fmt.render([data], ctx.format, console=ctx.console, output=ctx.output)
    else:
        rows = [{"setting": k, "value": v} for k, v in data.items()]
        fmt.render(rows, "table", title="Effective configuration", console=ctx.console, output=ctx.output)
    return EXIT_OK if not args.check or data.get("connection") == "OK" else EXIT_CONNECTION


def cmd_check(args: argparse.Namespace, ctx: Ctx) -> int:
    """Step-by-step connection test: DNS, TCP port, TLS handshake, LDAP bind."""
    s = ctx.settings
    if args.demo:
        ctx.note("demo mode: the built-in directory needs no network check")
        return EXIT_OK
    if not s.server:
        raise LdapGrepError("No LDAP server configured.", EXIT_USAGE,
                            "Use --server ldaps://host, LDAPGREP_SERVER or a config file.")
    rows: list[dict[str, Any]] = []
    ok = True
    for step in probe_server(s):
        rows.append({"step": step.name, "status": "OK" if step.ok else "FAILED",
                     "detail": step.detail, "seconds": f"{step.elapsed:.2f}"})
        if not step.ok:
            ok = False
            break
    if ok:
        try:
            with connect(args, s, ctx) as client:
                rows.append({"step": "bind", "status": "OK", "detail": f"bound as {client.whoami()}", "seconds": ""})
                rows.append({"step": "directory", "status": "OK",
                             "detail": f"{client.flavor.name.upper()}, base {client.base_dn}, "
                                       f"schema {'loaded' if client.schema_available else 'not loaded'}",
                             "seconds": ""})
                flush_warnings(client, ctx)
        except LdapGrepError as exc:
            rows.append({"step": "bind", "status": "FAILED", "detail": exc.message, "seconds": ""})
            ok = False
    title = f"Connection check {s.display_url}"
    if ctx.format in ("json", "yaml"):
        fmt.render(rows, ctx.format, console=ctx.console, output=ctx.output)
    else:
        fmt.render(rows, "table", title=title, console=ctx.console, output=ctx.output)
    return EXIT_OK if ok else EXIT_CONNECTION


def cmd_tui(args: argparse.Namespace, ctx: Ctx) -> int:
    try:
        from . import tui
    except ImportError as exc:  # textual missing
        raise LdapGrepError(f"The console GUI needs the 'textual' package: {exc}", EXIT_USAGE,
                            "Install it with:  pip install textual") from exc
    if not sys.stdout.isatty():
        raise LdapGrepError("The console GUI needs an interactive terminal.", EXIT_USAGE)
    return tui.run(ctx.settings, demo=args.demo)


COMMANDS = {
    "user": cmd_user,
    "group": cmd_group,
    "groups": cmd_groups,
    "memberof": cmd_memberof,
    "compare": cmd_compare,
    "search": cmd_search,
    "info": cmd_info,
    "whoami": cmd_whoami,
    "schema": cmd_schema,
    "tree": cmd_tree,
    "config": cmd_config,
    "check": cmd_check,
    "tui": cmd_tui,
}


# --------------------------------------------------------------------------- #
# entry point
# --------------------------------------------------------------------------- #

class _SafeLogFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        return terminal_text(super().format(record), multiline=True)


def setup_logging(verbosity: int, quiet: bool) -> None:
    level = logging.ERROR if quiet else (logging.WARNING if verbosity == 0 else (logging.INFO if verbosity == 1 else logging.DEBUG))
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(_SafeLogFormatter("%(levelname)s: %(message)s"))
    logging.basicConfig(level=level, handlers=[handler])
    # library warnings are surfaced through Ctx.warn -> keep the logger quiet unless -v
    logging.getLogger("ldapgrep").setLevel(logging.INFO if verbosity else logging.ERROR)
    if verbosity >= 2:
        try:
            from ldap3.utils.log import BASIC, set_library_log_detail_level

            set_library_log_detail_level(BASIC)
            logging.getLogger("ldap3").setLevel(logging.DEBUG)
        except Exception:  # pragma: no cover
            pass


def _configure_stdout() -> None:
    for stream in (sys.stdout, sys.stderr):
        try:
            if hasattr(stream, "reconfigure") and (stream.encoding or "").lower().replace("-", "") not in ("utf8",):
                stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:  # pragma: no cover
            pass


def main(argv: Sequence[str] | None = None) -> int:
    _configure_stdout()
    argv_list = list(sys.argv[1:] if argv is None else argv)
    parser = build_parser()
    args = parser.parse_args(argv_list)
    setup_logging(args.verbose, args.quiet)

    try:
        settings = settings_from_args(args)
    except ConfigError as exc:
        print(f"error: {terminal_text(exc)}", file=sys.stderr)
        return EXIT_USAGE

    ctx = Ctx(args, settings)
    _warn_config_mismatch(args, settings, ctx)
    command = args.command
    if command is None:
        interactive = sys.stdout.isatty() and sys.stdin.isatty()
        if interactive:
            command = "tui"
            try:
                import textual  # noqa: F401
            except ImportError:
                parser.print_help()
                print("\n(install 'textual' for the console GUI, or run `ldapgrep group` for the default group)", file=sys.stderr)
                return EXIT_USAGE
        elif settings.default_group_dn or args.demo:
            command = "group"           # no command given: list the configured default group
            args.name = None
            for k, v in (("recursive", False), ("active", False), ("kind", "all"), ("memberof", False),
                         ("count", False), ("show", False), ("view", "compact"), ("attrs", None)):
                setattr(args, k, v)
        else:
            parser.print_help()
            return EXIT_USAGE

    try:
        return COMMANDS[command](args, ctx)
    except LdapGrepError as exc:
        ctx.err.print(f"[bold red]error:[/] {escape(terminal_text(exc.message))}")
        if exc.hint:
            ctx.err.print(Text("hint: " + terminal_text(exc.hint), style="dim"))
        if getattr(exc, "candidates", None) and not args.quiet:
            for c in exc.candidates[:10]:
                ctx.err.print(Text(f"  {terminal_text(c.login or c.display_name):<20} {terminal_text(c.dn)}"))
        return exc.exit_code
    except KeyboardInterrupt:
        ctx.err.print("[dim]interrupted[/]")
        return 130
    except BrokenPipeError:
        _silence_stdout()                 # reader went away (e.g. `| head`)
        return EXIT_OK
    finally:
        _flush_stdout()


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
