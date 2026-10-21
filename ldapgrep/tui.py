"""Interactive console GUI built with Textual.

    ldapgrep tui            # real server (prompts for missing connection data)
    ldapgrep tui --demo     # built-in demo directory

Keys (also shown in the footer / F1):
    /          focus the search box          Enter   search / open selected row
    F2 F3 F4   mode: users / groups / filter  m       members of group / groups of user
    r          toggle recursive               a       toggle "active accounts only"
    d          toggle detail <-> raw          e       export the current result
    c          copy DN to clipboard           i       server information
    s          switch server / profile        Backspace  back to the previous result
    F1         help                           q / Ctrl+Q  quit
"""

from __future__ import annotations

import threading
import time
import shlex
from dataclasses import dataclass, field, replace
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

from rich.console import Group
from rich.markup import escape
from rich.table import Table
from rich.text import Text
from textual import on, work
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.screen import ModalScreen
from textual.widgets import Button, Checkbox, DataTable, Footer, Header, Input, Label, Select, Static
from textual.worker import get_current_worker

from . import __version__
from . import format as fmt
from .client import AmbiguousMatch, LdapClient, LdapGrepError, ProbeStep, Record, is_broad_term, probe_server
from .config import PUBLIC_PROFILES, Settings, all_profiles, profile_settings
from .display import terminal_text
from .exports import default_export_dir

MODES = [("Users", "users"), ("Groups", "groups"), ("LDAP filter", "filter")]


@dataclass
class ResultSet:
    title: str
    kind: str                         # users | groups | members | memberof | raw
    records: list[Record] = field(default_factory=list)
    rows: list[dict[str, Any]] = field(default_factory=list)
    elapsed: float = 0.0
    query: str = ""
    comment: str = ""                 # '# ...' export header: the query, repeatable from the CLI


# --------------------------------------------------------------------------- #
# modal screens
# --------------------------------------------------------------------------- #

DEMO_CHOICE = "demo"
CUSTOM_CHOICE = "custom"


def shell_command(argv: list[str], shell: str) -> str:
    if any("\x00" in value for value in argv):
        raise ValueError("Shell arguments cannot contain NUL characters.")
    if shell == "posix":
        return shlex.join(argv)
    if shell == "powershell":
        return "& " + " ".join("'" + value.replace("'", "''") + "'" for value in argv)
    raise ValueError("Choose powershell or posix.")


def profile_choices(settings: Settings) -> list[tuple[str | Text, str]]:
    """(label, key) pairs for the server picker: config profiles, built-in public servers, demo, custom."""
    path = Path(settings.config_file) if settings.config_file else None
    choices: list[tuple[str | Text, str]] = []
    for name, source in all_profiles(path):
        try:
            ps = profile_settings(path, name)
            where = ps.display_url if ps.server else "(no server)"
        except Exception:  # unreadable profile: still offer it
            where = "?"
        tag = "public test server" if source == "built-in" else f"{settings.config_file and Path(settings.config_file).name}"
        choices.append((Text(terminal_text(f"{name}  -  {where}  [{tag}]")), f"profile:{name}"))
    choices.append(("Demo directory (offline, fictional data)", DEMO_CHOICE))
    choices.append(("Custom - type the connection data below", CUSTOM_CHOICE))
    return choices


class LoginScreen(ModalScreen[Optional[dict]]):
    """Pick a server (config profile, public test server, demo) and/or enter connection data.

    Dismisses with {"demo": True}, {"settings": Settings} or None (cancel)."""

    BINDINGS = [Binding("escape", "cancel", "Cancel")]
    DEFAULT_CSS = """
    LoginScreen { align: center middle; }
    #login { width: 90; height: auto; border: thick $accent; background: $surface; padding: 1 2; }
    #login Label { margin-top: 1; color: $text-muted; }
    #login .title { text-style: bold; color: $accent; margin-top: 0; }
    #login .error { color: $error; }
    #login Horizontal { height: auto; margin-top: 1; align-horizontal: right; }
    #login Button { margin-left: 1; }
    #login Checkbox { margin-top: 1; }
    """

    def __init__(self, settings: Settings, error: str = "", connected: bool = False) -> None:
        super().__init__()
        self.settings = settings
        self.error = error
        self.connected = connected          # True when switching servers inside a running session
        self.choices = profile_choices(settings)
        self.current: Settings = replace(settings)
        self._selected_choice = self._initial_choice()

    def _initial_choice(self) -> str:
        keys = {k for _, k in self.choices}
        if self.settings.fallback_profile and f"profile:{self.settings.fallback_profile}" in keys:
            return f"profile:{self.settings.fallback_profile}"
        if self.settings.profile and f"profile:{self.settings.profile}" in keys and self.settings.server:
            return f"profile:{self.settings.profile}"
        return CUSTOM_CHOICE

    def compose(self) -> ComposeResult:
        s = self.settings
        with Vertical(id="login"):
            yield Label("ldapgrep - connect to a directory", classes="title")
            if self.error:
                yield Label(Text(terminal_text(self.error)), classes="error")
            yield Label("Server / profile")
            yield Select(self.choices, value=self._initial_choice(), allow_blank=False, id="profile")
            yield Label("Server (ldap://host:389 or ldaps://host:636)")
            yield Input(value=s.server, placeholder="ldaps://dc01.example.com:636", id="server")
            yield Label("Bind DN / user@domain / DOMAIN\\user  (empty = anonymous)")
            yield Input(value=s.bind_dn, placeholder="CN=svc,OU=Service Accounts,DC=example,DC=com", id="bind_dn")
            yield Label("Password")
            yield Input(value=s.bind_password or "", password=True, placeholder="password", id="password")
            yield Label("Base DN (optional, auto-detected when empty)")
            yield Input(value=s.base_dn, placeholder="DC=example,DC=com", id="base_dn")
            yield Checkbox("Verify the TLS certificate", value=bool(s.tls_verify), id="tls_verify")
            with Horizontal():
                yield Button("Connect", variant="primary", id="connect")
                yield Button("Test", id="test")
                yield Button("Demo", id="demo")
                yield Button("Cancel" if self.connected else "Quit", id="quit")

    def on_mount(self) -> None:
        target = "server" if not self.settings.server else ("bind_dn" if not self.settings.bind_dn else "password")
        if self.settings.bind_password or self.settings.auth == "anonymous":
            target = "profile"
        self.query_one(f"#{target}").focus()

    def _fill(self, s: Settings) -> None:
        self.current = replace(s)
        self.query_one("#server", Input).value = s.server
        self.query_one("#bind_dn", Input).value = s.bind_dn if s.auth != "anonymous" else ""
        self.query_one("#password", Input).value = s.bind_password or ""
        self.query_one("#base_dn", Input).value = s.base_dn
        self.query_one("#tls_verify", Checkbox).value = bool(s.tls_verify)

    @on(Select.Changed, "#profile")
    def _profile_changed(self, event: Select.Changed) -> None:
        key = str(event.value)
        if key == self._selected_choice:
            return
        self._selected_choice = key
        if key.startswith("profile:"):
            name = key.split(":", 1)[1]
            path = Path(self.settings.config_file) if self.settings.config_file else None
            try:
                self._fill(profile_settings(path, name))
            except Exception as exc:
                self._fill(Settings(config_file=self.settings.config_file))
                self.notify(f"profile {name}: {exc}", severity="error")
        elif key == CUSTOM_CHOICE:
            # fresh connection settings: do not drag OUs / default group of another profile along
            fresh = Settings()
            for k in ("timeout", "page_size", "load_schema", "date_format", "min_search_length",
                      "user_extra_attributes", "group_extra_attributes", "config_file"):
                setattr(fresh, k, getattr(self.current, k))
            self._fill(fresh)
            self.query_one("#server", Input).focus()
        elif key == DEMO_CHOICE:
            self._fill(Settings())

    def _collect(self) -> dict:
        key = str(self.query_one("#profile", Select).value)
        if key == DEMO_CHOICE:
            return {"demo": True}
        s = replace(self.current)
        s.server = self.query_one("#server", Input).value.strip()
        s.bind_dn = self.query_one("#bind_dn", Input).value.strip()
        s.bind_password = self.query_one("#password", Input).value
        s.base_dn = self.query_one("#base_dn", Input).value.strip()
        s.tls_verify = self.query_one("#tls_verify", Checkbox).value
        if not s.bind_dn and not s.bind_password:
            s.auth = "anonymous"
        elif s.auth == "anonymous":
            s.auth = "simple"
        s.fallback_profile = ""
        return {"settings": s}

    def _ready(self) -> bool:
        key = str(self.query_one("#profile", Select).value)
        if key == DEMO_CHOICE:
            return True
        server = self.query_one("#server", Input).value.strip()
        bind_dn = self.query_one("#bind_dn", Input).value.strip()
        password = self.query_one("#password", Input).value
        return bool(server) and (bool(bind_dn) == bool(password))

    @on(Button.Pressed, "#connect")
    def _connect(self) -> None:
        if self._ready():
            self.dismiss(self._collect())
        else:
            self.notify("Server and either bind DN + password or nothing (anonymous) are needed.", severity="warning")

    @on(Button.Pressed, "#test")
    def _test(self) -> None:
        """Pre-flight check of the typed connection data: DNS, TCP port, TLS (no bind)."""
        if str(self.query_one("#profile", Select).value) == DEMO_CHOICE:
            self.notify("The demo directory is offline - nothing to test.", timeout=3)
            return
        server = self.query_one("#server", Input).value.strip()
        if not server:
            self.notify("Enter a server first.", severity="warning")
            return
        settings = self._collect()["settings"]
        self.notify(f"testing {settings.display_url} ...", timeout=3)
        self._probe_worker(settings)

    @work(thread=True, exit_on_error=False, group="probe")
    def _probe_worker(self, settings: Settings) -> None:
        steps: list[ProbeStep] = []
        try:
            for step in probe_server(settings):
                steps.append(step)
                if not step.ok:
                    break
        except Exception as exc:  # pragma: no cover - unexpected
            steps.append(ProbeStep("probe", False, f"{type(exc).__name__}: {exc}"))
        self.call_from_thread(self._show_probe, settings.display_url, steps)

    def _show_probe(self, url: str, steps: list[ProbeStep]) -> None:
        table = Table(show_header=False, box=None, pad_edge=False)
        table.add_column("step", style="cyan", no_wrap=True)
        table.add_column("status", no_wrap=True)
        table.add_column("detail", overflow="fold")
        for st in steps:
            status = Text("OK", style="green") if st.ok else Text("FAILED", style="bold red")
            table.add_row(Text(terminal_text(st.name)), status, Text(terminal_text(st.detail)))
        hint = "\nAll good - press Connect to bind." if steps and all(s.ok for s in steps) else ""
        self.app.push_screen(TextScreen(f"Connection test {url}", Group(table, Text(hint, style="dim"))))

    @on(Button.Pressed, "#demo")
    def _demo(self) -> None:
        self.dismiss({"demo": True})

    @on(Button.Pressed, "#quit")
    def action_cancel(self) -> None:
        self.dismiss(None)

    @on(Input.Submitted)
    def _submitted(self, event: Input.Submitted) -> None:
        if event.input.id == "password" or self._ready():
            self._connect()
        else:
            self.focus_next()


class ExportScreen(ModalScreen[Optional[tuple[str, str, bool]]]):
    """Dismisses with (format, filename, include_query_comment) or None (cancel)."""

    BINDINGS = [Binding("escape", "cancel", "Cancel")]
    DEFAULT_CSS = """
    ExportScreen { align: center middle; }
    #export { width: 70; height: auto; border: thick $accent; background: $surface; padding: 1 2; }
    #export Label { margin-top: 1; color: $text-muted; }
    #export .title { text-style: bold; color: $accent; margin-top: 0; }
    #export Checkbox { margin-top: 1; }
    #export Horizontal { height: auto; margin-top: 1; align-horizontal: right; }
    #export Button { margin-left: 1; }
    """

    def __init__(self, default_name: str, has_query: bool = True) -> None:
        super().__init__()
        self.default_name = default_name
        self.has_query = has_query

    def compose(self) -> ComposeResult:
        with Vertical(id="export"):
            yield Label("Export current result", classes="title")
            yield Label("Format")
            yield Select([(f, f) for f in ("csv", "json", "tsv", "ldif", "yaml", "table")], value="csv", id="format", allow_blank=False)
            yield Label("File name")
            yield Input(value=f"{self.default_name}.csv", id="filename")
            box = Checkbox("include the LDAP query as a comment (repeatable from the CLI)",
                           value=False, id="query_comment")
            box.disabled = not self.has_query
            yield box
            with Horizontal():
                yield Button("Export", variant="primary", id="ok")
                yield Button("Cancel", id="cancel")

    @on(Select.Changed, "#format")
    def _fmt_changed(self, event: Select.Changed) -> None:
        name = self.query_one("#filename", Input)
        stem = name.value.rsplit(".", 1)[0] if "." in name.value else name.value
        ext = "txt" if event.value == "table" else str(event.value)
        name.value = f"{stem}.{ext}"
        box = self.query_one("#query_comment", Checkbox)
        box.disabled = not self.has_query or event.value == "json"    # json has no comments

    @on(Button.Pressed, "#ok")
    @on(Input.Submitted, "#filename")
    def _ok(self) -> None:
        box = self.query_one("#query_comment", Checkbox)
        self.dismiss((str(self.query_one("#format", Select).value),
                      self.query_one("#filename", Input).value.strip(),
                      bool(box.value) and not box.disabled))

    @on(Button.Pressed, "#cancel")
    def action_cancel(self) -> None:
        self.dismiss(None)


class ConfirmScreen(ModalScreen[bool]):
    """Yes/No question (e.g. before a broad '*' search)."""

    BINDINGS = [Binding("escape", "no", "No"), Binding("n", "no", "No"), Binding("y", "yes", "Yes")]
    DEFAULT_CSS = """
    ConfirmScreen { align: center middle; }
    #confirm { width: 70; height: auto; border: thick $warning; background: $surface; padding: 1 2; }
    #confirm .title { text-style: bold; color: $warning; }
    #confirm Static { margin-top: 1; }
    #confirm Horizontal { height: auto; margin-top: 1; align-horizontal: right; }
    #confirm Button { margin-left: 1; }
    """

    def __init__(self, title: str, message: str) -> None:
        super().__init__()
        self.title_text = title
        self.message = message

    def compose(self) -> ComposeResult:
        with Vertical(id="confirm"):
            yield Label(Text(terminal_text(self.title_text)), classes="title")
            yield Static(Text(terminal_text(self.message, multiline=True)))
            with Horizontal():
                yield Button("Yes, search everything", variant="warning", id="yes")
                yield Button("No", variant="primary", id="no")

    @on(Button.Pressed, "#yes")
    def action_yes(self) -> None:
        self.dismiss(True)

    @on(Button.Pressed, "#no")
    def action_no(self) -> None:
        self.dismiss(False)


class TextScreen(ModalScreen[None]):
    """Scrollable text popup (help, server info, errors)."""

    BINDINGS = [Binding("escape", "close", "Close"), Binding("q", "close", "Close"), Binding("enter", "close", "Close")]
    DEFAULT_CSS = """
    TextScreen { align: center middle; }
    #popup { width: 90%; height: 80%; border: thick $accent; background: $surface; padding: 1 2; }
    #popup .title { text-style: bold; color: $accent; }
    #popup VerticalScroll { height: 1fr; margin-top: 1; }
    """

    def __init__(self, title: str, body: Any) -> None:
        super().__init__()
        self.title_text = title
        self.body = body

    def compose(self) -> ComposeResult:
        with Vertical(id="popup"):
            yield Label(Text(terminal_text(self.title_text)), classes="title")
            with VerticalScroll():
                yield Static(self.body)
            yield Label("[dim]Esc / Enter to close[/]")

    def action_close(self) -> None:
        self.dismiss(None)


HELP_TEXT = """\
[b]Search[/b]
  Type in the search box and press [b]Enter[/b].  F2 = users, F3 = groups, F4 = raw LDAP filter.
  Users: login, name, mail, UPN, employee id, 'First Last', wildcards (*), umlauts in any spelling.
  Groups: substring of the group name.
  Broad wildcard searches ('*', 'a*', ...) are blocked while min_search_length >= 2 (the default).
  With a lower min_search_length you are asked for confirmation before the whole directory is read.

[b]Navigation[/b]
  Up/Down        move in the result list (detail panel follows)
  Enter / m      group -> its members,  user -> their groups
  Backspace      back to the previous result
  Tab            switch focus between search box, results and detail panel
  /              jump to the search box

[b]Toggles[/b]
  r              recursive (nested groups) on/off
  a              only enabled accounts on/off
  d              detail panel: summary <-> all attributes

[b]Actions[/b]
  e              export the current result (csv/json/tsv/ldif/yaml/table);
                 optionally with the LDAP query as a comment, so it can be repeated from the CLI
  c              copy the DN of the selected entry to the clipboard
  i              server information
  s              switch server / profile (the login dialog also has a connection [b]Test[/b] button)
  F1             this help      q / Ctrl+Q   quit
"""


# --------------------------------------------------------------------------- #
# the application
# --------------------------------------------------------------------------- #

class LdapGrepApp(App[int]):
    TITLE = "ldapgrep"
    SUB_TITLE = f"v{__version__}"
    CSS = """
    Screen { layout: vertical; }
    #topbar { height: 3; padding: 0 1; background: $panel; }
    #mode { width: 18; }
    #search { width: 1fr; }
    #flags { width: auto; min-width: 40; content-align: right middle; color: $text-muted; padding: 0 1; }
    #main { height: 1fr; }
    #results { width: 58%; height: 1fr; border: round $primary; }
    #results:focus { border: round $accent; }
    #detail { width: 1fr; height: 1fr; border: round $primary; padding: 0 1; }
    #detail:focus { border: round $accent; }
    #status { height: 1; padding: 0 1; background: $panel; color: $text-muted; }
    .flag-on { color: $success; text-style: bold; }
    """
    BINDINGS = [
        Binding("f1", "help", "Help"),
        Binding("slash", "focus_search", "Search"),
        Binding("f2", "set_mode('users')", "Users"),
        Binding("f3", "set_mode('groups')", "Groups"),
        Binding("f4", "set_mode('filter')", "Filter"),
        Binding("m", "drill", "Members/Groups"),
        Binding("r", "toggle_recursive", "Recursive"),
        Binding("a", "toggle_active", "Active only"),
        Binding("d", "toggle_raw", "Detail/Raw"),
        Binding("backspace", "back", "Back"),
        Binding("e", "export", "Export"),
        Binding("c", "copy_dn", "Copy DN"),
        Binding("i", "server_info", "Info"),
        Binding("s", "switch_server", "Server"),
        Binding("q", "quit", "Quit"),
        Binding("ctrl+q", "quit", "Quit", show=False),
        Binding("escape", "focus_results", "Results", show=False),
    ]

    def __init__(self, settings: Settings, demo: bool = False) -> None:
        super().__init__()
        self.settings = settings
        self.demo = demo
        self.client: LdapClient | None = None
        self.lock = threading.Lock()
        self.mode = "users"
        self.recursive = False
        self.active_only = False
        self.raw_detail = False
        self.history: list[ResultSet] = []
        self.current: ResultSet | None = None
        self.by_dn: dict[str, Record] = {}

    def notify(self, message: str, **kwargs: Any) -> None:
        if "title" in kwargs:
            kwargs["title"] = escape(terminal_text(kwargs["title"]))
        super().notify(escape(terminal_text(message, multiline=True)), **kwargs)

    # ---- layout ---------------------------------------------------------- #
    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with Horizontal(id="topbar"):
            yield Select(MODES, value="users", id="mode", allow_blank=False)
            yield Input(placeholder="search users: login, name, mail, 'First Last', wild*card ...", id="search")
            yield Static("", id="flags")
        with Horizontal(id="main"):
            table: DataTable = DataTable(id="results", cursor_type="row", zebra_stripes=True)
            yield table
            yield VerticalScroll(Static("", id="detail_text"), id="detail")
        yield Static("not connected", id="status")
        yield Footer()

    def on_mount(self) -> None:
        self._update_flags()
        self.query_one("#search", Input).focus()
        s = self.settings
        complete = s.server and not s.fallback_profile and (
            s.auth == "anonymous" or (s.bind_dn and s.bind_password))
        if self.demo or complete:
            self._connect_worker(self.demo)
        else:
            # nothing (or only the public fallback) configured: let the user pick a server
            self.push_screen(LoginScreen(self.settings), self._login_result)

    # ---- connection ------------------------------------------------------ #
    def _login_result(self, data: dict | None) -> None:
        if data is None:
            if self.client is None:
                self.exit(2)
            return                                   # cancelled a server switch: keep the session
        self._disconnect()
        if data.get("demo"):
            self.demo = True
            self._connect_worker(True)
            return
        self.demo = False
        self.settings = data["settings"]
        self._connect_worker(False)

    def _disconnect(self) -> None:
        """Close the current connection and clear everything that belongs to it."""
        with self.lock:
            if self.client is not None:
                try:
                    self.client.close()
                except Exception:
                    pass
            self.client = None
        self.history.clear()
        self.current = None
        self.by_dn = {}
        self.query_one("#results", DataTable).clear(columns=True)
        self.query_one("#detail_text", Static).update("")
        self.sub_title = ""
        self._set_status("not connected")

    def action_switch_server(self) -> None:
        self.push_screen(LoginScreen(self.settings, connected=self.client is not None), self._login_result)

    @work(thread=True, exclusive=True, group="connect", exit_on_error=False)
    def _connect_worker(self, demo: bool) -> None:
        self.call_from_thread(self._set_status, "connecting ...")
        try:
            client = LdapClient(self.settings, demo=demo).connect()
        except LdapGrepError as exc:
            self.call_from_thread(self._connect_failed, str(exc))
            return
        except Exception as exc:  # pragma: no cover - unexpected
            self.call_from_thread(self._connect_failed, f"{type(exc).__name__}: {exc}")
            return
        self.call_from_thread(self._connected, client)

    def _connect_failed(self, message: str) -> None:
        self._set_status("[red]connection failed[/]")
        self.push_screen(LoginScreen(self.settings, error=message), self._login_result)

    def _connected(self, client: LdapClient) -> None:
        self.client = client
        info = client.server_info()
        self.sub_title = terminal_text(f"{info.get('server')}  |  {client.flavor.name.upper()}  |  {client.base_dn}")
        self._set_status(f"connected as [b]{escape(client.whoami())}[/]  -  type a search term and press Enter  -  F1 help")
        for w in client.warnings:
            self.notify(w, severity="warning", timeout=8)
        client.warnings.clear()
        if self.demo:
            self.notify("Demo mode: fictional in-memory directory. Try 'mül', 'IT' (F3) or 'All Staff'.", timeout=10)

    # ---- status / flags -------------------------------------------------- #
    def _set_status(self, text: str) -> None:
        self.query_one("#status", Static).update(terminal_text(text, multiline=True))

    def _update_flags(self) -> None:
        def flag(on: bool, label: str) -> str:
            return f"[green b]{label}[/]" if on else f"[dim]{label}[/]"
        self.query_one("#flags", Static).update(
            f"{flag(self.recursive, 'r:recursive')}  {flag(self.active_only, 'a:active only')}  {flag(self.raw_detail, 'd:raw')}"
        )
        placeholder = {
            "users": "search users: login, name, mail, 'First Last', wild*card ...",
            "groups": "search groups by name (substring), '*' for all ...",
            "filter": "raw LDAP filter, e.g. (&(objectClass=user)(title=*Engineer*))",
        }[self.mode]
        self.query_one("#search", Input).placeholder = placeholder

    # ---- actions --------------------------------------------------------- #
    def action_help(self) -> None:
        self.push_screen(TextScreen(f"ldapgrep v{__version__} - keyboard reference", HELP_TEXT))

    def action_focus_search(self) -> None:
        box = self.query_one("#search", Input)
        box.focus()

    def action_focus_results(self) -> None:
        self.query_one("#results", DataTable).focus()

    def action_set_mode(self, mode: str) -> None:
        self.mode = mode
        self.query_one("#mode", Select).value = mode
        self._update_flags()
        self.action_focus_search()

    def action_toggle_recursive(self) -> None:
        self.recursive = not self.recursive
        self._update_flags()
        self.notify(f"recursive {'on' if self.recursive else 'off'}", timeout=2)

    def action_toggle_active(self) -> None:
        self.active_only = not self.active_only
        self._update_flags()
        self.notify(f"active accounts only {'on' if self.active_only else 'off'}", timeout=2)

    def action_toggle_raw(self) -> None:
        self.raw_detail = not self.raw_detail
        self._update_flags()
        self._show_detail(self._selected_record())

    def action_back(self) -> None:
        if self.focused is not None and isinstance(self.focused, Input) and self.focused.value:
            # let Backspace edit the search box when it has text
            self.focused.action_delete_left()
            return
        if not self.history:
            self.notify("no previous result", timeout=2)
            return
        self._render_result(self.history.pop(), push=False)

    def action_drill(self) -> None:
        rec = self._selected_record()
        if rec is None:
            return
        if rec.is_group:
            self._search_worker("members", rec.dn, rec.display_name)
        else:
            self._search_worker("memberof", rec.dn, rec.display_name)

    def action_copy_dn(self) -> None:
        rec = self._selected_record()
        if rec is None:
            return
        try:
            import pyperclip  # type: ignore

            pyperclip.copy(rec.dn)
            self.notify("DN copied to clipboard", timeout=3)
        except Exception:
            self.notify(f"clipboard not available - DN: {rec.dn}", severity="warning", timeout=10)

    def action_server_info(self) -> None:
        if self.client is None:
            return
        with self.lock:
            info = self.client.server_info()
            info["whoami"] = self.client.whoami()
        table = Table(show_header=False, box=None, pad_edge=False)
        table.add_column("key", style="cyan")
        table.add_column("value")
        for k, v in info.items():
            table.add_row(Text(terminal_text(k)), Text(terminal_text(fmt.flatten_value(v, "\n"), multiline=True)))
        self.push_screen(TextScreen("Server information", table))

    def action_export(self) -> None:
        if not self.current or not self.current.rows:
            self.notify("nothing to export", severity="warning", timeout=3)
            return
        default = str(default_export_dir() / fmt.auto_filename(self.current.query or self.current.kind, "x")[:-2])
        self.push_screen(ExportScreen(default, has_query=bool(self.current.comment)), self._export_result)

    def _export_result(self, data: tuple[str, str, bool] | None) -> None:
        if not data or not self.current:
            return
        f, filename, with_comment = data
        try:
            fmt.render(self.current.rows, f, output=filename, title=self.current.title,
                       comment=self.current.comment if with_comment else None)
        except (OSError, ValueError) as exc:
            self.notify(f"export failed: {exc}", severity="error", timeout=8)
            return
        self.notify(f"{len(self.current.rows)} entries written to {filename}", timeout=6)

    # ---- events ---------------------------------------------------------- #
    @on(Select.Changed, "#mode")
    def _mode_changed(self, event: Select.Changed) -> None:
        if event.value in ("users", "groups", "filter"):
            self.mode = str(event.value)
            self._update_flags()

    @on(Input.Submitted, "#search")
    def _search_submitted(self, event: Input.Submitted) -> None:
        term = event.value.strip()
        if not term:
            return
        if self.mode in ("users", "groups") and is_broad_term(term):
            min_len = max(0, int(self.settings.min_search_length or 0))
            if min_len >= 2:
                self._search_failed(f"'{term}': broad wildcard searches are blocked (min_search_length = {min_len}). "
                                    "Use at least 2 characters before the wildcard.")
                return
            self.push_screen(
                ConfirmScreen(
                    "Broad search",
                    f"'{term}' can match every entry of the directory.\n"
                    "On a large directory this is slow and produces a lot of traffic.\n"
                    "Are you sure you want to search everything?",
                ),
                lambda ok: self._start_search(term, allow_broad=bool(ok)) if ok else None,
            )
            return
        self._start_search(term)

    def _start_search(self, term: str, allow_broad: bool = False) -> None:
        self._search_worker(self.mode, term, term, allow_broad=allow_broad)
        self.action_focus_results()

    @on(DataTable.RowHighlighted, "#results")
    def _row_highlighted(self, event: DataTable.RowHighlighted) -> None:
        if event.row_key is not None and event.row_key.value is not None:
            self._show_detail(self.by_dn.get(str(event.row_key.value)))

    @on(DataTable.RowSelected, "#results")
    def _row_selected(self, event: DataTable.RowSelected) -> None:
        self.action_drill()

    # ---- searching ------------------------------------------------------- #
    def _selected_record(self) -> Record | None:
        table = self.query_one("#results", DataTable)
        if table.row_count == 0 or table.cursor_row is None:
            return None
        try:
            key = table.coordinate_to_cell_key(table.cursor_coordinate).row_key
        except Exception:
            return None
        return self.by_dn.get(str(key.value)) if key.value is not None else None

    @work(thread=True, exclusive=True, group="search", exit_on_error=False)
    def _search_worker(self, kind: str, query: str, label: str, allow_broad: bool = False) -> None:
        if self.client is None:
            self.call_from_thread(self.notify, "not connected", severity="error")
            return
        worker = get_current_worker()
        self.call_from_thread(self._set_status, f"searching {escape(label)} ...")
        started = time.perf_counter()
        s = self.settings
        try:
            with self.lock:
                c = self.client
                user_attrs = fmt.user_attributes("detail", s, include_memberof=True)
                group_attrs = fmt.group_attributes("detail", s)
                if kind == "users":
                    recs = c.search_users(query, user_attrs, mode="prefix", active_only=self.active_only,
                                          limit=2000, allow_broad=allow_broad)
                    rows = [fmt.user_to_dict(r, "compact", s) for r in recs]
                    title = f"Users matching '{label}'"
                elif kind == "groups":
                    recs = c.list_groups(query, group_attrs, mode="contains", limit=2000, allow_broad=allow_broad)
                    recs.sort(key=lambda r: r.display_name.lower())
                    rows = [fmt.group_to_dict(r, "compact", s) for r in recs]
                    title = f"Groups matching '{label}'"
                elif kind == "filter":
                    recs = c.search(query, None, limit=2000)
                    rows = [fmt.record_to_raw(r, s) for r in recs]
                    title = f"Filter {label}"
                elif kind == "members":
                    attrs = list(user_attrs or []) + list(group_attrs or [])
                    recs = c.group_members(query, attrs, recursive=self.recursive, active_only=self.active_only)
                    rows = [fmt.member_to_dict(r, "compact", s) for r in recs]
                    title = f"Members of {label}" + (" (recursive)" if self.recursive else "")
                elif kind == "memberof":
                    user = c.get_entry(query, ["cn", "displayName", "memberOf", "primaryGroupID", "objectClass", "sAMAccountName", "uid"])
                    recs = c.user_groups(user, recursive=self.recursive, attributes=group_attrs) if user else []
                    rows = [fmt.group_to_dict(r, "compact", s) for r in recs]
                    title = f"Groups of {label}" + (" (recursive)" if self.recursive else "")
                else:  # pragma: no cover
                    return
                comment = self._build_comment(kind, label, c)
                warnings = list(c.warnings)
                c.warnings.clear()
        except AmbiguousMatch as exc:
            self.call_from_thread(self._search_failed, exc.message)
            return
        except LdapGrepError as exc:
            self.call_from_thread(self._search_failed, str(exc))
            return
        except Exception as exc:  # pragma: no cover - unexpected
            self.call_from_thread(self._search_failed, f"{type(exc).__name__}: {exc}")
            return
        if worker.is_cancelled:
            return
        result = ResultSet(title=title, kind=kind, records=recs, rows=rows, elapsed=time.perf_counter() - started,
                           query=label, comment=comment)
        self.call_from_thread(self._render_result, result, True, warnings)

    def _build_comment(self, kind: str, label: str, client: LdapClient) -> str:
        """'# ...' header for exports: how this result was produced and how to repeat it on the CLI."""
        command = {"users": "user", "groups": "groups", "filter": "search",
                   "members": "group", "memberof": "memberof"}.get(kind, "search")
        argv = ["ldapgrep", command, label]
        if kind in ("members", "memberof") and self.recursive:
            argv.append("--recursive")
        lines = [
            f"exported by ldapgrep v{__version__} (console GUI) on {datetime.now():%Y-%m-%d %H:%M:%S}",
            "repeat with: choose your shell",
            "PowerShell: " + shell_command(argv, "powershell"),
            "POSIX:      " + shell_command(argv, "posix"),
        ]
        if client.last_query:
            base, scope, flt = client.last_query
            cli_scope = {"BASE": "base", "LEVEL": "one", "SUBTREE": "sub"}.get(str(scope), str(scope).lower())
            lines += [
                f"server:      {'demo (built-in directory)' if self.demo else self.settings.display_url}",
                f"search base: {base}   scope: {cli_scope}",
                f"ldap filter: {flt}",
                "raw query (PowerShell): " + shell_command(
                    ["ldapgrep", "search", flt, "--base", base, "--scope", cli_scope], "powershell"),
                "raw query (POSIX): " + shell_command(
                    ["ldapgrep", "search", flt, "--base", base, "--scope", cli_scope], "posix"),
            ]
        return "\n".join(lines)

    def _search_failed(self, message: str) -> None:
        self._set_status(f"[red]{escape(message)}[/]")
        self.notify(message, severity="error", timeout=8)

    def _render_result(self, result: ResultSet, push: bool = True, warnings: list[str] | None = None) -> None:
        if push and self.current is not None:
            self.history.append(self.current)
            del self.history[:-25]
        self.current = result
        self.by_dn = {r.dn: r for r in result.records}
        table = self.query_one("#results", DataTable)
        table.clear(columns=True)

        if result.kind in ("users",):
            columns = [("login", "name"), ("name", "givenName_surname"), ("mail", "email"), ("office / dept", "office_department"),
                       ("title", "title"), ("disabled", "disabled")]
        elif result.kind in ("groups", "memberof"):
            columns = [("group", "name"), ("description", "description"), ("type", "type"), ("members", "member_count")]
        elif result.kind == "members":
            columns = [("login / group", "name"), ("name", "givenName_surname"), ("mail", "email"),
                       ("office / dept", "office_department"), ("type", "type"), ("disabled", "disabled")]
        else:
            keys = fmt.collect_keys(result.rows)
            preferred = [k for k in ("cn", "sAMAccountName", "uid", "mail", "objectClass") if k in keys]
            columns = [(k, k) for k in (preferred or keys[:5])] + [("dn", "dn")]

        for label, _key in columns:
            table.add_column(Text(terminal_text(label)), key=_key)
        for rec, row in zip(result.records, result.rows):
            cells = []
            for _label, key in columns:
                v = row.get(key, "")
                if key == "description" and not v and rec.is_group is False and result.kind == "members":
                    v = ""
                cells.append(fmt.style_cell(key, v if v != [] else ""))
            table.add_row(*cells, key=rec.dn)

        n = len(result.rows)
        hist = f"  -  Backspace: back ({len(self.history)})" if self.history else ""
        self._set_status(f"[b]{escape(result.title)}[/]  -  {n} result{'s' if n != 1 else ''} in {result.elapsed:.2f}s{hist}")
        self.title = "ldapgrep - " + terminal_text(result.title)
        for w in warnings or []:
            self.notify(w, severity="warning", timeout=6)
        if n:
            table.focus()
            table.move_cursor(row=0)
            self._show_detail(result.records[0])
        else:
            self._show_detail(None)
            self.notify("no results", timeout=3)

    # ---- detail panel ---------------------------------------------------- #
    def _show_detail(self, rec: Record | None) -> None:
        panel = self.query_one("#detail_text", Static)
        if rec is None:
            panel.update(Text("select an entry to see its details", style="dim"))
            return
        s = self.settings
        if self.raw_detail:
            data = fmt.record_to_raw(rec, s)
            heading = Text(f"{terminal_text(rec.display_name)}  (all {len(data) - 1} attributes)", style="bold")
        elif rec.is_group:
            data = fmt.group_to_dict(rec, "full", s)
            heading = Text(f"{terminal_text(rec.display_name)}  (group)", style="bold magenta")
        else:
            data = fmt.user_to_dict(rec, "full", s, include_memberof=rec.has("memberOf"))
            data = {k: v for k, v in data.items() if v not in ("", None, [])}
            heading = Text(terminal_text(rec.display_name), style="bold")
            if rec.disabled:
                heading.append("  DISABLED", style="bold red")
            if rec.locked:
                heading.append("  LOCKED", style="bold yellow")
            if rec.is_computer:
                heading.append("  computer", style="yellow")

        table = Table(show_header=False, box=None, pad_edge=False, expand=True)
        table.add_column("attr", style="cyan", no_wrap=True, ratio=1)
        table.add_column("value", ratio=3, overflow="fold")
        for k, v in data.items():
            if isinstance(v, list):
                value = Text("\n".join(terminal_text(fmt.flatten_value(x)) for x in v))
            elif isinstance(v, bool):
                value = Text("yes" if v else "no", style="red" if (v and k in ("disabled", "locked")) else "")
            else:
                value = Text(terminal_text(fmt.flatten_value(v)))
            table.add_row(Text(terminal_text(k)), value)
        hint = Text("\nEnter/m: " + ("members" if rec.is_group else "groups") + "   d: raw   c: copy DN", style="dim")
        panel.update(Group(heading, Text(""), table, hint))

    # ---- lifecycle ------------------------------------------------------- #
    def action_quit(self) -> None:
        if self.client is not None:
            try:
                self.client.close()
            except Exception:
                pass
        self.exit(0)


def run(settings: Settings, demo: bool = False) -> int:
    app = LdapGrepApp(settings, demo=demo)
    result = app.run()
    return int(result) if isinstance(result, int) else 0
