import asyncio
import io

import pytest

pytest.importorskip("textual")

from textual.widgets import DataTable, Input  # noqa: E402
from rich.console import Console  # noqa: E402

from ldapgrep import __version__  # noqa: E402
from ldapgrep.config import Settings  # noqa: E402
from ldapgrep.tui import LdapGrepApp  # noqa: E402


async def _wait_until(pilot, predicate, timeout=10.0):
    for _ in range(int(timeout / 0.1)):
        if predicate():
            return True
        await pilot.pause(0.1)
    return False


def test_tui_demo_flow():
    async def scenario():
        app = LdapGrepApp(Settings(), demo=True)
        async with app.run_test(size=(140, 40)) as pilot:
            assert await _wait_until(pilot, lambda: app.client is not None), "demo connection"
            table = app.query_one("#results", DataTable)

            # search a user
            box = app.query_one("#search", Input)
            box.focus()
            await pilot.press(*"mül", "enter")
            assert await _wait_until(pilot, lambda: table.row_count == 1), "search result"
            assert app.current.kind == "users"
            detail = app.query_one("#detail_text")
            content = detail.renderable if hasattr(detail, "renderable") else detail.content
            capture = io.StringIO()
            Console(file=capture, width=140, color_system=None).print(content)
            assert "Max Müller" in capture.getvalue()

            # Enter on the user -> their groups
            table.focus()
            await pilot.press("enter")
            assert await _wait_until(pilot, lambda: app.current is not None and app.current.kind == "memberof"), "memberof"
            assert table.row_count == 2       # Domain Users + IT-Admins
            assert len(app.history) == 1

            # recursive on, drill again from history
            await pilot.press("backspace")
            await pilot.pause(0.2)
            assert app.current.kind == "users" and not app.history
            await pilot.press("r")
            await pilot.press("m")
            assert await _wait_until(pilot, lambda: app.current.kind == "memberof" and table.row_count == 6), "recursive memberof"

            # groups mode: members of a group
            await pilot.press("f3")
            await pilot.pause(0.1)
            await pilot.press(*"all staff", "enter")
            assert await _wait_until(pilot, lambda: app.current.kind == "groups" and table.row_count == 1), "group search"
            table.focus()
            await pilot.press("enter")
            assert await _wait_until(pilot, lambda: app.current.kind == "members"), "members"
            assert table.row_count == 32 + 8 or table.row_count >= 32   # recursive: users + nested groups

            # raw filter mode
            await pilot.press("f4")
            await pilot.pause(0.1)
            await pilot.press(*"(department=Legal)", "enter")
            assert await _wait_until(pilot, lambda: app.current.kind == "raw" or app.current.kind == "filter"), "filter"
            assert table.row_count == 3

            # toggles and popups must not crash
            await pilot.press("d")
            await pilot.press("i")
            await pilot.pause(0.1)
            await pilot.press("escape")
            await pilot.press("f1")
            await pilot.pause(0.1)
            assert f"v{__version__}" in app.screen.title_text
            await pilot.press("escape")
            await pilot.press("q")

    asyncio.run(scenario())


def test_tui_login_screen_without_settings():
    async def scenario():
        app = LdapGrepApp(Settings(), demo=False)
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause(0.2)
            assert app.screen.__class__.__name__ == "LoginScreen"
            await pilot.press("escape")
            await pilot.pause(0.2)
        assert app.return_value == 2

    asyncio.run(scenario())


def test_tui_login_screen_server_picker():
    from textual.widgets import Select

    async def scenario():
        app = LdapGrepApp(Settings(), demo=False)
        async with app.run_test(size=(120, 45)) as pilot:
            await pilot.pause(0.2)
            screen = app.screen
            assert screen.__class__.__name__ == "LoginScreen"
            picker = screen.query_one("#profile", Select)
            keys = [k for _, k in picker._options] if hasattr(picker, "_options") else []
            assert "profile:debian" in keys and "demo" in keys and "custom" in keys
            picker.value = "profile:debian"
            await pilot.pause(0.3)
            assert screen.query_one("#server", Input).value == "ldap://db.debian.org:389"
            assert screen.query_one("#bind_dn", Input).value == ""
            picker.value = "profile:forumsys"
            await pilot.pause(0.3)
            assert screen.query_one("#bind_dn", Input).value.startswith("cn=read-only-admin")
            data = screen._collect()
            assert data["settings"].server.startswith("ldap://ldap.forumsys.com") and data["settings"].auth == "simple"
            picker.value = "demo"
            await pilot.pause(0.2)
            assert screen._collect() == {"demo": True}
            await pilot.press("escape")
            await pilot.pause(0.2)
        assert app.return_value == 2

    asyncio.run(scenario())


def test_tui_broad_search_guard():
    async def scenario():
        app = LdapGrepApp(Settings(), demo=True)
        async with app.run_test(size=(120, 40)) as pilot:
            assert await _wait_until(pilot, lambda: app.client is not None), "demo connection"
            box = app.query_one("#search", Input)
            box.focus()
            # default min_search_length = 2: '*' is refused without touching the server
            await pilot.press("*", "enter")
            await pilot.pause(0.3)
            assert app.current is None
            # min_search_length lowered: a confirmation dialog appears first
            app.settings.min_search_length = 0
            box.value = ""
            box.focus()
            await pilot.press("*", "enter")
            await pilot.pause(0.3)
            assert app.screen.__class__.__name__ == "ConfirmScreen"
            await pilot.press("y")
            assert await _wait_until(pilot, lambda: app.current is not None and app.current.kind == "users")
            assert app.query_one("#results", DataTable).row_count >= 30
            await pilot.press("q")

    asyncio.run(scenario())


def test_tui_export_with_query_comment(tmp_path):
    from ldapgrep.tui import ExportScreen

    async def scenario():
        app = LdapGrepApp(Settings(), demo=True)
        async with app.run_test(size=(120, 40)) as pilot:
            assert await _wait_until(pilot, lambda: app.client is not None), "demo connection"
            box = app.query_one("#search", Input)
            box.focus()
            await pilot.press(*"mül", "enter")
            assert await _wait_until(pilot, lambda: app.current is not None and app.current.kind == "users")
            assert "ldap filter:" in app.current.comment and "repeat with:" in app.current.comment
            # Query metadata must be selected explicitly.
            app.action_export()
            await pilot.pause(0.3)
            screen = app.screen
            assert isinstance(screen, ExportScreen)
            from textual.widgets import Checkbox
            assert screen.query_one("#query_comment", Checkbox).value is False
            screen.query_one("#query_comment", Checkbox).value = True
            target = tmp_path / "export.csv"
            screen.query_one("#filename", Input).value = str(target)
            await pilot.click("#ok")
            await pilot.pause(0.3)
            text = target.read_text(encoding="utf-8")
            assert text.startswith("# exported by ldapgrep")
            assert "# ldap filter:" in text and "mmueller" in text
            await pilot.press("q")

    asyncio.run(scenario())
