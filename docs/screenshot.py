"""Generate docs/screenshot.svg from the built-in demo directory (run: python docs/screenshot.py)."""

import asyncio
from pathlib import Path

from ldapgrep.config import Settings
from ldapgrep.tui import LdapGrepApp

OUT = Path(__file__).with_name("screenshot.svg")


async def main() -> None:
    app = LdapGrepApp(Settings(), demo=True)
    async with app.run_test(size=(120, 36)) as pilot:
        for _ in range(100):
            if app.client is not None:
                break
            await pilot.pause(0.1)
        from textual.widgets import DataTable, Input
        box = app.query_one("#search", Input)
        box.focus()
        await pilot.press(*"it", "enter")
        table = app.query_one("#results", DataTable)
        for _ in range(100):
            if app.current is not None and table.row_count > 3:
                break
            await pilot.pause(0.1)
        await pilot.pause(0.3)
        OUT.write_text(app.export_screenshot(), encoding="utf-8")
    print(f"wrote {OUT}")


if __name__ == "__main__":
    asyncio.run(main())
