"""Render untrusted directory text without terminal control sequences."""

import unicodedata


def terminal_text(value: object, *, multiline: bool = False) -> str:
    out = []
    for char in str(value):
        code = ord(char)
        if multiline and char in "\n\t":
            out.append(char)
        elif unicodedata.category(char) == "Cc" or unicodedata.bidirectional(char) in (
            "RLO", "LRO", "RLE", "LRE", "PDF", "RLI", "LRI", "FSI", "PDI",
        ):
            out.append(f"\\x{code:02x}" if code < 256 else f"\\u{code:04x}")
        else:
            out.append(char)
    return "".join(out)
