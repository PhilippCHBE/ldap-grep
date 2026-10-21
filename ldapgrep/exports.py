"""Private, exclusive export creation; existing files are never overwritten."""

from __future__ import annotations

import os
import stat
from pathlib import Path


def default_export_dir() -> Path:
    if os.name == "nt":
        base = Path(os.environ.get("LOCALAPPDATA", str(Path.home() / "AppData" / "Local")))
        return base / "ldapgrep" / "exports"
    return Path.home() / ".local" / "state" / "ldapgrep" / "exports"


def _reject_links(path: Path) -> None:
    for item in (path, *path.parents):
        try:
            info = item.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
            raise OSError("Export paths must not contain symlinks or Windows reparse points.")


def _windows_descriptor():
    import ctypes
    from ctypes import wintypes

    api = ctypes.WinDLL("advapi32", use_last_error=True)
    convert = api.ConvertStringSecurityDescriptorToSecurityDescriptorW
    convert.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, ctypes.POINTER(wintypes.LPVOID),
                        ctypes.POINTER(wintypes.DWORD)]
    convert.restype = wintypes.BOOL
    descriptor = wintypes.LPVOID()
    # Protected DACL: only the object owner and Windows SYSTEM, no inherited broad grants.
    if not convert("D:P(A;;FA;;;SY)(A;;FA;;;OW)", 1, ctypes.byref(descriptor), None):
        raise ctypes.WinError(ctypes.get_last_error())
    return api, descriptor


def _free_descriptor(descriptor) -> None:
    import ctypes
    from ctypes import wintypes
    free = ctypes.WinDLL("kernel32", use_last_error=True).LocalFree
    free.argtypes = [wintypes.HLOCAL]
    free.restype = wintypes.HLOCAL
    free(descriptor)


def _private_directory(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    _reject_links(path)
    if os.name == "nt":
        import ctypes
        from ctypes import wintypes
        api, descriptor = _windows_descriptor()
        try:
            apply = api.SetFileSecurityW
            apply.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.LPVOID]
            apply.restype = wintypes.BOOL
            if not apply(str(path), 0x80000004, descriptor):
                raise ctypes.WinError(ctypes.get_last_error())
        finally:
            _free_descriptor(descriptor)
    else:
        path.chmod(0o700)


def _open_new(path: Path) -> int:
    if os.name != "nt":
        return os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    import ctypes
    import msvcrt
    from ctypes import wintypes

    class SecurityAttributes(ctypes.Structure):
        _fields_ = [("nLength", wintypes.DWORD), ("lpSecurityDescriptor", wintypes.LPVOID),
                    ("bInheritHandle", wintypes.BOOL)]

    _, descriptor = _windows_descriptor()
    create = ctypes.WinDLL("kernel32", use_last_error=True).CreateFileW
    create.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
                       ctypes.POINTER(SecurityAttributes), wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
    create.restype = wintypes.HANDLE
    attrs = SecurityAttributes(ctypes.sizeof(SecurityAttributes), descriptor, False)
    try:
        handle = create(str(path), 0x40000000, 0, ctypes.byref(attrs), 1, 0x80, None)
        if handle == wintypes.HANDLE(-1).value:
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            return msvcrt.open_osfhandle(handle, os.O_WRONLY | os.O_BINARY)
        except OSError:
            close = ctypes.WinDLL("kernel32", use_last_error=True).CloseHandle
            close.argtypes = [wintypes.HANDLE]
            close.restype = wintypes.BOOL
            close(handle)
            raise
    finally:
        _free_descriptor(descriptor)


def write_private(path: str, text: str) -> None:
    target = Path(path).expanduser().absolute()
    _reject_links(target)
    default = default_export_dir().absolute()
    if target.parent == default:
        _private_directory(default.parent)
        _private_directory(default)
    fd = _open_new(target)
    with os.fdopen(fd, "w", encoding="utf-8", newline="") as stream:
        stream.write(text)
        stream.flush()
        os.fsync(stream.fileno())
