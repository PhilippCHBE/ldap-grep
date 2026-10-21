import os
import shlex
import shutil
import stat
import subprocess
import json
from pathlib import Path

import pytest

from ldapgrep.exports import default_export_dir, write_private
from ldapgrep.tui import shell_command


def test_existing_file_is_never_overwritten(tmp_path):
    path = tmp_path / "export.json"
    path.write_text("original", encoding="utf-8")
    with pytest.raises(OSError):
        write_private(str(path), "replacement")
    assert path.read_text() == "original"


def test_export_creation_is_private(tmp_path):
    path = tmp_path / "export.json"
    write_private(str(path), "example")
    assert path.read_text() == "example"
    if os.name == "nt":
        security = pytest.importorskip("win32security")
        descriptor = security.GetFileSecurity(str(path), security.DACL_SECURITY_INFORMATION)
        acl = descriptor.GetSecurityDescriptorDacl()
        sids = {security.ConvertSidToStringSid(acl.GetAce(i)[2]) for i in range(acl.GetAceCount())}
        assert sids == {"S-1-5-18", "S-1-3-4"}  # SYSTEM and OWNER RIGHTS only
        assert descriptor.GetSecurityDescriptorControl()[0] & 0x1000  # protected DACL
    else:
        assert stat.S_IMODE(path.stat().st_mode) == 0o600


def test_symlink_target_is_rejected(tmp_path):
    original = tmp_path / "original.txt"
    original.write_text("original")
    link = tmp_path / "link.txt"
    try:
        link.symlink_to(original)
    except OSError:
        pytest.skip("Symlink creation is unavailable for this Windows user.")
    with pytest.raises(OSError, match="symlink"):
        write_private(str(link), "replacement")
    assert original.read_text() == "original"


def test_private_default_directory(tmp_path, monkeypatch):
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path))
    parent = default_export_dir()
    write_private(str(parent / "export.txt"), "example")
    assert (parent / "export.txt").is_file()
    if os.name != "nt":
        assert stat.S_IMODE(parent.stat().st_mode) == 0o700


@pytest.mark.parametrize("value", ["O'Brien", "$(echo injected)", "; echo injected", "a b", "", "é"])
def test_posix_quoting_roundtrips(value):
    argv = ["ldapgrep", "user", value]
    assert shlex.split(shell_command(argv, "posix")) == argv


def test_powershell_quoting_roundtrips():
    executable = shutil.which("pwsh") or shutil.which("powershell")
    if not executable:
        pytest.skip("PowerShell unavailable; POSIX quoting is tested separately.")
    values = ["O'Brien", "$(Write-Output injected)", "; echo injected", "", "a b"]
    command = "function capture-argv { ConvertTo-Json -InputObject @($args) -Compress }; "
    command += shell_command(["capture-argv", *values], "powershell")
    result = subprocess.run([executable, "-NoProfile", "-NonInteractive", "-Command", command],
                            capture_output=True, text=True, check=True, timeout=15)
    assert json.loads(result.stdout) == values
