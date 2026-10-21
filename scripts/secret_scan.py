"""Fail-closed staged/history scans used by both native Git hooks and CI."""
import argparse
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

VERSION = "8.30.1"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=("staged", "history", "files"))
    parser.add_argument("--source", type=Path)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    source = (args.source or root).resolve()
    local = root / ".private" / "tools" / "gitleaks" / VERSION / ("gitleaks.exe" if os.name == "nt" else "gitleaks")
    binary = str(local) if local.is_file() else shutil.which("gitleaks")
    if not binary:
        parser.exit(2, "Secret scan blocked: run python scripts/install_gitleaks.py first.\n")
    version = subprocess.run([binary, "version"], capture_output=True, text=True, check=True).stdout.strip()
    if version.lstrip("v") != VERSION:
        parser.exit(2, f"Secret scan blocked: Gitleaks {VERSION} is required.\n")
    cmd = [binary, "dir" if args.mode == "files" else "git", "--redact", "--no-banner",
           "--config", str(root / ".gitleaks.toml")]
    if args.mode == "staged":
        cmd += ["--pre-commit", "--staged"]
    elif args.mode == "history":
        cmd += ["--log-opts=--all"]
    if args.mode == "files" and (source / ".git").exists():
        # Scan publication candidates, not ignored credentials/tool caches. Git scans
        # never exclude private-looking paths: force-added secrets must still be caught.
        paths = subprocess.check_output(
            ["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"], cwd=source).decode().split("\0")
        with tempfile.TemporaryDirectory(prefix="ldapgrep-public-scan-") as temporary:
            snapshot = Path(temporary)
            for name in set(paths) - {""}:
                path = source / name
                if path.is_symlink():
                    parser.exit(2, "Secret scan blocked: publication candidates contain a symlink.\n")
                if path.is_file():
                    target = snapshot / name
                    target.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copyfile(path, target)
            return subprocess.run(cmd + [str(snapshot)], cwd=snapshot).returncode
    return subprocess.run(cmd + [str(source)], cwd=source).returncode


if __name__ == "__main__":
    raise SystemExit(main())
