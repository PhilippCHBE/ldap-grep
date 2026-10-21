"""Install the pinned, checksum-verified scanner into the ignored local tool directory."""
import hashlib
import io
import platform
import tarfile
import urllib.request
import zipfile
from pathlib import Path

VERSION = "8.30.1"
ARTIFACTS = {
    "Windows": ("windows_x64.zip", "d29144deff3a68aa93ced33dddf84b7fdc26070add4aa0f4513094c8332afc4e"),
    "Linux": ("linux_x64.tar.gz", "551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb"),
}


def main():
    system = platform.system()
    if platform.machine().lower() not in ("amd64", "x86_64") or system not in ARTIFACTS:
        raise SystemExit("This installer supports Windows/Linux x64; install the pinned Gitleaks version separately.")
    name, digest = ARTIFACTS[system]
    url = f"https://github.com/gitleaks/gitleaks/releases/download/v{VERSION}/gitleaks_{VERSION}_{name}"
    data = urllib.request.urlopen(url, timeout=60).read()
    if hashlib.sha256(data).hexdigest() != digest:
        raise SystemExit("Gitleaks checksum mismatch; nothing installed.")
    binary = "gitleaks.exe" if system == "Windows" else "gitleaks"
    if system == "Windows":
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            content = archive.read(binary)
    else:
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as archive:
            content = archive.extractfile(binary).read()
    path = Path(__file__).resolve().parents[1] / ".private" / "tools" / "gitleaks" / VERSION / binary
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content)
    path.chmod(0o700)
    print(f"Installed checksum-verified Gitleaks {VERSION}.")


if __name__ == "__main__":
    main()
