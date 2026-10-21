"""Run the offline regression reproductions for security findings F1-F10.
Uses synthetic data and no external LDAP connections. Requires the dev/test dependencies.
Run from repository root: python docs/security-review-repro.py
"""
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

if __name__ == "__main__":
    import pytest
    raise SystemExit(pytest.main([
        str(ROOT / "tests" / "test_security.py"),
        str(ROOT / "tests" / "test_security_outputs.py"),
        "-q",
    ]))
