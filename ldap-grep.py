#!/usr/bin/env python3
"""ldapgrep launcher - run from a checkout without installing.

    python3 ldap-grep.py user meier
    python3 ldap-grep.py tui

Installed via pip the same thing is available as the `ldapgrep` command.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from ldapgrep.cli import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main())
