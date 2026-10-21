# Changelog

All notable changes to ldapgrep.

## 2.3.1

### Security
- Remove automatic public-server fallback; built-in public profiles ignore environment
  overrides and reject credential/target changes and personal-password prompts (F1).
- Discover configuration only in user/system locations; project-local files require
  explicit `--config FILE` or `LDAPGREP_CONFIG` (F2).
- Require TLS for authenticated LDAP; only isolated tests may opt in using
  `--allow-plaintext-auth` / `allow_plaintext_auth = true`. Reject invalid URL schemes
  and ports, and never bind after unsuccessful StartTLS (F3).
- Reject unknown boolean values instead of silently disabling TLS verification;
  fix the example configurations and require explicit opt-out for the FreeIPA demo CA (F4).
- Require pyasn1 >= 0.6.4 and audit installed dependencies in CI (F5).
- Neutralize spreadsheet formula prefixes in CSV/TSV values and headers; use JSON/LDIF
  for unchanged raw values (F6).
- Clear all connection fields and restore TLS verification when switching to Custom,
  including after a failed profile load (F7).
- Stream fallback members, stop work at the matching-result limit, and enforce shared
  query/page, entry, depth and time budgets for group and memberof traversal (F8).
- Render untrusted values as literal text, escape terminal controls on interactive
  output, and preserve raw file/pipe contents (F9).
- Redact URL userinfo in all configuration diagnostic fields, even malformed URLs;
  exclude credentials and raw URLs from the Settings repr (F10).
- Create exports exclusively with Unix mode 0600 or a protected Windows owner/SYSTEM
  ACL; reject symlinks/reparse points and existing destinations. Automatic exports use
  private application storage and unique names instead of the checkout directory.
- Disable export query comments by default. Optional comments label separately quoted
  PowerShell and POSIX commands, including values containing apostrophes.
- Add private-storage ignore rules and pinned, checksum-verified Gitleaks scans before
  commit/push and in CI; missing scanners and detected secrets block local operations.
- Pin GitHub Actions to full commit SHAs, limit default permissions to contents:read,
  and separate release validation/build from the minimal Trusted Publishing job.
  Publishing stays disabled until the new repository's release protections are configured.

### Changed
- Display the release version in the GUI help dialog.
- Use the public maintainer handle in package and copyright metadata; omit the personal email.
- Keep the README option table contiguous and escape pipes inside option alternatives.
- Quote every CSV/TSV cell and display NUL bytes as `\x00`, including on Python 3.9/3.10;
  retain original values in JSON/LDIF. Use Python 3.9-compatible GUI base-class type parameters.

### Tests
- Verify the GUI help version and replace the ineffective detail-panel assertion with a
  check of the rendered content.
- Test private export creation, overwrite/symlink rejection, both shell quoting variants,
  real TLS certificate/hostname failures and refused StartTLS without transmitting a bind.
  Detect local certificate interception explicitly; document optional Samba/AD testing.

## 2.3.0

### Added
- Account status fields: `password_expired` (userAccountControl `PASSWORD_EXPIRED` bit) in the
  compact/detail/full views, shown red in tables like `disabled`/`locked`, and `passwordExpires`
  (detail/full) from AD's computed `msDS-UserPasswordExpiryTimeComputed` - formatted as a date,
  `never` for accounts whose password does not expire.
- MIT license.
- GitHub Actions: `pytest` on every push/PR (Python 3.9-3.13) and PyPI publish on GitHub release
  (trusted publishing, no stored token).

## 2.2.0

### Added
- `check` command: step-by-step pre-flight connection test (DNS resolution, TCP port, TLS
  handshake, bind) that touches nothing in the directory. The GUI login dialog has a matching
  **Test** button.
- `user --count` and `groups --count`: only the number of matches is printed; the server is
  asked for no attributes at all, so even huge counts do not read or parse the tree
  (`search --count` already existed).
- GUI export (`e`): a checkbox adds the LDAP query as a `#` comment to the exported file -
  including a ready-made `ldapgrep search ...` command line, so the query can be repeated
  outside the GUI. (json has no comments; the checkbox is disabled there.)
- GUI: confirmation dialog before broad wildcard searches when `min_search_length` is lowered.

### Changed
- `min_search_length = 2` (the default) now blocks broad wildcard searches (`user "*"`, `a*`,
  `groups "*"`). Such terms can dump an entire large directory; use `--filter` to narrow them
  deliberately, or set `min_search_length = 0` / `1`, in which case the CLI asks for
  confirmation (warns on non-interactive calls) and the GUI shows a dialog.
- `min_search_length = 0` is honoured literally (it was previously clamped to 1).

### Removed
- The legacy `ldap-getGroupMembers.py` compatibility: the 1.x flag translation
  (`--search-user`, `--show-groups`, `--export-csv`, ...) is gone, the legacy config file name
  `ldap-getGroupMembers.conf` is no longer read, and `legacy/` was dropped. The view aliases
  `--full`, `--detail`, `--all-attributes` stay.

## 2.1.0 - 2026-10-18

### Added
- Built-in profiles for the public test servers: `--profile forumsys`, `debian`, `freeipa`. They work
  without a config file and never inherit the `[LDAP]` section; a `[profile:NAME]` of the same name in
  the config file replaces them. `config --check` lists all profiles with their source.
- Default server: when no server is configured anywhere, the `forumsys` profile is used and a note is
  printed on stderr (not in `--demo` mode).
- GUI: server picker in the login dialog (config profiles, public test servers, demo, custom) with a
  TLS verification checkbox; empty bind DN + password means anonymous. New key `s` switches the server
  during a session (connection closed, history cleared).
- Connection: one automatic retry when the server drops the first connection (seen with the FreeIPA demo).

### Removed
- The `ldap-getGroupMembers.py` shim. Call `ldap-grep.py` instead; the 1.x flags are still
  translated and `ldap-getGroupMembers.conf` is still read. The original script stays in `legacy/`.

### Changed
- Default config file name is `ldap-grep.conf` (matching the launcher); `ldapgrep.conf` stays accepted
  at every location, `ldap-getGroupMembers.conf` is still read. Template renamed to `ldap-grep.conf.example`.

### Fixed
- `--output -` wrote a file literally named `-`; it now means stdout (pipe convention).
- Login dialog: Enter never connected for anonymous profiles (it insisted on bind DN and password).
- Unknown `--profile` now also lists the built-in profiles.

## 2.0.1 - 2026-10-18

First release tested against real servers: ldap.forumsys.com and db.debian.org (OpenLDAP) and
ipa.demo1.freeipa.org (389 Directory Server / FreeIPA). See "Trying it against public test servers"
in the README.

### Fixed
- `tree` (and any filter naming an object class the server does not have, e.g. `container` on
  OpenLDAP) crashed with `LDAPObjectClassError`. Unknown classes are now rewritten to a never-matching
  term; filters with unknown attribute names fall back to server-side evaluation with a warning.
- Base DN auto-detection picked `cn=log` (OpenLDAP accesslog) on db.debian.org. Operational naming
  contexts (config, schema, monitor, accesslog, changelog, DNS zones) are skipped, `dc=` contexts preferred.
- 389ds/FreeIPA also publish `defaultNamingContext` and were about to be treated as Active Directory;
  detection now needs the AD capability OID or forest/domain functionality (or no vendor name).
- `memberof joerg` was "ambiguous" when another entry had `cn=joerg`: the login name now wins.
- `user NAME --detail` (new syntax with a 1.x view flag) was mis-translated. `--full`, `--detail` and
  `--all-attributes` are accepted as aliases of `--view` in the new syntax.
- Repeated entries from a server (389ds compat plugin) are suppressed.
- `StartTLS failed` because of an untrusted certificate now points to `--ca-file` / `--insecure`
  instead of suggesting `ldaps://`.
- `... | head` no longer ends with exit code 120 or `Cannot write output: [Errno 22]` (on Windows a
  closed pipe is `OSError(EINVAL)`, not `BrokenPipeError`).
- Launcher docstring of `ldap-grep.py` named the wrong file.

### Added
- FreeIPA: search base narrowed to `cn=accounts,<suffix>` when auto-detected; `memberOf` values
  outside it (permissions, roles, sudo/HBAC rules) are hidden. `--base-dn` overrides this.
- `tree` lists `nsContainer` objects (389ds/FreeIPA).
- `--no-config` ignores every config file, and a warning is printed when `-H` points to a different
  host than the config file whose `base_dn` / OUs still apply.
- README section about public test servers; 6 new tests (43).

## 2.0.0 - 2026-10-17

Complete rewrite of `ldap-getGroupMembers.py` into the `ldapgrep` package.

### Added
- Sub-command CLI: `user`, `group`, `groups`, `memberof`, `compare`, `search`, `info`, `whoami`,
  `schema`, `tree`, `config`, `tui`.
- Interactive console GUI (`ldapgrep tui`, Textual): search users / groups / raw filters, drill down
  from groups to members and from users to groups, history, detail panel (summary or all attributes),
  export, copy DN, login dialog.
- Automatic detection of server type (Active Directory vs. generic LDAP) and base DN from the rootDSE.
- Nested group resolution (`--recursive`): server side on AD (`LDAP_MATCHING_RULE_IN_CHAIN`),
  client side recursion elsewhere. AD primary group included in `memberof`.
- Group comparison of two users (`compare`), bulk lookups (`--from-file`), extra filters
  (`--filter`, `--base`), account state filters (`--active`, `--disabled`, `--locked`), computers (`--computers`).
- Output formats json, table, csv, tsv, ldif, yaml, list, dn; `--fields`, `--sort`, `--output`, `-o auto`.
- Umlaut-aware search: `Müller` matches `Müller`, `Mueller` and `Muller`; `'First Last'` matches
  givenName/sn combinations; user wildcards (`*`, `?`).
- Decoding of `userAccountControl`, `groupType`, FILETIME, GeneralizedTime, `objectSid`, `objectGUID`,
  binary values (base64).
- Configuration: profiles (`[profile:NAME]`), environment variables (`LDAPGREP_*`), password file,
  interactive password prompt (`-W`), NTLM and anonymous authentication, StartTLS, CA file,
  `--insecure`, `--no-schema` / `load_schema`, company specific `user_extra_attributes`.
- Paged searches everywhere; server limit hits return the partial result plus a warning.
- Built-in demo directory (`--demo`) and an offline test-suite (pytest, 37 tests incl. headless GUI).
- Exit codes like grep: 0 match, 1 no match, 2 usage/config, 3 connection/auth, 4 LDAP.
- Plain-English hints for connection, TLS, DNS and AD bind sub-code errors (52e, 533, 775, ...).

### Changed
- `python-ldap` replaced by the pure-Python `ldap3` (no C libraries, runs on Windows).
- `ldap-getGroupMembers.py` is now a compatibility shim that translates all 1.x flags; the original
  1.0.19 script lives in `legacy/`. `ldap-getGroupMembers.conf` is still read.
- Requested attributes are intersected with the server schema; unknown attributes are skipped
  (built-ins silently, user supplied ones with a warning) instead of failing.
- Dates are shown in local time; `accountExpires` prints `never`; `lastLogon = 0` prints empty.
- Minimum search length 2 (was 3), configurable with `min_search_length`.
- JSON key `streetAdress` (typo) renamed to `streetAddress`.
- Warnings go to stderr; data only to stdout.
- An empty result exits with code 1 (was 0).
- Default output on a terminal is a colored table; JSON when piped. Legacy invocations keep JSON.

### Removed
- Hard-coded default server / bind credentials in the script.
- The 1000-entry result cap (`SIZELIMIT_EXCEEDED` abort).

## 1.0.19 - 2025-12-19 (ldap-getGroupMembers.py)
- Added `--all-attributes` and `--detail` for `--search-user`.

## 1.0.18
- More error proof version.

## 1.0.17
- Re-added `--help` and `--version` handling at startup.

## 1.0.16
- Added `--groups` support for `--search-user`; combinable with `--full`, `--active`, `--export-csv`, `--memberof`.

## 1.0.15
- `--search-user` requires at least 3 characters; renamed `--aktiv` to `--active`.

## 1.0.14
- New option `--search-user`.

## 1.0.13
- Config file is looked up in the folder of the script.

## 1.0.10
- Configuration variables read from an external file.

## 1.0.9
- `BrokenPipeError` corrected.
