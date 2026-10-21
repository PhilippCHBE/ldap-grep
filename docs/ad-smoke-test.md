# Smoke test against a production Active Directory

The AD-only code paths (NTLM, ANR, `LDAP_MATCHING_RULE_IN_CHAIN`, bitwise `userAccountControl`
filters, referrals) cannot be covered by the offline test suite - the ldap3 mock cannot evaluate
them. Use an isolated synthetic Samba/AD domain first; see [security testing](security-testing.md).
Production testing requires a separately authorized scope. Share only sanitized results.

Setup: use a read-only account and verified LDAPS or StartTLS. Put configuration in
`~/.config/ldapgrep/ldap-grep.conf`, select a project file explicitly with `--config FILE`,
or pass `-H/-D/-W`. Configure the correct CA and certificate hostname.

| # | Command | Exercises | Expected |
|---|---------|-----------|----------|
| 1 | `ldapgrep check` | DNS, TCP, TLS handshake, bind | all steps green; TLS errors must name the cause |
| 2 | `ldapgrep config --check -v` | rootDSE / flavor detection | server type reported as `AD`, base DN auto-detected |
| 3 | `ldapgrep user <login>` | simple bind, schema read, paging | one row, `disabled` column correct |
| 4 | `ldapgrep --auth ntlm -D 'DOMAIN\user' -W user <login>` | NTLM bind | same result as simple bind |
| 5 | `ldapgrep user "firstname lastname"` | ANR (`anr=...` clause) | finds the person by fuzzy name |
| 6 | `ldapgrep user <login> --memberof -r` | server-side nesting via `LDAP_MATCHING_RULE_IN_CHAIN` | includes indirect groups; compare with `-r` off |
| 7 | `ldapgrep group <group> -r` | in-chain member query | nested group members resolved server side |
| 8 | `ldapgrep user <term> --active` | bitwise filter `(!(userAccountControl:1.2.840.113556.1.4.803:=2))` | disabled accounts excluded |
| 9 | `ldapgrep user <login> --detail` | new in 2.3.0: `password_expired`, `passwordExpires` | `passwordExpires` shows a date or `never` (from `msDS-UserPasswordExpiryTimeComputed`) |
| 10 | `ldapgrep user "<x>*" --count` vs. `ldapgrep user "<x>*" --format dn \| wc -l` | count vs. real listing | numbers match; count returns instantly even for 10k+ |
| 11 | large result set (> page size, default 1000 on AD) | paged search over several pages | no duplicates, no missing entries |
| 12 | search base that spans a trust / child domain | referral handling | clean error message naming the referral, no crash |
| 13 | `ldapgrep tui` | GUI against AD incl. Test button, export with query comment | behaves like against the demo directory |

Notes:
- Step 9 needs the AD to compute `msDS-UserPasswordExpiryTimeComputed` (constructed attribute,
  Windows Server 2008+). Fine-Grained Password Policies are reflected in the value.
- `lockoutTime` is only set while an account is actually locked out; `locked` shows `yes` then.
- If anything diverges, please open an issue with the command, the ldapgrep version
  (`ldapgrep --version`), the Windows Server version of the DC, and the (sanitized) output.
