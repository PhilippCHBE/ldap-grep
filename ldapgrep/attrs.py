"""Built-in attribute lists shared by the client (silent schema filtering) and the views."""

from __future__ import annotations

USER_ATTRS_COMPACT = [
    "cn", "displayName", "sAMAccountName", "uid", "mail", "userAccountControl", "sn", "givenName",
    "telephoneNumber", "mobile", "title", "department", "physicalDeliveryOfficeName", "objectClass",
    "nsAccountLock", "pwdAccountLockedTime",
]
USER_ATTRS_DETAIL = USER_ATTRS_COMPACT + [
    "userPrincipalName", "employeeID", "employeeNumber", "employeeType", "company", "division", "o", "ou",
    "streetAddress", "postalCode", "l", "st", "co", "c", "manager", "description", "info",
    "whenCreated", "whenChanged", "accountExpires", "lastLogon", "lastLogonTimestamp", "pwdLastSet",
    "badPasswordTime", "badPwdCount", "lockoutTime", "primaryGroupID", "objectSid", "objectGUID",
    "homeDirectory", "scriptPath", "msDS-UserPasswordExpiryTimeComputed",
]
GROUP_ATTRS_COMPACT = ["cn", "name", "sAMAccountName", "description", "groupType", "mail", "objectClass"]
GROUP_ATTRS_DETAIL = GROUP_ATTRS_COMPACT + [
    "managedBy", "info", "whenCreated", "whenChanged", "objectSid", "memberOf", "gidNumber",
    "member", "uniqueMember", "memberUid",
]
MEMBERSHIP_ATTRS = ["memberOf", "primaryGroupID", "primaryGroupToken", "member", "uniqueMember", "memberUid",
                    "distinguishedName", "entryDN", "lockoutTime", "groupType", "objectCategory"]

# attributes ldapgrep asks for on its own: missing ones are dropped silently
BUILTIN_ATTRIBUTES: set[str] = {
    a.lower() for a in (USER_ATTRS_DETAIL + GROUP_ATTRS_DETAIL + MEMBERSHIP_ATTRS)
}
