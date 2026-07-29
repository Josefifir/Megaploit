"""
megaploit.modules.auxiliary.ldap_enum
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
LDAP/Active Directory enumeration module.

Enumerates:
  - Users (sAMAccountName, UPN, memberOf, description, adminCount)
  - Groups and group memberships
  - Service Principal Names (SPNs — Kerberoast targets)
  - Delegations (unconstrained, constrained, RBCD)
  - Password policy
  - Privileged accounts (adminCount=1)
  - Computer accounts

References
----------
* https://attack.mitre.org/techniques/T1087/002/
* https://ldap3.readthedocs.io/
"""

from __future__ import annotations

import socket
from megaploit.modules.base import Module, ModuleType, OptionType


# Useful AD attribute sets
_USER_ATTRS = [
    "sAMAccountName", "userPrincipalName", "displayName", "description",
    "memberOf", "adminCount", "userAccountControl",
    "servicePrincipalName", "pwdLastSet", "lastLogon",
]
_GROUP_ATTRS = ["sAMAccountName", "description", "member", "memberOf"]
_COMPUTER_ATTRS = ["dNSHostName", "operatingSystem", "operatingSystemVersion",
                   "userAccountControl", "lastLogon"]

# UAC flags
_UAC_DONT_REQ_PREAUTH    = 0x400000
_UAC_PASSWD_NOTREQD      = 0x0020
_UAC_TRUSTED_FOR_DELEG   = 0x080000   # unconstrained delegation
_UAC_NOT_DELEGATED        = 0x100000
_UAC_DISABLED             = 0x0002


class LdapEnumModule(Module):
    name        = "auxiliary/ldap/enum"
    description = (
        "Enumerate Active Directory users, groups, SPNs, delegations, "
        "and password policy via LDAP"
    )
    module_type = ModuleType.AUXILIARY
    author      = "megaploit"
    references  = [
        "https://attack.mitre.org/techniques/T1087/002/",
        "https://attack.mitre.org/techniques/T1069/002/",
    ]
    platform    = ["multi"]; arch = []; rank = 400

    def _define_options(self) -> None:
        self._opt("RHOSTS",   OptionType.ADDRESS, required=True,
                  description="Domain controller IP or hostname")
        self._opt("DOMAIN",   OptionType.STRING,  required=True,
                  description="AD domain  (e.g. corp.local)")
        self._opt("USERNAME", OptionType.STRING,  required=True,
                  description="Domain user for LDAP bind")
        self._opt("PASSWORD", OptionType.STRING,  required=True,
                  description="Password")
        self._opt("ENUM",     OptionType.ENUM,    default="all",
                  choices=["all","users","groups","spns","computers",
                           "delegations","policy","privusers"],
                  description="What to enumerate")
        self._opt("LDAPS",    OptionType.BOOLEAN, default=False, required=False,
                  description="Use LDAPS (port 636) instead of LDAP (389)")
        self._opt("TIMEOUT",  OptionType.INTEGER, default=30, required=False,
                  description="Connection timeout in seconds")
        self._opt("OUTFILE",  OptionType.PATH,    required=False,
                  description="Save output to file (optional)")

    def check(self, session=None) -> str:
        self.validate()
        host    = str(self.get("RHOSTS"))
        use_tls = bool(self.get("LDAPS"))
        port    = 636 if use_tls else 389
        timeout = int(self.get("TIMEOUT"))
        try:
            with socket.create_connection((host, port), timeout=timeout):
                return f"[+] {host}:{port} — {'LDAPS' if use_tls else 'LDAP'} reachable"
        except OSError as e:
            return f"[-] {host}:{port} — {e}"

    def run(self, session=None) -> list:
        self.validate()
        self.results.clear()

        dc       = str(self.get("RHOSTS"))
        domain   = str(self.get("DOMAIN"))
        username = str(self.get("USERNAME"))
        password = str(self.get("PASSWORD"))
        enum     = str(self.get("ENUM")).lower()
        use_tls  = bool(self.get("LDAPS"))
        timeout  = int(self.get("TIMEOUT"))
        outfile  = self.get("OUTFILE") or ""
        port     = 636 if use_tls else 389

        # Try ldap3 first (pure Python, easier install)
        try:
            import ldap3
            _driver = "ldap3"
        except ImportError:
            try:
                from impacket.ldap import ldap as _impacket_ldap
                _driver = "impacket"
            except ImportError:
                return [self._fail(
                    "No LDAP library — install ldap3:  pip install ldap3"
                )]

        base_dn = ",".join(f"DC={p}" for p in domain.split("."))
        self._emit(f"[*] Connecting to {dc}:{port}  base_dn={base_dn}")

        lines: list[str] = []

        if _driver == "ldap3":
            import ldap3 as L3
            server = L3.Server(dc, port=port, use_ssl=use_tls,
                               connect_timeout=timeout)
            bind_dn = f"{username}@{domain}"
            conn = L3.Connection(server, user=bind_dn, password=password,
                                 authentication=L3.NTLM, auto_bind=True)

            def _search(flt: str, attrs: list[str]) -> list[L3.Entry]:
                conn.search(base_dn, flt, L3.SUBTREE,
                            attributes=attrs or L3.ALL_ATTRIBUTES)
                return list(conn.entries)

            if enum in ("all", "users"):
                self._emit("[*] Enumerating users…")
                entries = _search(
                    "(&(objectClass=user)(objectCategory=person))",
                    _USER_ATTRS
                )
                lines.append(f"\n=== USERS ({len(entries)}) ===")
                for e in entries:
                    sam  = str(e.sAMAccountName)
                    uac  = int(str(e.userAccountControl or "0"))
                    flags = []
                    if uac & _UAC_DISABLED:              flags.append("DISABLED")
                    if uac & _UAC_DONT_REQ_PREAUTH:      flags.append("NO_PREAUTH")
                    if uac & _UAC_PASSWD_NOTREQD:        flags.append("NO_PWD_REQ")
                    if uac & _UAC_TRUSTED_FOR_DELEG:     flags.append("UNCONSTRAINED_DELEG")
                    flag_str = "  [" + ", ".join(flags) + "]" if flags else ""
                    lines.append(f"  {sam}{flag_str}")
                    if str(e.adminCount or "0") == "1":
                        self._emit(f"  [!] Admin account: {sam}")
                self._ok(f"Enumerated {len(entries)} users", count=len(entries))

            if enum in ("all", "groups"):
                self._emit("[*] Enumerating groups…")
                entries = _search("(objectClass=group)", _GROUP_ATTRS)
                lines.append(f"\n=== GROUPS ({len(entries)}) ===")
                for e in entries:
                    sam     = str(e.sAMAccountName)
                    members = len(e.member) if hasattr(e.member, "__len__") else 0
                    lines.append(f"  {sam}  ({members} member(s))")
                self._ok(f"Enumerated {len(entries)} groups", count=len(entries))

            if enum in ("all", "spns"):
                self._emit("[*] Enumerating SPNs (Kerberoast targets)…")
                entries = _search(
                    "(&(objectClass=user)(servicePrincipalName=*)"
                    "(!(userAccountControl:1.2.840.113556.1.4.803:=2)))",
                    ["sAMAccountName", "servicePrincipalName"]
                )
                lines.append(f"\n=== KERBEROASTABLE SPNs ({len(entries)}) ===")
                for e in entries:
                    sam = str(e.sAMAccountName)
                    for spn in (e.servicePrincipalName or []):
                        lines.append(f"  {sam}  →  {spn}")
                        self._emit(f"  [!] SPN: {spn} ({sam})")
                self._ok(f"Found {len(entries)} SPN account(s)", count=len(entries))

            if enum in ("all", "computers"):
                self._emit("[*] Enumerating computer accounts…")
                entries = _search("(objectClass=computer)", _COMPUTER_ATTRS)
                lines.append(f"\n=== COMPUTERS ({len(entries)}) ===")
                for e in entries:
                    dns = str(e.dNSHostName or "?")
                    os_ = str(e.operatingSystem or "?")
                    lines.append(f"  {dns}  [{os_}]")
                self._ok(f"Enumerated {len(entries)} computers", count=len(entries))

            if enum in ("all", "delegations"):
                self._emit("[*] Enumerating delegations…")
                unc = _search(
                    "(&(userAccountControl:1.2.840.113556.1.4.803:=524288)"
                    "(!primaryGroupID=516)(!primaryGroupID=521))",
                    ["sAMAccountName", "userAccountControl"]
                )
                con = _search(
                    "(msDS-AllowedToDelegateTo=*)",
                    ["sAMAccountName", "msDS-AllowedToDelegateTo"]
                )
                lines.append(f"\n=== DELEGATIONS ===")
                for e in unc:
                    lines.append(f"  [UNCONSTRAINED] {e.sAMAccountName}")
                    self._emit(f"  [!] Unconstrained delegation: {e.sAMAccountName}")
                for e in con:
                    for target in (e["msDS-AllowedToDelegateTo"] or []):
                        lines.append(f"  [CONSTRAINED] {e.sAMAccountName}  →  {target}")
                self._ok(f"Delegations: {len(unc)} unconstrained, {len(con)} constrained")

            if enum in ("all", "privusers"):
                self._emit("[*] Enumerating privileged accounts (adminCount=1)…")
                entries = _search(
                    "(&(objectClass=user)(adminCount=1))",
                    ["sAMAccountName", "memberOf"]
                )
                lines.append(f"\n=== PRIVILEGED ACCOUNTS ({len(entries)}) ===")
                for e in entries:
                    lines.append(f"  {e.sAMAccountName}")
                self._ok(f"Found {len(entries)} privileged user(s)", count=len(entries))

            if enum in ("all", "policy"):
                self._emit("[*] Retrieving domain password policy…")
                entries = _search("(objectClass=domain)",
                                  ["minPwdLength","pwdHistoryLength",
                                   "lockoutThreshold","maxPwdAge","minPwdAge"])
                if entries:
                    e = entries[0]
                    pol = {
                        "minPwdLength":     str(e.minPwdLength or "?"),
                        "pwdHistoryLength":  str(e.pwdHistoryLength or "?"),
                        "lockoutThreshold":  str(e.lockoutThreshold or "?"),
                    }
                    lines.append("\n=== PASSWORD POLICY ===")
                    for k, v in pol.items():
                        lines.append(f"  {k}: {v}")
                    self._ok("Password policy retrieved", **pol)

            conn.unbind()

        # Write output
        output = "\n".join(lines)
        if output.strip() and outfile:
            try:
                import os
                os.makedirs(os.path.dirname(outfile) or ".", exist_ok=True)
                with open(outfile, "w", encoding="utf-8") as f:
                    f.write(output)
                self._emit(f"[+] Output saved to {outfile}")
            except OSError as e:
                self._emit(f"[-] Write error: {e}")

        if not any(r.ok for r in self.results):
            self._fail("Enumeration produced no results")
        return self.results


MODULE = LdapEnumModule
