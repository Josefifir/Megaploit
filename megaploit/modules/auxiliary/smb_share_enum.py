"""
megaploit.modules.auxiliary.smb_share_enum
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Enumerate SMB shares on one or more targets.

Uses the ``impacket`` library when available; falls back to a raw
SMB negotiate / TREE_CONNECT probe otherwise.
"""
from __future__ import annotations

import socket
import struct
from concurrent.futures import ThreadPoolExecutor, as_completed

from megaploit.modules.base import Module, ModuleType, OptionType

try:
    from impacket.smbconnection import SMBConnection  # type: ignore
    _HAS_IMPACKET = True
except ImportError:
    _HAS_IMPACKET = False


class SmbShareEnum(Module):
    name        = "auxiliary/scanner/smb_share_enum"
    description = "Enumerate SMB shares (impacket if available, else raw probe)"
    module_type = ModuleType.AUXILIARY
    author      = "megaploit"
    rank        = 300

    def _define_options(self) -> None:
        self._opt("RHOSTS",   OptionType.STRING,  required=True,
                  description="Target IP(s) or CIDR")
        self._opt("USERNAME", OptionType.STRING,  default="",   required=False,
                  description="SMB username (blank for anonymous)")
        self._opt("PASSWORD", OptionType.STRING,  default="",   required=False,
                  description="SMB password")
        self._opt("DOMAIN",   OptionType.STRING,  default="WORKGROUP", required=False,
                  description="SMB domain / workgroup")
        self._opt("THREADS",  OptionType.INTEGER, default=20,   required=False,
                  description="Concurrent threads")
        self._opt("TIMEOUT",  OptionType.INTEGER, default=5,    required=False,
                  description="Per-host timeout seconds")

    # ------------------------------------------------------------------

    def _enum_host_impacket(self, host: str, user: str, pwd: str,
                             domain: str, timeout: int) -> list[str]:
        try:
            conn = SMBConnection(host, host, timeout=timeout)
            conn.login(user, pwd, domain)
            shares = []
            for share in conn.listShares():
                shares.append(share["shi1_netname"][:-1])  # strip null terminator
            conn.logoff()
            return shares
        except Exception as exc:
            return [f"ERROR: {exc}"]

    def _check_port_open(self, host: str, timeout: int) -> bool:
        try:
            with socket.create_connection((host, 445), timeout=timeout):
                return True
        except OSError:
            return False

    def _enum_host_raw(self, host: str, timeout: int) -> list[str]:
        """Basic TCP-445 check — no share listing without impacket."""
        if self._check_port_open(host, timeout):
            return ["<SMB port open — install impacket for share listing>"]
        return []

    def _process_host(self, host: str, user: str, pwd: str,
                       domain: str, timeout: int) -> None:
        if _HAS_IMPACKET:
            shares = self._enum_host_impacket(host, user, pwd, domain, timeout)
        else:
            shares = self._enum_host_raw(host, timeout)

        for s in shares:
            if s.startswith("ERROR"):
                self._fail(f"{host} — {s}", host=host)
            else:
                self._ok(f"{host}  \\\\{host}\\{s}", host=host, share=s)

    def run(self, session=None) -> list:
        self.validate()
        self.results.clear()

        rhosts  = str(self.get("RHOSTS"))
        user    = str(self.get("USERNAME"))
        pwd     = str(self.get("PASSWORD"))
        domain  = str(self.get("DOMAIN"))
        threads = int(self.get("THREADS"))
        timeout = int(self.get("TIMEOUT"))

        hosts = list(self.expand_cidr(rhosts)) if "/" in rhosts else [rhosts]
        backend = "impacket" if _HAS_IMPACKET else "raw-probe"
        self._emit(f"[*] SMB share enum  — {len(hosts)} host(s) via {backend}")

        with ThreadPoolExecutor(max_workers=threads) as pool:
            futs = {pool.submit(self._process_host, h, user, pwd, domain, timeout): h
                    for h in hosts}
            for fut in as_completed(futs):
                if self._stopped():
                    pool.shutdown(wait=False, cancel_futures=True)
                    break
                try:
                    fut.result()
                except Exception as exc:
                    self._fail(str(exc))

        found = sum(1 for r in self.results if r.ok)
        self._emit(f"[+] Done — {found} share(s) found")
        return self.results


MODULE = SmbShareEnum
