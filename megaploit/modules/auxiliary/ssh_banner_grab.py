"""
megaploit.modules.auxiliary.ssh_banner_grab
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Grab SSH version banners from one or more hosts.
"""
from __future__ import annotations

import socket
from concurrent.futures import ThreadPoolExecutor, as_completed

from megaploit.modules.base import Module, ModuleType, OptionType


class SshBannerGrab(Module):
    name        = "auxiliary/scanner/ssh_banner_grab"
    description = "Grab SSH server version banners"
    module_type = ModuleType.AUXILIARY
    author      = "megaploit"
    rank        = 300

    def _define_options(self) -> None:
        self._opt("RHOSTS",  OptionType.STRING,  required=True,
                  description="Target IP(s) or CIDR")
        self._opt("PORT",    OptionType.PORT,    default=22, required=False,
                  description="SSH port")
        self._opt("THREADS", OptionType.INTEGER, default=30, required=False,
                  description="Concurrent threads")
        self._opt("TIMEOUT", OptionType.INTEGER, default=4,  required=False,
                  description="Per-host timeout seconds")

    # ------------------------------------------------------------------

    def _grab_one(self, host: str, port: int, timeout: int) -> tuple[bool, str]:
        try:
            with socket.create_connection((host, port), timeout=timeout) as s:
                s.settimeout(timeout)
                banner = s.recv(256).decode(errors="replace").strip()
                return True, banner
        except Exception as exc:
            return False, str(exc)

    def run(self, session=None) -> list:
        self.validate()
        self.results.clear()

        rhosts  = str(self.get("RHOSTS"))
        port    = int(self.get("PORT"))
        threads = int(self.get("THREADS"))
        timeout = int(self.get("TIMEOUT"))

        hosts = list(self.expand_cidr(rhosts)) if "/" in rhosts else [rhosts]
        self._emit(f"[*] SSH banner grab — {len(hosts)} host(s) on port {port}")

        with ThreadPoolExecutor(max_workers=threads) as pool:
            futs = {pool.submit(self._grab_one, h, port, timeout): h for h in hosts}
            for fut in as_completed(futs):
                if self._stopped():
                    pool.shutdown(wait=False, cancel_futures=True)
                    break
                host = futs[fut]
                ok_, banner = fut.result()
                if ok_:
                    self._ok(f"{host}:{port}  {banner}", host=host, port=port, banner=banner)
                else:
                    self._fail(f"{host}:{port}  {banner}", host=host)

        found = sum(1 for r in self.results if r.ok)
        self._emit(f"[+] Done — {found} SSH banner(s) grabbed")
        return self.results


MODULE = SshBannerGrab
