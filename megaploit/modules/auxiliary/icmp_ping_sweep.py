"""
megaploit.modules.auxiliary.icmp_ping_sweep
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
ICMP ping sweep using platform ``ping`` command.

Works on both Windows (ping -n 1 -w <ms>) and POSIX (ping -c 1 -W <s>).
Falls back to TCP-80 probe when ICMP is blocked.
"""
from __future__ import annotations

import platform
import socket
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed

from megaploit.modules.base import Module, ModuleType, OptionType


class IcmpPingSweep(Module):
    name        = "auxiliary/scanner/icmp_ping_sweep"
    description = "Host discovery via ICMP ping sweep (TCP-80 fallback)"
    module_type = ModuleType.AUXILIARY
    author      = "megaploit"
    rank        = 300

    _IS_WIN = platform.system().lower() == "windows"

    def _define_options(self) -> None:
        self._opt("RHOSTS",   OptionType.CIDR,    required=True,
                  description="CIDR range  e.g. 192.168.1.0/24")
        self._opt("THREADS",  OptionType.INTEGER, default=100, required=False,
                  description="Concurrent threads")
        self._opt("TIMEOUT",  OptionType.INTEGER, default=1,   required=False,
                  description="Ping wait seconds")
        self._opt("TCP_FALLBACK", OptionType.BOOLEAN, default=True, required=False,
                  description="Also try TCP:80 when ping fails")

    # ------------------------------------------------------------------

    def _ping_one(self, host: str, timeout: int) -> bool:
        if self._IS_WIN:
            cmd = ["ping", "-n", "1", "-w", str(timeout * 1000), host]
        else:
            cmd = ["ping", "-c", "1", "-W", str(timeout), host]
        try:
            rc = subprocess.call(cmd,
                                 stdout=subprocess.DEVNULL,
                                 stderr=subprocess.DEVNULL,
                                 timeout=timeout + 2)
            return rc == 0
        except Exception:
            return False

    def _tcp_probe(self, host: str, timeout: int) -> bool:
        for p in (80, 443, 22):
            try:
                with socket.create_connection((host, p), timeout=timeout):
                    return True
            except OSError:
                pass
        return False

    def _check_host(self, host: str, timeout: int, tcp_fb: bool) -> bool:
        if self._ping_one(host, timeout):
            return True
        if tcp_fb:
            return self._tcp_probe(host, timeout)
        return False

    def run(self, session=None) -> list:
        self.validate()
        self.results.clear()

        rhosts  = str(self.get("RHOSTS"))
        threads = int(self.get("THREADS"))
        timeout = int(self.get("TIMEOUT"))
        tcp_fb  = bool(self.get("TCP_FALLBACK"))

        hosts = list(self.expand_cidr(rhosts))
        self._emit(f"[*] Ping sweep — {len(hosts)} host(s)  tcp_fallback={tcp_fb}")

        with ThreadPoolExecutor(max_workers=threads) as pool:
            futs = {pool.submit(self._check_host, h, timeout, tcp_fb): h for h in hosts}
            for fut in as_completed(futs):
                if self._stopped():
                    pool.shutdown(wait=False, cancel_futures=True)
                    break
                host = futs[fut]
                alive = fut.result()
                if alive:
                    self._ok(f"{host}  alive", host=host)

        alive_cnt = sum(1 for r in self.results if r.ok)
        self._emit(f"[+] Done — {alive_cnt} host(s) alive")
        return self.results


MODULE = IcmpPingSweep
