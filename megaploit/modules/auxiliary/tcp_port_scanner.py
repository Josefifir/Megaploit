"""
megaploit.modules.auxiliary.tcp_port_scanner
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Fast multi-threaded TCP port scanner.

Options: RHOSTS (CIDR or single IP), PORTS (comma-separated, ranges OK),
         THREADS, TIMEOUT, VERBOSE
"""
from __future__ import annotations

import socket
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed

from megaploit.modules.base import Module, ModuleType, OptionType


class TcpPortScanner(Module):
    name        = "auxiliary/scanner/tcp_port"
    description = "Multi-threaded TCP connect() port scanner"
    module_type = ModuleType.AUXILIARY
    author      = "megaploit"
    rank        = 300

    def _define_options(self) -> None:
        self._opt("RHOSTS",  OptionType.STRING,  required=True,
                  description="Target IP, hostname, or CIDR (e.g. 10.0.0.0/24)")
        self._opt("PORTS",   OptionType.STRING,  default="21-23,25,53,80,110,135,139,143,443,445,3306,3389,8080,8443",
                  required=True,
                  description="Ports or ranges: 22,80,443,8000-9000")
        self._opt("THREADS", OptionType.INTEGER, default=100, required=False,
                  description="Concurrent threads")
        self._opt("TIMEOUT", OptionType.INTEGER, default=2,   required=False,
                  description="Connect timeout seconds")
        self._opt("VERBOSE", OptionType.BOOLEAN, default=False, required=False,
                  description="Print closed ports too")

    # ------------------------------------------------------------------

    @staticmethod
    def _parse_ports(spec: str) -> list[int]:
        ports: list[int] = []
        for part in spec.split(","):
            part = part.strip()
            if "-" in part:
                lo, hi = part.split("-", 1)
                ports.extend(range(int(lo), int(hi) + 1))
            else:
                ports.append(int(part))
        return sorted(set(ports))

    def _scan_one(self, host: str, port: int, timeout: int) -> tuple[str, int, bool, str]:
        try:
            with socket.create_connection((host, port), timeout=timeout):
                banner = ""
                return host, port, True, banner
        except Exception:
            return host, port, False, ""

    def run(self, session=None) -> list:
        self.validate()
        self.results.clear()

        rhosts  = str(self.get("RHOSTS"))
        ports   = self._parse_ports(str(self.get("PORTS")))
        threads = int(self.get("THREADS"))
        timeout = int(self.get("TIMEOUT"))
        verbose = bool(self.get("VERBOSE"))

        hosts: list[str] = []
        # Accept CIDR or single address/hostname
        if "/" in rhosts:
            hosts = list(self.expand_cidr(rhosts))
        else:
            hosts = [rhosts]

        self._emit(f"[*] Scanning {len(hosts)} host(s), {len(ports)} port(s)  ({threads} threads)")

        tasks: list[tuple[str, int]] = [(h, p) for h in hosts for p in ports]
        with ThreadPoolExecutor(max_workers=threads) as pool:
            futs = {pool.submit(self._scan_one, h, p, timeout): (h, p) for h, p in tasks}
            for fut in as_completed(futs):
                if self._stopped():
                    pool.shutdown(wait=False, cancel_futures=True)
                    break
                host, port, open_, _banner = fut.result()
                if open_:
                    self._ok(f"{host}:{port} open", host=host, port=port)
                elif verbose:
                    self._fail(f"{host}:{port} closed")

        open_cnt = sum(1 for r in self.results if r.ok)
        self._emit(f"[+] Scan complete — {open_cnt} open port(s) found")
        return self.results


MODULE = TcpPortScanner
