"""
megaploit.modules.auxiliary.dns_resolver
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Perform bulk DNS lookups (A, AAAA, MX, NS, TXT, PTR, CNAME).
"""
from __future__ import annotations

import socket
from concurrent.futures import ThreadPoolExecutor, as_completed

from megaploit.modules.base import Module, ModuleType, OptionType

try:
    import dns.resolver   # type: ignore
    import dns.reversename
    _HAS_DNSPYTHON = True
except ImportError:
    _HAS_DNSPYTHON = False


class DnsResolver(Module):
    name        = "auxiliary/scanner/dns_resolver"
    description = "Bulk DNS lookups with optional record-type selection"
    module_type = ModuleType.AUXILIARY
    author      = "megaploit"
    rank        = 300

    def _define_options(self) -> None:
        self._opt("TARGETS",    OptionType.STRING, required=True,
                  description="Comma-separated hostnames or IPs for PTR")
        self._opt("RECORD",     OptionType.ENUM,   default="A", required=False,
                  description="DNS record type to query",
                  choices=["A", "AAAA", "MX", "NS", "TXT", "CNAME", "PTR", "ANY"])
        self._opt("NAMESERVER", OptionType.STRING, default="", required=False,
                  description="Custom DNS server (blank = system default)")
        self._opt("THREADS",    OptionType.INTEGER, default=20, required=False,
                  description="Concurrent threads")
        self._opt("TIMEOUT",    OptionType.INTEGER, default=5,  required=False,
                  description="Query timeout seconds")

    # ------------------------------------------------------------------

    def _resolve_system(self, target: str, rtype: str) -> list[str]:
        """Fallback when dnspython is unavailable — A/AAAA only."""
        try:
            if rtype in ("A", "AAAA", "ANY"):
                infos = socket.getaddrinfo(target, None)
                return list({i[4][0] for i in infos})
            return [f"(dnspython required for {rtype} records)"]
        except socket.gaierror as exc:
            return [f"ERROR: {exc}"]

    def _resolve_dnspython(self, target: str, rtype: str,
                            ns: str, timeout: int) -> list[str]:
        try:
            resolver = dns.resolver.Resolver()
            if ns:
                resolver.nameservers = [ns]
            resolver.lifetime = timeout

            if rtype == "PTR":
                addr = dns.reversename.from_address(target)
                answers = resolver.resolve(addr, "PTR")
            else:
                answers = resolver.resolve(target, rtype)

            return [str(r) for r in answers]
        except Exception as exc:
            return [f"ERROR: {exc}"]

    def run(self, session=None) -> list:
        self.validate()
        self.results.clear()

        targets_raw = str(self.get("TARGETS"))
        rtype       = str(self.get("RECORD"))
        ns          = str(self.get("NAMESERVER"))
        threads     = int(self.get("THREADS"))
        timeout     = int(self.get("TIMEOUT"))

        targets = [t.strip() for t in targets_raw.split(",") if t.strip()]
        backend = "dnspython" if _HAS_DNSPYTHON else "system"
        self._emit(f"[*] DNS {rtype} lookup — {len(targets)} target(s) via {backend}")

        def _work(target: str) -> None:
            if _HAS_DNSPYTHON:
                records = self._resolve_dnspython(target, rtype, ns, timeout)
            else:
                records = self._resolve_system(target, rtype)
            for rec in records:
                if rec.startswith("ERROR:"):
                    self._fail(f"{target}  {rec}", target=target)
                else:
                    self._ok(f"{target}  {rtype}  {rec}", target=target, record=rec, rtype=rtype)

        with ThreadPoolExecutor(max_workers=threads) as pool:
            futs = [pool.submit(_work, t) for t in targets]
            for fut in as_completed(futs):
                if self._stopped():
                    pool.shutdown(wait=False, cancel_futures=True)
                    break
                try:
                    fut.result()
                except Exception as exc:
                    self._fail(str(exc))

        found = sum(1 for r in self.results if r.ok)
        self._emit(f"[+] Done — {found} record(s) resolved")
        return self.results


MODULE = DnsResolver
