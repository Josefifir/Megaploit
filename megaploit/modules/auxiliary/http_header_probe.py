"""
megaploit.modules.auxiliary.http_header_probe
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Probe HTTP/HTTPS response headers on a list of targets.

Collects: Server, X-Powered-By, X-Frame-Options, Content-Security-Policy,
          Strict-Transport-Security, Set-Cookie (flags only), WWW-Authenticate.
"""
from __future__ import annotations

import http.client
import ssl
from concurrent.futures import ThreadPoolExecutor, as_completed

from megaploit.modules.base import Module, ModuleType, OptionType


_INTERESTING = {
    "server", "x-powered-by", "x-frame-options", "content-security-policy",
    "strict-transport-security", "www-authenticate", "x-aspnet-version",
    "x-generator", "via", "x-backend-server",
}


class HttpHeaderProbe(Module):
    name        = "auxiliary/scanner/http_header_probe"
    description = "Fingerprint web servers via HTTP response headers"
    module_type = ModuleType.AUXILIARY
    author      = "megaploit"
    rank        = 300

    def _define_options(self) -> None:
        self._opt("RHOSTS",   OptionType.STRING,  required=True,
                  description="IP(s) or hostname(s), comma-separated or CIDR")
        self._opt("PORT",     OptionType.PORT,    default=80, required=False,
                  description="HTTP port")
        self._opt("SSL",      OptionType.BOOLEAN, default=False, required=False,
                  description="Use HTTPS")
        self._opt("PATH",     OptionType.STRING,  default="/", required=False,
                  description="URI path to request")
        self._opt("THREADS",  OptionType.INTEGER, default=30,  required=False,
                  description="Concurrent threads")
        self._opt("TIMEOUT",  OptionType.INTEGER, default=5,   required=False,
                  description="Per-host timeout seconds")
        self._opt("VHOST",    OptionType.STRING,  default="",  required=False,
                  description="Optional Host header override")

    # ------------------------------------------------------------------

    def _probe_host(self, host: str, port: int, use_ssl: bool,
                    path: str, vhost: str, timeout: int) -> dict[str, str]:
        try:
            ctx = ssl.create_default_context() if use_ssl else None
            if ctx:
                ctx.check_hostname = False
                ctx.verify_mode    = ssl.CERT_NONE
            ConnClass = http.client.HTTPSConnection if use_ssl else http.client.HTTPConnection
            conn = ConnClass(host, port, timeout=timeout, context=ctx) if use_ssl \
                else ConnClass(host, port, timeout=timeout)
            headers = {"Host": vhost or host, "User-Agent": "Mozilla/5.0 (Megaploit)"}
            conn.request("HEAD", path, headers=headers)
            resp = conn.getresponse()
            conn.close()
            result = {"STATUS": str(resp.status)}
            for hname, hval in resp.getheaders():
                if hname.lower() in _INTERESTING:
                    result[hname.lower()] = hval
            return result
        except Exception as exc:
            return {"ERROR": str(exc)}

    def run(self, session=None) -> list:
        self.validate()
        self.results.clear()

        rhosts  = str(self.get("RHOSTS"))
        port    = int(self.get("PORT"))
        use_ssl = bool(self.get("SSL"))
        path    = str(self.get("PATH"))
        vhost   = str(self.get("VHOST"))
        threads = int(self.get("THREADS"))
        timeout = int(self.get("TIMEOUT"))

        # Build host list — support comma-separated + CIDR
        raw_hosts = [h.strip() for h in rhosts.split(",")]
        hosts: list[str] = []
        for rh in raw_hosts:
            if "/" in rh:
                hosts.extend(self.expand_cidr(rh))
            else:
                hosts.append(rh)

        scheme = "https" if use_ssl else "http"
        self._emit(f"[*] HTTP header probe — {len(hosts)} host(s) on {scheme}:{port}{path}")

        with ThreadPoolExecutor(max_workers=threads) as pool:
            futs = {
                pool.submit(self._probe_host, h, port, use_ssl, path, vhost, timeout): h
                for h in hosts
            }
            for fut in as_completed(futs):
                if self._stopped():
                    pool.shutdown(wait=False, cancel_futures=True)
                    break
                host = futs[fut]
                headers = fut.result()
                if "ERROR" in headers:
                    self._fail(f"{host} — {headers['ERROR']}", host=host)
                else:
                    status = headers.pop("STATUS", "?")
                    parts  = [f"HTTP {status}"] + [f"{k}: {v}" for k, v in headers.items()]
                    self._ok("  ".join(parts), host=host, headers=headers, status=status)

        found = sum(1 for r in self.results if r.ok)
        self._emit(f"[+] Done — {found} host(s) responded")
        return self.results


MODULE = HttpHeaderProbe
