"""
megaploit.modules.auxiliary.banner_grabber
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Generic TCP banner grabber for arbitrary ports.

Sends an optional prompt string and reads back up to RECV_SIZE bytes,
recording service fingerprints that can be used for version detection.
"""
from __future__ import annotations

import socket
from concurrent.futures import ThreadPoolExecutor, as_completed

from megaploit.modules.base import Module, ModuleType, OptionType


# Common service fingerprint patterns  (banner substring → service label)
_FINGERPRINTS: list[tuple[str, str]] = [
    ("SSH-2.0",      "OpenSSH"),
    ("SSH-1.99",     "SSH-legacy"),
    ("220 ",         "FTP/SMTP/POP"),
    ("HTTP/",        "HTTP"),
    ("* OK",         "IMAP"),
    ("+OK",          "POP3"),
    ("ESMTP",        "SMTP"),
    ("FTP",          "FTP"),
    ("220-",         "SMTP/FTP"),
    ("RFB ",         "VNC"),
    ("JDWP",         "Java-JDWP"),
    ("RMI",          "Java-RMI"),
    ("%TAPI",        "TAPI"),
    ("AMQP",         "RabbitMQ/AMQP"),
    ("REDIS",        "Redis"),
    ("Postfix",      "Postfix-SMTP"),
    ("Exim",         "Exim-SMTP"),
    ("ProFTPD",      "ProFTPD"),
    ("vsftpd",       "vsftpd"),
    ("PureFTPd",     "PureFTPD"),
    ("MySQL",        "MySQL"),
    ("MariaDB",      "MariaDB"),
    ("PostgreSQL",   "PostgreSQL"),
]


def _fingerprint(banner: str) -> str:
    for pattern, label in _FINGERPRINTS:
        if pattern in banner:
            return label
    return "unknown"


class BannerGrabber(Module):
    name        = "auxiliary/scanner/banner_grabber"
    description = "TCP banner grabber with service fingerprinting"
    module_type = ModuleType.AUXILIARY
    author      = "megaploit"
    rank        = 300

    def _define_options(self) -> None:
        self._opt("RHOSTS",    OptionType.STRING,  required=True,
                  description="Target IP(s) or CIDR")
        self._opt("PORTS",     OptionType.STRING,  default="21,22,23,25,80,110,143,443,3306,5432",
                  required=True,
                  description="Comma-separated ports (ranges OK)")
        self._opt("PROMPT",    OptionType.STRING,  default="", required=False,
                  description="Optional data to send before reading (e.g. HEAD / HTTP/1.0\\r\\n\\r\\n)")
        self._opt("RECV_SIZE", OptionType.INTEGER, default=1024, required=False,
                  description="Max bytes to read from banner")
        self._opt("THREADS",   OptionType.INTEGER, default=50,   required=False,
                  description="Concurrent threads")
        self._opt("TIMEOUT",   OptionType.INTEGER, default=4,    required=False,
                  description="Per-host timeout seconds")

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

    def _grab_one(self, host: str, port: int,
                   prompt: bytes, recv_size: int, timeout: int) -> tuple[bool, str]:
        try:
            with socket.create_connection((host, port), timeout=timeout) as s:
                s.settimeout(timeout)
                if prompt:
                    s.sendall(prompt)
                data = b""
                while len(data) < recv_size:
                    chunk = s.recv(recv_size - len(data))
                    if not chunk:
                        break
                    data += chunk
                banner = data.decode(errors="replace").strip()
                return True, banner
        except Exception as exc:
            return False, str(exc)

    def run(self, session=None) -> list:
        self.validate()
        self.results.clear()

        rhosts    = str(self.get("RHOSTS"))
        ports     = self._parse_ports(str(self.get("PORTS")))
        prompt    = str(self.get("PROMPT")).encode().replace(b"\\r\\n", b"\r\n")
        recv_size = int(self.get("RECV_SIZE"))
        threads   = int(self.get("THREADS"))
        timeout   = int(self.get("TIMEOUT"))

        hosts = list(self.expand_cidr(rhosts)) if "/" in rhosts else [rhosts]
        self._emit(f"[*] Banner grab — {len(hosts)} host(s) × {len(ports)} port(s)")

        tasks = [(h, p) for h in hosts for p in ports]
        with ThreadPoolExecutor(max_workers=threads) as pool:
            futs = {pool.submit(self._grab_one, h, p, prompt, recv_size, timeout): (h, p)
                    for h, p in tasks}
            for fut in as_completed(futs):
                if self._stopped():
                    pool.shutdown(wait=False, cancel_futures=True)
                    break
                host, port = futs[fut]
                ok_, banner = fut.result()
                if ok_ and banner:
                    svc = _fingerprint(banner)
                    first_line = banner.splitlines()[0][:80]
                    self._ok(f"{host}:{port}  [{svc}]  {first_line}",
                             host=host, port=port, service=svc, banner=banner)

        found = sum(1 for r in self.results if r.ok)
        self._emit(f"[+] Done — {found} banner(s) grabbed")
        return self.results


MODULE = BannerGrabber
