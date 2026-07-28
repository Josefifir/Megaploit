"""
megaploit.modules.auxiliary.udp_scanner
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
UDP service discovery scanner.

Sends a protocol-appropriate probe payload for well-known UDP services
(DNS, SNMP, NTP, TFTP, mDNS, SSDP, NetBIOS-NS, CHARGEN) and listens
for a response.  Unknown ports get an empty datagram.
"""
from __future__ import annotations

import socket
import struct
from concurrent.futures import ThreadPoolExecutor, as_completed

from megaploit.modules.base import Module, ModuleType, OptionType


# Probe payloads keyed by port number
_PROBES: dict[int, bytes] = {
    53:   b"\xaa\xbb\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"    # DNS query
          b"\x07version\x04bind\x00\x00\x10\x00\x03",
    161:  b"\x30\x26\x02\x01\x01\x04\x06\x70\x75\x62\x6c\x69\x63"  # SNMPv1 GetRequest
          b"\xa0\x19\x02\x04\x72\x0b\x8c\x3f\x02\x01\x00\x02\x01"
          b"\x00\x30\x0b\x30\x09\x06\x05\x2b\x06\x01\x02\x01\x05\x00",
    123:  b"\x1b" + b"\x00" * 47,                                  # NTP client request
    69:   b"\x00\x01netascii\x00",                                  # TFTP RRQ
    5353: b"\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00"     # mDNS query
          b"\x05local\x00\x00\xff\x00\x01",
    137:  b"\xaa\xbb\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00"     # NetBIOS Name Service
          b"\x20CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x00\x00\x21\x00\x01",
    1900: b"M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\n"  # SSDP
          b"MAN: \"ssdp:discover\"\r\nMX: 1\r\nST: ssdp:all\r\n\r\n",
}


class UdpScanner(Module):
    name        = "auxiliary/scanner/udp_scanner"
    description = "UDP service discovery with protocol-specific probes"
    module_type = ModuleType.AUXILIARY
    author      = "megaploit"
    rank        = 300

    def _define_options(self) -> None:
        self._opt("RHOSTS",   OptionType.STRING,  required=True,
                  description="Target IP(s) or CIDR")
        self._opt("PORTS",    OptionType.STRING,  default="53,69,123,137,161,1900,5353",
                  required=True,
                  description="Comma-separated UDP ports (no range support)")
        self._opt("THREADS",  OptionType.INTEGER, default=50,  required=False,
                  description="Concurrent threads")
        self._opt("TIMEOUT",  OptionType.INTEGER, default=2,   required=False,
                  description="Receive timeout seconds")

    # ------------------------------------------------------------------

    @staticmethod
    def _parse_ports(spec: str) -> list[int]:
        return sorted({int(p.strip()) for p in spec.split(",") if p.strip()})

    def _probe_one(self, host: str, port: int, timeout: int) -> tuple[bool, bytes]:
        payload = _PROBES.get(port, b"\x00")
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.settimeout(timeout)
                s.sendto(payload, (host, port))
                data, _ = s.recvfrom(1024)
                return True, data
        except socket.timeout:
            return False, b""
        except Exception:
            return False, b""

    def run(self, session=None) -> list:
        self.validate()
        self.results.clear()

        rhosts  = str(self.get("RHOSTS"))
        ports   = self._parse_ports(str(self.get("PORTS")))
        threads = int(self.get("THREADS"))
        timeout = int(self.get("TIMEOUT"))

        hosts = list(self.expand_cidr(rhosts)) if "/" in rhosts else [rhosts]
        self._emit(f"[*] UDP scan — {len(hosts)} host(s) × {len(ports)} port(s)")

        tasks = [(h, p) for h in hosts for p in ports]
        with ThreadPoolExecutor(max_workers=threads) as pool:
            futs = {pool.submit(self._probe_one, h, p, timeout): (h, p) for h, p in tasks}
            for fut in as_completed(futs):
                if self._stopped():
                    pool.shutdown(wait=False, cancel_futures=True)
                    break
                host, port = futs[fut]
                responded, data = fut.result()
                if responded:
                    preview = data[:32].hex()
                    self._ok(f"{host}:{port}/udp  open  {preview}…",
                             host=host, port=port, data_hex=preview)

        found = sum(1 for r in self.results if r.ok)
        self._emit(f"[+] Done — {found} UDP port(s) responded")
        return self.results


MODULE = UdpScanner
