#!/usr/bin/env python3
"""
server.py — Megaploit C2 operator console.

Usage
-----
  python server.py -lh <your-ip> -p <port>
  python server.py -lh <your-ip> -p <port> --cert cert.pem --key key.pem
  python server.py -lh <your-ip> -p <port> --allow-ip 10.0.0.5 --allow-ip 10.0.0.6

Options
-------
  -lh, --lhost       IP address the agent will connect back to (required)
  -p,  --port        TCP port (required)
  -rh, --rhost       IP to bind the listener socket (default: 0.0.0.0)
  --cert             SSL certificate file (PEM)  — enables TLS 1.2+
  --key              SSL private key file (PEM)  — enables TLS 1.2+
  --secret           Path to secret.key (default: secret.key)
  --allow-ip         Allowlisted source IP; repeat for multiple.
                     If omitted, all IPs may attempt authentication.
"""

import argparse
import sys

from megaploit.server.cli import Console


def _parse() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="megaploit",
        description="Megaploit C2 operator console",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("-lh", "--lhost",    required=True,
                   help="Callback IP for the agent")
    p.add_argument("-p",  "--port",     type=int, required=True,
                   help="TCP port")
    p.add_argument("-rh", "--rhost",    default="0.0.0.0",
                   help="Listener bind IP (default: 0.0.0.0)")
    p.add_argument("--cert",            default="",
                   help="SSL certificate (PEM) — enables TLS")
    p.add_argument("--key",             default="",
                   help="SSL private key (PEM) — enables TLS")
    p.add_argument("--secret",          default="secret.key",
                   help="Path to HMAC secret key file")
    p.add_argument("--allow-ip",        dest="allow_ips", metavar="IP",
                   action="append", default=[],
                   help="Allowlisted source IP (repeat for multiple). "
                        "Omit to allow all IPs.")
    return p.parse_args()


def main() -> None:
    args = _parse()
    console = Console()
    try:
        console.run(
            bind_host=args.rhost,
            lhost=args.lhost,
            port=args.port,
            cert=args.cert,
            key_file=args.key,
            secret_key_path=args.secret,
            allowed_ips=args.allow_ips or None,
        )
    except KeyboardInterrupt:
        sys.exit(0)


if __name__ == "__main__":
    main()
