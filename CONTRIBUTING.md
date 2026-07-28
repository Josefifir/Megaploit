# Contributing to Megaploit

Thank you for considering a contribution! This guide gets you from zero to a merged PR in as little time as possible.

> **New here?** Look for issues labelled [`good first issue`](https://github.com/Josefifir/Megaploit/labels/good%20first%20issue) or [`module-request`](https://github.com/Josefifir/Megaploit/labels/module-request) — these are intentionally scoped and well-documented.

---

## Table of Contents

1. [Quick start](#1-quick-start)
2. [What to contribute](#2-what-to-contribute)
3. [Adding an exploit / auxiliary module](#3-adding-an-exploit--auxiliary-module)
4. [Adding a session command](#4-adding-a-session-command)
5. [Adding a plugin (no Python required)](#5-adding-a-plugin-no-python-required)
6. [Writing tests](#6-writing-tests)
7. [Code style](#7-code-style)
8. [Pull request checklist](#8-pull-request-checklist)

---

## 1. Quick start

```bash
git clone https://github.com/<you>/Megaploit.git
cd Megaploit
pip install -r requirements.txt
pip install pytest pytest-cov cryptography flask
pytest tests/ -v --tb=short     # should all pass
```

Create a branch:

```bash
git checkout -b feat/my-exploit
```

---

## 2. What to contribute

| Type | Where | Effort |
|---|---|---|
| New exploit module | `megaploit/modules/exploits/` | Medium |
| New auxiliary scanner | `megaploit/modules/auxiliary/` | Low |
| New session command | `commands.py` + `handlers.py` | Medium |
| TOML plugin | `plugins/` | Very low — no Python needed |
| Bug fix | Anywhere | Varies |
| Documentation | `docs/` or `README.md` | Low |
| New test | `tests/` | Low |

---

## 3. Adding an exploit / auxiliary module

### Step 1 — copy the template

```bash
cp megaploit/modules/exploits/_template.py \
   megaploit/modules/exploits/<platform>/<category>/my_exploit.py
```

Platforms: `windows/`, `linux/`, `multi/`  
Categories: `smb/`, `http/`, `ssh/`, `rdp/`, `ftp/`, `redis/`, `misc/`

### Step 2 — fill in the template

The template is heavily commented. The minimum you need to change:

```python
class MyExploit(Module):
    name        = "exploits/windows/smb/my_exploit"   # must match file path
    description = "Short human-readable description"
    module_type = ModuleType.EXPLOIT
    author      = "your-handle"
    references  = ["CVE-2024-XXXXX", "https://nvd.nist.gov/..."]
    platform    = ["windows"]

    def _define_options(self) -> None:
        self._opt("RHOSTS", OptionType.STRING,  required=True)
        self._opt("LHOST",  OptionType.ADDRESS, required=True)

    def check(self, session=None) -> str:
        self.validate()
        # probe target without exploiting — return a status string
        return "[+] Target appears vulnerable"

    def run(self, session=None) -> list:
        self.validate()
        self.results.clear()
        # do the work; use self._ok() / self._fail() / self._emit()
        self._ok("Exploited", host=self.get("RHOSTS"))
        return self.results

MODULE = MyExploit   # required — registry discovers this
```

### Step 3 — test it

```bash
pytest tests/test_exploit_modules.py -v   # existing modules should still pass
python -m py_compile megaploit/modules/exploits/<platform>/<category>/my_exploit.py
```

### Step 4 — open a PR

The CI pipeline will run all tests automatically on your PR.

---

## 4. Adding a session command

Commands have two sides: **server** (operator → C2) and **agent** (C2 → victim).

**Server side** — `megaploit/server/commands.py`:

```python
@_cmd("mycommand", usage="mycommand <arg>", help_text="Does something useful")
def cmd_mycommand(session: Session, args: list[str]) -> CommandResult:
    if not args:
        return _err("Usage: mycommand <arg>")
    send_msg(session.conn, json.dumps({"cmd": "mycommand", "args": args}))
    return _ok(recv_msg(session.conn))
```

For commands that receive a file:

```python
err = _recv_file_or_err(session.conn, local_path, timeout=30)
if err:
    return err
return _ok(f"[+] Saved to: {local_path}")
```

**Agent side** — `megaploit/agent/handlers.py`:

```python
@_register("mycommand")
def _mycommand(conn, args: list[str]) -> str:
    return f"[+] Result: {args[0]}"
```

For handlers that send a file — always send `FILE_OK` first:

```python
@_register("mycommand")
def _mycommand(conn, args: list[str]) -> None:
    _send_msg(conn, "FILE_OK")
    _send_file(conn, path)
    return None   # shell.py sends nothing when handler returns None
```

---

## 5. Adding a plugin (no Python required)

Create `plugins/myplugin.toml`. The full annotated schema is in [`plugins/example.toml`](plugins/example.toml).

Minimal example — a command that runs on the operator machine:

```toml
[plugin]
name    = "my-tools"
version = "1.0.0"
author  = "you"

[[command]]
name    = "portscan"
kind    = "local"
shell   = "nmap -sV -p {arg0:-1-1000} {session_ip}"
usage   = "portscan [ports]"
timeout = 120
```

Drop the file in `plugins/` and run `plugins reload` in the console — no restart needed.

---

## 6. Writing tests

Tests live in `tests/` and use `pytest`.

```python
# tests/test_my_module.py
import pytest
from megaploit.modules.exploits.windows.smb.my_exploit import MyExploit
from megaploit.modules.base import ModuleError

class TestMyExploit:
    def test_requires_rhosts(self):
        m = MyExploit()
        with pytest.raises(ModuleError):
            m.validate()

    def test_set_and_get_option(self):
        m = MyExploit()
        m.set("RHOSTS", "10.0.0.1")
        m.set("LHOST",  "10.0.0.2")
        assert m.get("RHOSTS") == "10.0.0.1"
```

Run all tests:

```bash
pytest tests/ -v --tb=short
pytest tests/ --cov=megaploit --cov-report=term-missing
```

---

## 7. Code style

- **Python 3.10+ type hints** — `from __future__ import annotations` at the top of every file
- **`@dataclass`** for all data structures
- **ANSI colour** only via `_c()` helper in `cli.py` — no colour in library modules
- **Module-level docstrings** — explain what the module does and any non-obvious design choices
- Line length: 100 chars max (guideline, not enforced)
- No external dependencies unless unavoidable — keep the `requirements.txt` lean

---

## 8. Pull request checklist

- [ ] All existing tests pass: `pytest tests/ -v`
- [ ] New tests added for all new functionality
- [ ] All new `.py` files compile: `python -m py_compile <file>`
- [ ] Docstrings on all new public functions / classes
- [ ] `README.md` updated if new commands or features are user-visible
- [ ] No hardcoded IPs, credentials, or real target hostnames
- [ ] PR description explains *what* and *why*, not just *what*

---

For significant changes (new subsystems, protocol changes, breaking API changes) please **open an issue first** to discuss before investing time in a PR.

All contributors must follow the [Code of Conduct](CODE_OF_CONDUCT.md).
