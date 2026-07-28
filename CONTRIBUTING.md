# Contributing to Megaploit

Thank you for your interest in contributing! Please read this guide before submitting a pull request.

## Getting Started

1. Fork the repository
2. Clone your fork: `git clone https://github.com/<you>/Megaploit.git`
3. Install dependencies: `pip install -r requirements.txt && pip install pytest pytest-cov cryptography flask`
4. Run tests to verify your setup: `pytest tests/ -v`

## Development Workflow

1. Create a feature branch: `git checkout -b feature/my-feature`
2. Make your changes
3. Add tests in `tests/test_<module>.py`
4. Run tests: `pytest tests/ -v --tb=short`
5. Check for syntax errors: `python -m py_compile megaploit/**/*.py`
6. Commit with a descriptive message
7. Open a Pull Request against `main`

## Code Style

- **Python 3.10+ type hints** throughout; `from __future__ import annotations` in every module
- **`@dataclass`** for all data structures  
- **ANSI colour output** via `_c()` helper in `cli.py` — no colour output in library modules
- **Module docstrings** — every module-level docstring must explain what the module does and key design decisions
- Line length: 100 chars max (not enforced by linter, just a guideline)

## Adding a Session Command

**Server side** (`megaploit/server/commands.py`):

```python
@_cmd("mycommand", usage="mycommand <arg>", help_text="Does something useful")
def cmd_mycommand(session: Session, args: list[str]) -> CommandResult:
    if not args:
        return _err("Usage: mycommand <arg>")
    send_msg(session.conn, json.dumps({"cmd": "mycommand", "args": args}))
    return _ok(recv_msg(session.conn))
```

For file-receiving commands:
```python
err = _recv_file_or_err(session.conn, local_path, timeout=30)
if err:
    return err
return _ok(f"[+] Saved to: {local_path}")
```

**Agent side** (`megaploit/agent/handlers.py`):

```python
@_register("mycommand")
def _mycommand(conn, args: list[str]) -> str:
    return f"[+] Got: {args[0]}"
```

For file-sending handlers — always emit `FILE_OK` first:
```python
@_register("mycommand")
def _mycommand(conn, args: list[str]) -> None:
    # ... produce the file ...
    _send_msg(conn, "FILE_OK")
    _send_file(conn, path)
    return None   # shell.py sends nothing when handler returns None
```

## Adding a Module

1. Create `megaploit/modules/auxiliary/my_scanner.py` (or `exploits/`, `post/`)
2. Subclass `Module`, set class-level metadata, implement `_define_options()` and `run()`
3. Add `MODULE = MyClassName` at the bottom
4. Add test in `tests/test_modules_base.py` or a new `tests/test_my_scanner.py`
5. See [docs/MODULE_SYSTEM.md](docs/MODULE_SYSTEM.md) for the full guide

## Adding a Plugin (TOML — no Python required)

Create `plugins/myplugin.toml`. See `plugins/example.toml` for the full annotated schema.

## Adding a Toolbox Tool

```
megaploit > toolbox install https://github.com/user/repo toolname "description" --tags tag1,tag2
```

No code changes required.

## Writing Tests

Tests live in `tests/` and use `pytest`. Test files must be named `test_*.py`.

```python
# tests/test_my_module.py
import pytest
from megaploit.modules.auxiliary.my_scanner import MyScanner
from megaploit.modules.base import ModuleError

class TestMyScanner:
    def test_requires_rhosts(self):
        m = MyScanner()
        with pytest.raises(ModuleError):
            m.validate()

    def test_set_and_get_option(self):
        m = MyScanner()
        m.set("RHOSTS", "10.0.0.1")
        assert m.get("RHOSTS") == "10.0.0.1"
```

Run the full suite:
```bash
pytest tests/ -v --tb=short
pytest tests/ --cov=megaploit --cov-report=term-missing
```

## Pull Request Checklist

- [ ] Tests added for all new functionality
- [ ] All existing tests pass: `pytest tests/ -v`
- [ ] All new files compile: `python -m py_compile <file>`
- [ ] No new warnings in `py_compile`
- [ ] Docstrings added to new public functions/classes
- [ ] README.md updated if new commands or features added
- [ ] `CHANGELOG.md` or PR description explains the change

## Code of Conduct

All contributors must follow the [Code of Conduct](CODE_OF_CONDUCT.md). Be respectful and constructive.

## Discuss First

For significant changes (new subsystems, protocol changes, breaking API changes), please open an issue first to discuss the approach before investing time in implementation.
