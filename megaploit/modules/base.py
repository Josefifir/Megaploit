"""
megaploit.modules.base
~~~~~~~~~~~~~~~~~~~~~~
Base class for all Megaploit modules (exploits, auxiliary, post, payloads).

Every module is a Python file that defines a class inheriting from ``Module``.
The file must set a module-level ``MODULE`` variable pointing to that class, so
the registry can import it without instantiation:

    class MyScanner(Module):
        ...

    MODULE = MyScanner

Lifecycle
---------
1.  ``module.set(key, value)``          — fill required options
2.  ``module.validate()``               — raise ModuleError if options missing
3.  ``module.check()``                  — optional light probe before committing
4.  ``module.run(session=None)``        — execute the module
5.  ``module.results``                  — list[ModuleResult] after run
"""

from __future__ import annotations

import datetime
import ipaddress
import threading
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Iterator, Optional

__all__ = [
    "ModuleType",
    "OptionType",
    "ModuleOption",
    "ModuleResult",
    "ModuleError",
    "Module",
    "AgentModule",
]


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------

class ModuleType(str, Enum):
    EXPLOIT   = "exploit"
    AUXILIARY = "auxiliary"
    POST      = "post"
    PAYLOAD   = "payload"


class OptionType(str, Enum):
    STRING  = "string"
    INTEGER = "integer"
    BOOLEAN = "boolean"
    ADDRESS = "address"   # IPv4/IPv6 or hostname
    CIDR    = "cidr"      # CIDR range  e.g. 10.0.0.0/24
    PORT    = "port"      # 1-65535
    PATH    = "path"      # local filesystem path
    ENUM    = "enum"      # limited set of string choices


# ---------------------------------------------------------------------------
# Option descriptor
# ---------------------------------------------------------------------------

@dataclass
class ModuleOption:
    """Describes a single configurable option."""
    name:        str
    kind:        OptionType           = OptionType.STRING
    default:     Any                  = None
    required:    bool                 = True
    description: str                  = ""
    choices:     list[str]            = field(default_factory=list)  # for ENUM
    _value:      Any                  = field(default=None, init=False, repr=False)

    # ------------------------------------------------------------------
    def set(self, raw: str) -> None:
        """Parse and store a raw string value, coercing to the correct type."""
        if self.kind == OptionType.INTEGER:
            try:
                self._value = int(raw)
            except ValueError:
                raise ModuleError(f"Option {self.name!r}: expected integer, got {raw!r}")
        elif self.kind == OptionType.PORT:
            try:
                p = int(raw)
            except ValueError:
                raise ModuleError(f"Option {self.name!r}: expected integer port, got {raw!r}")
            if not (1 <= p <= 65535):
                raise ModuleError(f"Option {self.name!r}: port {p} out of range 1–65535")
            self._value = p
        elif self.kind == OptionType.BOOLEAN:
            if raw.lower() in ("true", "yes", "1", "on"):
                self._value = True
            elif raw.lower() in ("false", "no", "0", "off"):
                self._value = False
            else:
                raise ModuleError(f"Option {self.name!r}: expected boolean, got {raw!r}")
        elif self.kind == OptionType.ADDRESS:
            # Accept hostnames and IP addresses — only validate if it looks like an IP
            self._value = raw.strip()
        elif self.kind == OptionType.CIDR:
            try:
                ipaddress.ip_network(raw, strict=False)
            except ValueError:
                raise ModuleError(f"Option {self.name!r}: invalid CIDR {raw!r}")
            self._value = raw.strip()
        elif self.kind == OptionType.ENUM:
            if self.choices and raw not in self.choices:
                raise ModuleError(
                    f"Option {self.name!r}: must be one of {self.choices}, got {raw!r}"
                )
            self._value = raw
        else:
            self._value = raw

    @property
    def value(self) -> Any:
        return self._value if self._value is not None else self.default

    @property
    def is_set(self) -> bool:
        return self._value is not None or self.default is not None

    def reset(self) -> None:
        self._value = None


# ---------------------------------------------------------------------------
# Result object
# ---------------------------------------------------------------------------

@dataclass
class ModuleResult:
    """A single finding/result item produced during module execution."""
    ok:        bool
    message:   str
    data:      dict[str, Any]    = field(default_factory=dict)
    timestamp: str               = field(
        default_factory=lambda: datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
    )

    def __str__(self) -> str:
        prefix = "[+]" if self.ok else "[-]"
        return f"{prefix} {self.message}"


# ---------------------------------------------------------------------------
# Exception
# ---------------------------------------------------------------------------

class ModuleError(Exception):
    """Raised when a module encounters a configuration or runtime error."""


# ---------------------------------------------------------------------------
# Base module
# ---------------------------------------------------------------------------

class Module:
    """
    Abstract base class for all Megaploit modules.

    Subclasses MUST set:
        name        — unique identifier  e.g. "auxiliary/scanner/tcp_port"
        description — one-line summary
        module_type — ModuleType enum value

    Subclasses SHOULD override:
        _define_options() — register options via self._opt(...)
        run()             — the main execution logic
        check()           — optional pre-run probe
    """

    name:        str        = "unknown/module"
    description: str        = "No description."
    module_type: ModuleType = ModuleType.AUXILIARY
    author:      str        = "unknown"
    references:  list[str]  = []
    platform:    list[str]  = []    # e.g. ["windows", "linux"]
    arch:        list[str]  = []    # e.g. ["x86", "x64"]
    rank:        int        = 300   # 100=low … 600=excellent (Metasploit convention)

    # ------------------------------------------------------------------
    def __init__(self) -> None:
        self._options: dict[str, ModuleOption] = {}
        self.results:  list[ModuleResult]      = []
        self._output_cb: Optional[Callable[[str], None]] = None
        self._stop_event = threading.Event()
        self._define_options()

    # ------------------------------------------------------------------
    # Option helpers
    # ------------------------------------------------------------------

    def _opt(
        self,
        name:        str,
        kind:        OptionType = OptionType.STRING,
        default:     Any        = None,
        required:    bool       = True,
        description: str        = "",
        choices:     list[str]  = None,
    ) -> None:
        """Register an option.  Call only from _define_options()."""
        self._options[name.upper()] = ModuleOption(
            name=name.upper(),
            kind=kind,
            default=default,
            required=required,
            description=description,
            choices=choices or [],
        )

    def _define_options(self) -> None:
        """Override to define module options via self._opt(...)."""

    def set(self, key: str, value: str) -> None:
        """Set an option value (raises ModuleError on bad input)."""
        k = key.upper()
        if k not in self._options:
            raise ModuleError(f"Unknown option: {key!r}")
        self._options[k].set(value)

    def get(self, key: str) -> Any:
        """Get the current value of an option."""
        k = key.upper()
        if k not in self._options:
            raise ModuleError(f"Unknown option: {key!r}")
        return self._options[k].value

    def options(self) -> dict[str, ModuleOption]:
        return dict(self._options)

    def unset(self, key: str) -> None:
        k = key.upper()
        if k in self._options:
            self._options[k].reset()

    # ------------------------------------------------------------------
    # Validation
    # ------------------------------------------------------------------

    def validate(self) -> None:
        """Raise ModuleError if any required option is unset."""
        missing = [
            opt.name for opt in self._options.values()
            if opt.required and not opt.is_set
        ]
        if missing:
            raise ModuleError(
                "Required option(s) not set: " + ", ".join(missing)
            )

    # ------------------------------------------------------------------
    # Output streaming
    # ------------------------------------------------------------------

    def set_output_callback(self, cb: Callable[[str], None]) -> None:
        """Register a function that receives real-time output lines."""
        self._output_cb = cb

    def _emit(self, msg: str) -> None:
        """Emit a line of output (calls callback if registered, else no-op)."""
        if self._output_cb:
            self._output_cb(msg)

    def _ok(self, msg: str, **data: Any) -> ModuleResult:
        r = ModuleResult(ok=True, message=msg, data=data)
        self.results.append(r)
        self._emit(str(r))
        return r

    def _fail(self, msg: str, **data: Any) -> ModuleResult:
        r = ModuleResult(ok=False, message=msg, data=data)
        self.results.append(r)
        self._emit(str(r))
        return r

    # ------------------------------------------------------------------
    # Stop / interrupt
    # ------------------------------------------------------------------

    def stop(self) -> None:
        """Signal the module to stop (checked via self._stopped())."""
        self._stop_event.set()

    def _stopped(self) -> bool:
        return self._stop_event.is_set()

    # ------------------------------------------------------------------
    # Lifecycle methods — override in subclasses
    # ------------------------------------------------------------------

    def check(self, session=None) -> Optional[str]:
        """
        Optional pre-run probe.

        Returns a human-readable status string, or None if check is not
        implemented.  Should NOT modify target state.
        """
        return None

    def run(self, session=None) -> list[ModuleResult]:
        """
        Execute the module.

        Must call self.validate() at the start.
        Should call self._ok() / self._fail() to record results.
        Returns self.results.
        """
        raise NotImplementedError(f"{self.__class__.__name__}.run() is not implemented")

    # ------------------------------------------------------------------
    # Introspection
    # ------------------------------------------------------------------

    def info(self) -> dict[str, Any]:
        """Return a serialisable info dict (used by 'info' command)."""
        return {
            "name":        self.name,
            "description": self.description,
            "type":        self.module_type.value,
            "author":      self.author,
            "references":  list(self.references),
            "platform":    list(self.platform),
            "arch":        list(self.arch),
            "rank":        self.rank,
            "options": {
                name: {
                    "kind":        opt.kind.value,
                    "default":     opt.default,
                    "required":    opt.required,
                    "description": opt.description,
                    "value":       opt.value,
                    "choices":     opt.choices,
                }
                for name, opt in self._options.items()
            },
        }

    def __repr__(self) -> str:
        return f"<Module {self.name}  type={self.module_type.value}>"

    # ------------------------------------------------------------------
    # CIDR expansion helper (used by scanner modules)
    # ------------------------------------------------------------------

    @staticmethod
    def expand_cidr(cidr: str) -> Iterator[str]:
        """Yield individual IP strings from a CIDR range."""
        try:
            net = ipaddress.ip_network(cidr, strict=False)
            for host in net.hosts():
                yield str(host)
        except ValueError:
            yield cidr

    # ------------------------------------------------------------------
    # Rate-limited iteration helper
    # ------------------------------------------------------------------

    def _throttled_hosts(
        self, hosts: list[str], rate_per_sec: float = 100.0
    ) -> Iterator[str]:
        """Yield hosts with rate limiting.  Stops if stop() is called."""
        delay = 1.0 / max(rate_per_sec, 0.1)
        for h in hosts:
            if self._stopped():
                return
            yield h
            time.sleep(delay)


# ---------------------------------------------------------------------------
# AgentModule  — session-bound post-exploitation base class
# ---------------------------------------------------------------------------

class AgentModule(Module):
    """
    Base class for modules that run *against* an active agent session.

    Adds
    ----
    * ``session``       — set automatically by the console before ``run()``
    * ``_send(cmd)``    — send a raw command string and return the response text
    * ``_shell(cmd)``   — alias for _send
    * ``_upload(local, remote)``  — transfer a local file to the target
    * ``_download(remote, local)``— pull a file from the target

    Subclasses still define options via ``_define_options()`` and implement
    ``run(session=None)``.  The ``session`` keyword arg is the preferred path;
    the ``self.session`` attribute is set by the console for convenience.

    Example
    -------
    ::

        class DumpShadow(AgentModule):
            name        = "post/linux/dump_shadow"
            description = "Read /etc/shadow and store as loot"
            module_type = ModuleType.POST
            platform    = ["linux"]

            def run(self, session=None):
                self.validate()
                sess = session or self.session
                if sess is None:
                    raise ModuleError("No session — use: set SESSION <id>")
                out = self._send("shell cat /etc/shadow", sess)
                if out.strip():
                    self._ok("shadow file retrieved", data={"shadow": out})
                else:
                    self._fail("empty output from /etc/shadow")
                return self.results
    """

    module_type: ModuleType = ModuleType.POST

    def __init__(self) -> None:
        super().__init__()
        self.session = None   # set by the console via module.session = <Session>

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _send(self, cmd: str, session=None) -> str:
        """
        Send *cmd* to the session and return the response text.

        Uses ``self.session`` if *session* is not provided.
        Raises ``ModuleError`` if no session is available.
        """
        sess = session or self.session
        if sess is None:
            raise ModuleError("AgentModule._send(): no session attached")
        try:
            from megaploit.server.commands import dispatch
            result = dispatch(sess, cmd)
            return result.output or ""
        except Exception as exc:
            raise ModuleError(f"dispatch failed: {exc}") from exc

    # Alias
    def _shell(self, cmd: str, session=None) -> str:
        """Alias for ``_send``."""
        return self._send(cmd, session)

    def _upload(self, local_path: str, remote_path: str, session=None) -> str:
        """Upload *local_path* to *remote_path* on the target."""
        return self._send(f"upload {local_path} {remote_path}", session)

    def _download(self, remote_path: str, local_path: str, session=None) -> str:
        """Download *remote_path* from target to *local_path*."""
        return self._send(f"download {remote_path} {local_path}", session)
