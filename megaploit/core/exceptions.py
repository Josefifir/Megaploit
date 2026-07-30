"""
megaploit.core.exceptions
~~~~~~~~~~~~~~~~~~~~~~~~~
Common exception hierarchy for Megaploit protocol and networking code.

All protocol-level and server-level errors inherit from MegaploitError so
callers can catch the broad base class or a specific sub-type as needed.

Hierarchy
---------
MegaploitError
├── ProtocolError          — generic wire-protocol violation
│   ├── FramingError       — malformed frame (bad length, truncated, too large)
│   ├── DecryptionError    — AES-GCM authentication or decryption failure
│   ├── ReplayError        — sequence number replay detected
│   └── HandshakeError     — version negotiation or key exchange failure
└── PluginError            — plugin loading, validation, or execution failure
    ├── PluginLoadError    — file parse or schema validation error
    ├── PluginTrustError   — plugin blocked by trust policy (remote loading, path traversal)
    └── PluginExecError    — runtime error raised by a plugin handler
"""

from __future__ import annotations


class MegaploitError(Exception):
    """Base class for all Megaploit-specific errors."""


# ---------------------------------------------------------------------------
# Protocol errors
# ---------------------------------------------------------------------------

class ProtocolError(MegaploitError, ConnectionError):
    """Generic wire-protocol violation.

    Inherits from ConnectionError so existing ``except ConnectionError``
    handlers continue to catch protocol errors without modification.
    """


class FramingError(ProtocolError):
    """Malformed frame — bad length field, truncated body, or oversized frame."""


class DecryptionError(ProtocolError):
    """AES-GCM authentication tag mismatch or decryption failure."""


class ReplayError(ProtocolError, ValueError):
    """Sequence number replay detected.

    Inherits from ValueError so existing ``except ValueError`` handlers
    that check for replay continue to work.
    """


class HandshakeError(ProtocolError):
    """Version negotiation or cryptographic key exchange failure."""


# ---------------------------------------------------------------------------
# Plugin errors
# ---------------------------------------------------------------------------

class PluginError(MegaploitError):
    """Base class for plugin-related errors."""


class PluginLoadError(PluginError):
    """Failed to parse, validate, or register a plugin."""


class PluginTrustError(PluginError, PermissionError):
    """Plugin blocked by trust policy (remote loading disabled, path traversal, etc.).

    Inherits from PermissionError so existing ``except PermissionError``
    handlers continue to work.
    """


class PluginExecError(PluginError, RuntimeError):
    """Unhandled exception raised by a plugin handler at runtime."""
