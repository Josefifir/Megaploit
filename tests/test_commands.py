"""
Unit tests for megaploit.server.commands — dispatch() and all_commands().

Strategy
--------
Commands that perform send_msg/recv_msg round-trips are tested with a real
in-process TCP socket pair (same technique as test_protocol.py).  The
"agent" side is a simple echo/response thread.

Commands that only do local work (help, cd bad-args, note, loot_list, tag,
handler-raises) are tested by mocking the session socket with MagicMock so
no real I/O is needed.
"""
from __future__ import annotations

import json
import os
import socket
import struct
import threading
from unittest.mock import MagicMock, patch

import pytest

from megaploit.server.commands import (
    CommandResult,
    _CommandDef,
    all_commands,
    dispatch,
)
from megaploit.server.session import Session


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _frame(data: bytes) -> bytes:
    return struct.pack(">I", len(data)) + data


def _recv_framed(sock: socket.socket) -> bytes:
    buf = b""
    while len(buf) < 4:
        chunk = sock.recv(4 - len(buf))
        if not chunk:
            raise ConnectionError
        buf += chunk
    (length,) = struct.unpack(">I", buf)
    data = b""
    while len(data) < length:
        chunk = sock.recv(min(65536, length - len(data)))
        if not chunk:
            raise ConnectionError
        data += chunk
    return data


def _socket_pair() -> tuple[socket.socket, socket.socket]:
    """Return (server_conn, client_conn) — a connected in-process pair."""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    port = srv.getsockname()[1]
    cli = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    cli.connect(("127.0.0.1", port))
    conn, _ = srv.accept()
    srv.close()
    return conn, cli


def _agent_side(sock: socket.socket, responses: list[str]) -> None:
    """
    Minimal 'agent' thread: for each framed JSON message received, pop and
    send back the next canned response.  Closes when responses are exhausted
    or the peer disconnects.
    """
    try:
        for resp in responses:
            raw = _recv_framed(sock)
            # seq(8) + payload
            payload = raw[8:]
            # Send back: seq(8) + JSON response
            reply_payload = struct.pack(">Q", 1) + json.dumps(resp).encode()
            sock.sendall(_frame(reply_payload))
    except (ConnectionError, OSError):
        pass
    finally:
        try:
            sock.close()
        except OSError:
            pass


def _make_session_with_agent(responses: list[str]) -> tuple[Session, socket.socket, threading.Thread]:
    """
    Spin up an agent thread that returns *responses* in order.
    Returns (session_using_client_conn, agent_conn, thread).

    Each call creates a fresh _ConnState so sequence counters start at 0
    — avoids replay-detection failures when the OS reuses a file-descriptor
    number across successive tests.
    """
    from megaploit.core.protocol import _ConnState, set_state, remove_state

    agent_conn, client_conn = _socket_pair()
    t = threading.Thread(target=_agent_side, args=(agent_conn, responses), daemon=True)
    t.start()

    # Force-install a brand-new (zeroed) _ConnState for this socket.
    set_state(client_conn, _ConnState())

    session = Session(conn=client_conn, ip="10.0.0.1", port=54321, id=1)
    return session, agent_conn, t


def _mock_session() -> Session:
    """Session backed by a MagicMock socket — for commands that don't do I/O."""
    sess = MagicMock(spec=Session)
    sess.id       = 1
    sess.ip       = "10.0.0.1"
    sess.port     = 54321
    sess.tag      = ""
    sess.os_name  = ""
    sess.hostname = ""
    sess.username = ""
    sess.conn     = MagicMock()
    return sess


# ---------------------------------------------------------------------------
# all_commands()
# ---------------------------------------------------------------------------

class TestAllCommands:
    def test_returns_dict(self):
        cmds = all_commands()
        assert isinstance(cmds, dict)

    def test_non_empty(self):
        assert len(all_commands()) > 0

    def test_contains_core_commands(self):
        cmds = all_commands()
        for name in ("help", "exit", "sysinfo", "cd", "shell",
                     "upload", "download", "screenshot", "record",
                     "ps", "netstat", "hashdump", "keylog_start"):
            assert name in cmds, f"'{name}' missing from all_commands()"

    def test_values_are_command_defs(self):
        for name, defn in all_commands().items():
            assert isinstance(defn, _CommandDef), f"Entry {name!r} is not a _CommandDef"

    def test_command_def_has_required_fields(self):
        for name, defn in all_commands().items():
            assert isinstance(defn.name, str)
            assert isinstance(defn.usage, str)
            assert isinstance(defn.help_text, str)
            assert isinstance(defn.dangerous, bool)
            assert callable(defn.handler)

    def test_returns_snapshot_not_reference(self):
        """Mutating the returned dict must not affect the real registry."""
        cmds = all_commands()
        original_len = len(cmds)
        cmds["__fake__"] = MagicMock()
        assert len(all_commands()) == original_len

    def test_dangerous_commands_flagged(self):
        """Commands we know to be dangerous must carry dangerous=True."""
        cmds = all_commands()
        for name in ("hashdump", "self_destruct", "inject_shellcode"):
            assert cmds[name].dangerous is True, f"'{name}' should be dangerous"

    def test_non_dangerous_commands_not_flagged(self):
        cmds = all_commands()
        for name in ("sysinfo", "ps", "screenshot", "netstat"):
            assert cmds[name].dangerous is False, f"'{name}' should not be dangerous"


# ---------------------------------------------------------------------------
# dispatch() — commands with no socket I/O
# ---------------------------------------------------------------------------

class TestDispatchNoIO:
    def test_empty_string_returns_ok(self):
        sess = _mock_session()
        result = dispatch(sess, "   ")
        assert result.ok is True

    def test_help_returns_ok(self):
        sess = _mock_session()
        result = dispatch(sess, "help")
        assert result.ok is True
        assert "COMMAND" in result.output

    def test_help_lists_registered_commands(self):
        sess = _mock_session()
        result = dispatch(sess, "help")
        for name in ("sysinfo", "screenshot", "ps", "netstat"):
            assert name in result.output

    def test_cd_missing_arg_returns_err(self):
        sess = _mock_session()
        result = dispatch(sess, "cd")
        assert result.ok is False
        assert "Usage" in result.output

    def test_cd_too_many_args_returns_err(self):
        sess = _mock_session()
        result = dispatch(sess, "cd /tmp /var")
        assert result.ok is False

    def test_upload_missing_arg_returns_err(self):
        sess = _mock_session()
        result = dispatch(sess, "upload")
        assert result.ok is False
        assert "Usage" in result.output

    def test_upload_nonexistent_file_returns_err(self):
        sess = _mock_session()
        result = dispatch(sess, "upload /no/such/file.txt")
        assert result.ok is False
        assert "not found" in result.output.lower() or "File not found" in result.output

    def test_record_non_digit_returns_err(self):
        sess = _mock_session()
        result = dispatch(sess, "record abc")
        assert result.ok is False

    def test_inject_shellcode_bad_args_returns_err(self):
        sess = _mock_session()
        result = dispatch(sess, "inject_shellcode")
        assert result.ok is False

    def test_make_token_missing_args_returns_err(self):
        sess = _mock_session()
        result = dispatch(sess, "make_token alice")
        assert result.ok is False

    def test_handler_exception_returns_err(self):
        """If a registered handler raises, dispatch returns ok=False."""
        from megaploit.server import commands as _cmds
        orig = _cmds._registry.get("help")
        bad_def = _CommandDef(
            name="help", usage="", help_text="", dangerous=False,
            handler=lambda s, a: (_ for _ in ()).throw(RuntimeError("boom")),
        )
        _cmds._registry["help"] = bad_def
        try:
            result = dispatch(_mock_session(), "help")
            assert result.ok is False
            assert "boom" in result.output
        finally:
            _cmds._registry["help"] = orig

    def test_result_is_command_result(self):
        sess = _mock_session()
        result = dispatch(sess, "help")
        assert isinstance(result, CommandResult)

    def test_close_session_false_by_default(self):
        sess = _mock_session()
        result = dispatch(sess, "help")
        assert result.close_session is False


# ---------------------------------------------------------------------------
# dispatch() — commands requiring socket I/O
# ---------------------------------------------------------------------------

class TestDispatchWithSocket:
    def test_sysinfo_round_trip(self):
        sysinfo_response = "[*] OS: Linux  Hostname: box  User: root"
        session, _, t = _make_session_with_agent([sysinfo_response])
        result = dispatch(session, "sysinfo")
        t.join(timeout=2)
        assert result.ok is True
        assert sysinfo_response in result.output

    def test_shell_fallback_round_trip(self):
        """Unrecognised command → forwarded to agent → response returned."""
        session, _, t = _make_session_with_agent(["uid=0(root)"])
        result = dispatch(session, "id")
        t.join(timeout=2)
        assert result.ok is True
        assert "uid=0(root)" in result.output

    def test_shell_fallback_with_args(self):
        """Unrecognised multi-word command is sent verbatim."""
        session, _, t = _make_session_with_agent(["drwxr-xr-x  /tmp"])
        result = dispatch(session, "ls -la /tmp")
        t.join(timeout=2)
        assert result.ok is True
        assert "drwxr-xr-x" in result.output

    def test_exit_sets_close_session(self):
        """exit command must return close_session=True."""
        session, _, t = _make_session_with_agent(["exit"])
        # The exit handler sends "exit" to the agent — agent echoes "exit"
        result = dispatch(session, "exit")
        t.join(timeout=2)
        assert result.close_session is True

    def test_connection_lost_returns_err(self):
        """If agent closes unexpectedly, dispatch returns ok=False."""
        agent_conn, client_conn = _socket_pair()
        # Close the agent side immediately — any recv will hit EOF
        agent_conn.close()

        from megaploit.core.protocol import get_state
        get_state(client_conn)
        session = Session(conn=client_conn, ip="10.0.0.2", port=9999, id=2)

        result = dispatch(session, "sysinfo")
        assert result.ok is False
        client_conn.close()

    def test_shell_fallback_connection_lost(self):
        """Shell fallback with dead agent → ok=False, close_session=True."""
        agent_conn, client_conn = _socket_pair()
        agent_conn.close()

        from megaploit.core.protocol import get_state
        get_state(client_conn)
        session = Session(conn=client_conn, ip="10.0.0.3", port=9999, id=3)

        result = dispatch(session, "whoami")
        assert result.ok is False
        assert result.close_session is True
        client_conn.close()

    def test_cd_with_arg_sends_to_agent(self):
        """cd <dir> dispatches 'cd /tmp' to the agent."""
        session, _, t = _make_session_with_agent(["[+] cwd: /tmp"])
        result = dispatch(session, "cd /tmp")
        t.join(timeout=2)
        assert result.ok is True
        assert "/tmp" in result.output

    def test_ps_round_trip(self):
        # Fresh session — avoids replay-detection collision with earlier tests
        session2, _, t = _make_session_with_agent(["PID  NAME"])
        result = dispatch(session2, "ps")
        t.join(timeout=2)
        assert result.ok is True

    def test_netstat_round_trip(self):
        session2, _, t = _make_session_with_agent(["ESTABLISHED 10.0.0.1:443"])
        result = dispatch(session2, "netstat")
        t.join(timeout=2)
        assert result.ok is True

    def test_getclip_round_trip(self):
        session, _, t = _make_session_with_agent(["clipboard contents here"])
        result = dispatch(session, "getclip")
        t.join(timeout=2)
        assert result.ok is True
        assert "clipboard contents here" in result.output

    def test_dispatch_case_insensitive_name(self):
        """Command name matching is case-insensitive."""
        session2, _, t = _make_session_with_agent(["some output"])
        result = dispatch(session2, "SYSINFO")
        t.join(timeout=2)
        assert result.ok is True


# ---------------------------------------------------------------------------
# dispatch() — operator-local commands (note / tag / loot_list)
# ---------------------------------------------------------------------------

class TestDispatchLocalOperatorCommands:
    def test_note_requires_arg(self):
        sess = _mock_session()
        result = dispatch(sess, "note")
        assert result.ok is False
        assert "Usage" in result.output

    def test_note_writes_file(self, tmp_path):
        session, _, t = _make_session_with_agent([])
        # Override loot_dir to use tmp_path
        session.loot_dir = lambda: str(tmp_path)
        result = dispatch(session, "note this is a test note")
        t.join(timeout=1)
        assert result.ok is True
        notes_file = tmp_path / "notes.txt"
        assert notes_file.exists()
        assert "this is a test note" in notes_file.read_text()

    def test_notes_no_file_returns_ok(self, tmp_path):
        session, _, t = _make_session_with_agent([])
        session.loot_dir = lambda: str(tmp_path)
        result = dispatch(session, "notes")
        t.join(timeout=1)
        assert result.ok is True
        assert "No notes" in result.output

    def test_tag_requires_arg(self):
        sess = _mock_session()
        result = dispatch(sess, "tag")
        assert result.ok is False

    def test_tag_sets_session_attribute(self, tmp_path):
        session, _, t = _make_session_with_agent([])
        session.loot_dir = lambda: str(tmp_path)
        dispatch(session, "tag dc-server")
        t.join(timeout=1)
        assert session.tag == "dc-server"

    def test_loot_list_empty_dir(self, tmp_path):
        session, _, t = _make_session_with_agent([])
        session.loot_dir = lambda: str(tmp_path)
        result = dispatch(session, "loot_list")
        t.join(timeout=1)
        assert result.ok is True

    def test_loot_list_with_files(self, tmp_path):
        (tmp_path / "screenshot.png").write_bytes(b"\x89PNG" + b"\x00" * 100)
        session, _, t = _make_session_with_agent([])
        session.loot_dir = lambda: str(tmp_path)
        result = dispatch(session, "loot_list")
        t.join(timeout=1)
        assert result.ok is True
        assert "screenshot.png" in result.output
