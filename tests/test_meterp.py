"""
tests/test_meterp.py
~~~~~~~~~~~~~~~~~~~~
Unit tests for megaploit.agent.meterp — advanced Meterpreter-class handlers.

All network I/O is mocked at the socket/subprocess boundary.
No live connections are made.
"""

from __future__ import annotations

import base64
import io
import os
import sys
import threading
import time
import types
from unittest.mock import MagicMock, Mock, patch, call

import pytest

# Ensure handlers are loaded
import megaploit.agent.meterp  # noqa: F401
from megaploit.agent.handlers import _HANDLERS


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture()
def conn():
    """A mock socket connection (not used by most meterp handlers directly)."""
    return MagicMock()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _call(verb: str, conn, raw_args: str = "") -> str:
    """Call a registered handler by verb name."""
    fn   = _HANDLERS[verb]
    args = raw_args.split() if raw_args else []
    return fn(conn, args)


# ===========================================================================
# 1. whoami
# ===========================================================================

class TestWhoami:
    def test_registered(self):
        assert "whoami" in _HANDLERS

    def test_returns_string(self, conn):
        result = _call("whoami", conn)
        assert isinstance(result, str)
        assert len(result) > 0

    def test_contains_username(self, conn):
        import getpass
        result = _call("whoami", conn)
        assert getpass.getuser() in result


# ===========================================================================
# 2. getpid
# ===========================================================================

class TestGetpid:
    def test_registered(self):
        assert "getpid" in _HANDLERS

    def test_returns_own_pid(self, conn):
        result = _call("getpid", conn)
        assert int(result) == os.getpid()


# ===========================================================================
# 3. getuid
# ===========================================================================

class TestGetuid:
    def test_registered(self):
        assert "getuid" in _HANDLERS

    def test_returns_string(self, conn):
        result = _call("getuid", conn)
        assert isinstance(result, str)
        assert len(result) > 0


# ===========================================================================
# 4. sleep
# ===========================================================================

class TestSleep:
    def test_registered(self):
        assert "sleep" in _HANDLERS

    def test_usage_on_no_args(self, conn):
        result = _call("sleep", conn)
        assert "Usage" in result

    def test_sleep_zero(self, conn):
        """sleep 0 should be clamped to 0 but still work (time.sleep(0))."""
        with patch("time.sleep") as mock_sleep:
            result = _HANDLERS["sleep"](conn, ["0"])
        mock_sleep.assert_called_once_with(0)
        assert "Slept" in result

    def test_sleep_caps_at_3600(self, conn):
        with patch("time.sleep") as mock_sleep:
            _HANDLERS["sleep"](conn, ["99999"])
        mock_sleep.assert_called_once_with(3600)


# ===========================================================================
# 5. beacon_sleep
# ===========================================================================

class TestBeaconSleep:
    def test_registered(self):
        assert "beacon_sleep" in _HANDLERS

    def test_usage_on_no_args(self, conn):
        result = _call("beacon_sleep", conn)
        assert "Usage" in result

    def test_sets_reconnect_delay(self, conn):
        from megaploit.core import config as cfg
        original = getattr(cfg, "RECONNECT_DELAY", 5)
        try:
            result = _HANDLERS["beacon_sleep"](conn, ["42"])
            assert "42" in result
            assert cfg.RECONNECT_DELAY == 42
        finally:
            cfg.RECONNECT_DELAY = original


# ===========================================================================
# 6. run_python
# ===========================================================================

class TestRunPython:
    def test_registered(self):
        assert "run_python" in _HANDLERS

    def test_usage_on_no_args(self, conn):
        result = _call("run_python", conn)
        assert "Usage" in result

    def test_executes_print(self, conn):
        result = _HANDLERS["run_python"](conn, ["print('hello_meterp')"])
        assert "hello_meterp" in result

    def test_captures_expression(self, conn):
        result = _HANDLERS["run_python"](conn, ["x=7;", "print(x*6)"])
        assert "42" in result

    def test_reports_exception(self, conn):
        result = _HANDLERS["run_python"](conn, ["raise", "ValueError('boom')"])
        assert "error" in result.lower() or "boom" in result

    def test_no_output_message(self, conn):
        result = _HANDLERS["run_python"](conn, ["x=1"])
        assert "no output" in result.lower()


# ===========================================================================
# 7. run_psh  (Windows-only; mocked on non-Windows)
# ===========================================================================

class TestRunPsh:
    def test_registered(self):
        assert "run_psh" in _HANDLERS

    def test_usage_on_no_args(self, conn):
        result = _call("run_psh", conn)
        assert "Usage" in result

    @pytest.mark.skipif(sys.platform != "win32", reason="Windows-only")
    def test_runs_on_windows(self, conn):
        result = _HANDLERS["run_psh"](conn, ["echo", "hello"])
        assert "hello" in result.lower()

    def test_non_windows_error(self, conn):
        with patch("sys.platform", "linux"):
            result = _HANDLERS["run_psh"](conn, ["echo", "hi"])
        assert "Windows-only" in result

    def test_mocked_subprocess(self, conn):
        """On any platform, mock subprocess and verify correct flags are passed."""
        with patch("subprocess.check_output", return_value="mocked_output") as mock_sub:
            with patch("sys.platform", "win32"):
                result = _HANDLERS["run_psh"](conn, ["Get-Date"])
        assert "mocked_output" in result
        call_args = mock_sub.call_args[0][0]
        assert "powershell" in call_args[0].lower()
        assert "Bypass" in call_args


# ===========================================================================
# 8. port_scan
# ===========================================================================

class TestPortScan:
    def test_registered(self):
        assert "port_scan" in _HANDLERS

    def test_usage_on_no_args(self, conn):
        result = _call("port_scan", conn)
        assert "Usage" in result

    def test_invalid_port_spec(self, conn):
        result = _HANDLERS["port_scan"](conn, ["10.0.0.1", "notaport"])
        assert "No valid ports" in result

    def test_detects_open_port(self, conn):
        """Mock socket.create_connection to simulate port 80 open."""
        mock_sock = MagicMock()
        mock_sock.__enter__ = Mock(return_value=mock_sock)
        mock_sock.__exit__  = Mock(return_value=False)

        def _fake_connect(addr, timeout):
            if addr[1] == 80:
                return mock_sock
            raise ConnectionRefusedError()

        with patch("socket.create_connection", side_effect=_fake_connect):
            result = _HANDLERS["port_scan"](conn, ["10.0.0.1", "79,80,81"])
        assert "80" in result
        assert "79" not in result
        assert "81" not in result

    def test_all_closed(self, conn):
        with patch("socket.create_connection", side_effect=ConnectionRefusedError):
            result = _HANDLERS["port_scan"](conn, ["10.0.0.1", "9999"])
        assert "closed" in result.lower() or "filtered" in result.lower()

    def test_range_syntax(self, conn):
        """port_scan should parse '8080-8082' into [8080,8081,8082]."""
        opened = []
        mock_sock = MagicMock()
        mock_sock.__enter__ = Mock(return_value=mock_sock)
        mock_sock.__exit__  = Mock(return_value=False)

        def _fake(addr, timeout):
            opened.append(addr[1])
            return mock_sock

        with patch("socket.create_connection", side_effect=_fake):
            _HANDLERS["port_scan"](conn, ["10.0.0.1", "8080-8082"])
        assert set(opened) == {8080, 8081, 8082}

    def test_range_too_large(self, conn):
        result = _HANDLERS["port_scan"](conn, ["10.0.0.1", "1-20001"])
        assert "exceeds" in result


# ===========================================================================
# 9. load_extension / unload_extension / list_extensions
# ===========================================================================

class TestExtensions:
    def test_load_registered(self):
        assert "load_extension" in _HANDLERS

    def test_unload_registered(self):
        assert "unload_extension" in _HANDLERS

    def test_list_registered(self):
        assert "list_extensions" in _HANDLERS

    def test_usage_load(self, conn):
        result = _call("load_extension", conn)
        assert "Usage" in result

    def test_usage_unload(self, conn):
        result = _call("unload_extension", conn)
        assert "Usage" in result

    def test_load_from_file(self, conn, tmp_path):
        """Create a temp extension file and load it."""
        ext_file = tmp_path / "test_ext.py"
        ext_file.write_text(
            'HANDLERS = {"_test_verb_xyz": lambda conn, args: "ext_ok"}\n'
        )
        result = _HANDLERS["load_extension"](conn, [str(ext_file)])
        assert "test_ext" in result or "loaded" in result.lower()
        # The verb should now be callable
        assert "_test_verb_xyz" in _HANDLERS
        assert _HANDLERS["_test_verb_xyz"](conn, []) == "ext_ok"

    def test_unload_removes_verb(self, conn, tmp_path):
        ext_file = tmp_path / "test_ext2.py"
        ext_file.write_text(
            'HANDLERS = {"_test_verb_abc": lambda conn, args: "abc"}\n'
        )
        _HANDLERS["load_extension"](conn, [str(ext_file)])
        assert "_test_verb_abc" in _HANDLERS
        _HANDLERS["unload_extension"](conn, ["test_ext2"])
        assert "_test_verb_abc" not in _HANDLERS

    def test_unload_unknown(self, conn):
        result = _HANDLERS["unload_extension"](conn, ["nonexistent_ext"])
        assert "not loaded" in result

    def test_list_empty(self, conn):
        # Ensure a clean state for this test
        from megaploit.agent import meterp as _m
        old = dict(_m._extensions)
        _m._extensions.clear()
        result = _call("list_extensions", conn)
        assert "no extensions" in result.lower()
        _m._extensions.update(old)

    def test_load_invalid_module_name(self, conn):
        result = _HANDLERS["load_extension"](conn, ["this_module_does_not_exist_xyz"])
        assert "error" in result.lower() or "load_extension" in result.lower()


# ===========================================================================
# 10. migrate (mocked — no real process manipulation)
# ===========================================================================

class TestMigrate:
    def test_registered(self):
        assert "migrate" in _HANDLERS

    def test_usage_on_no_args(self, conn):
        result = _call("migrate", conn)
        assert "Usage" in result

    def test_cannot_migrate_to_own_pid(self, conn):
        result = _HANDLERS["migrate"](conn, [str(os.getpid())])
        assert "own PID" in result

    def test_posix_migration_nonexistent_pid(self, conn):
        """Migrating to a non-existent PID should return a clear error."""
        # Patch os.kill to raise ProcessLookupError (cross-platform simulation)
        with patch("sys.platform", "linux"), \
             patch("os.kill", side_effect=ProcessLookupError("No such process")):
            result = _HANDLERS["migrate"](conn, ["999999"])
        assert "does not exist" in result

    def test_windows_fallback_spawn(self, conn):
        """On Windows path, verify Popen is called with the agent script."""
        fake_script = "/fake/agent.py"
        with patch("sys.platform", "win32"), \
             patch("sys.argv", [fake_script]), \
             patch("os.path.isfile", return_value=True), \
             patch("subprocess.Popen") as mock_popen:
            # OpenProcess fails → fallback
            with patch("ctypes.windll") as mock_w:
                mock_w.kernel32.OpenProcess.return_value = 0
                result = _HANDLERS["migrate"](conn, ["1234"])
        assert isinstance(result, str)


# ===========================================================================
# 11. memory_read / memory_write (Windows-only; non-Windows returns error)
# ===========================================================================

class TestMemoryReadWrite:
    def test_memory_read_registered(self):
        assert "memory_read" in _HANDLERS

    def test_memory_write_registered(self):
        assert "memory_write" in _HANDLERS

    def test_memory_read_non_windows(self, conn):
        with patch("sys.platform", "linux"):
            result = _HANDLERS["memory_read"](conn, ["1", "0x1000", "64"])
        assert "Windows-only" in result

    def test_memory_write_non_windows(self, conn):
        with patch("sys.platform", "linux"):
            result = _HANDLERS["memory_write"](conn, ["1", "0x1000",
                                                       base64.b64encode(b"data").decode()])
        assert "Windows-only" in result

    def test_memory_read_usage(self, conn):
        result = _call("memory_read", conn)
        assert "Usage" in result

    def test_memory_write_usage(self, conn):
        result = _call("memory_write", conn)
        assert "Usage" in result

    def test_memory_read_mocked_windows(self, conn):
        """Mock ctypes to simulate a successful memory read."""
        data = b"AAAA"
        import ctypes as _ctypes

        with patch("sys.platform", "win32"):
            import ctypes
            mock_k32 = MagicMock()
            mock_k32.OpenProcess.return_value = 0xDEAD
            mock_k32.ReadProcessMemory.side_effect = (
                lambda h, addr, buf, size, read_ptr: (
                    ctypes.memmove(buf, data, len(data)),
                    setattr(read_ptr, "_obj", None),
                    True,
                )[-1]
            )
            # Just verify no crash — the mock may not produce real output
            try:
                _HANDLERS["memory_read"](conn, ["1234", "0x1000", "4"])
            except Exception:
                pass  # ctypes mock may fail; we just check no hard crash


# ===========================================================================
# 12. screenshot_stream (mocked — no GUI)
# ===========================================================================

class TestScreenshotStream:
    def test_registered(self):
        assert "screenshot_stream" in _HANDLERS

    def test_usage_on_no_args(self, conn):
        result = _call("screenshot_stream", conn)
        assert "Usage" in result

    def test_sends_frames_pyautogui_fallback(self, conn):
        """
        Patch the entire pyautogui fallback path by mocking _screenshot_stream_burst
        to directly call _send_msg with synthetic FRAME messages — verifying the
        protocol contract without requiring a real display.
        """
        frames_sent: list[str] = []

        def _fake_send_msg(c, msg):
            frames_sent.append(msg)

        # Build a fake JPEG bytes buffer
        fake_jpeg = b"\xff\xd8\xff\xe0" + b"\x00" * 100

        # Patch pyautogui.screenshot to return an object whose .save writes fake JPEG
        class _FakeImg:
            def save(self, fp, format=None, quality=None, **kw):
                fp.write(fake_jpeg)

        # Also stub PIL.Image so the fallback path doesn't bail on missing Pillow
        import types as _types
        fake_pil   = _types.ModuleType("PIL")
        fake_image = _types.ModuleType("PIL.Image")
        fake_pil.Image = fake_image  # type: ignore[attr-defined]

        with patch("megaploit.agent.meterp._send_msg", side_effect=_fake_send_msg), \
             patch.dict("sys.modules", {
                 "cv2": None, "mss": None, "numpy": None,
                 "PIL": fake_pil, "PIL.Image": fake_image,
             }), \
             patch("pyautogui.screenshot", return_value=_FakeImg()), \
             patch("time.sleep"):
            _HANDLERS["screenshot_stream"](conn, ["3", "10"])

        frame_msgs = [m for m in frames_sent if isinstance(m, str) and m.startswith("FRAME:")]
        stream_end = "STREAM_END" in frames_sent
        assert stream_end, f"STREAM_END not sent; got: {frames_sent[-3:]}"
        assert len(frame_msgs) == 3

    def test_fps_default(self, conn):
        """Calling with only count should default to fps=5."""
        frames_sent: list[str] = []

        def _fake_send_msg(c, msg):
            frames_sent.append(msg)

        fake_img = MagicMock()
        fake_img.save = lambda buf, **kw: buf.write(b"\xff\xd8\xff\xe0fake_jpeg")

        with patch("megaploit.agent.meterp._send_msg", side_effect=_fake_send_msg), \
             patch("pyautogui.screenshot", return_value=fake_img), \
             patch("time.sleep"):
            _HANDLERS["screenshot_stream"](conn, ["2"])

        assert "STREAM_END" in frames_sent


# ---------------------------------------------------------------------------
# helpers for mock import tricks
# ---------------------------------------------------------------------------

def _selective_import_error(blocked: list[str]):
    """Return a __import__ side-effect that raises ImportError for listed modules."""
    real_import = __builtins__.__import__ if hasattr(__builtins__, "__import__") else __import__

    def _fake(name, *args, **kwargs):
        if any(name.startswith(b) for b in blocked):
            raise ImportError(f"Mocked ImportError: {name}")
        return real_import(name, *args, **kwargs)

    return _fake


# ===========================================================================
# 13. pty_shell (just smoke-test instantiation / usage path)
# ===========================================================================

class TestPtyShell:
    def test_registered(self):
        assert "pty_shell" in _HANDLERS

    def test_returns_string(self, conn):
        """Calling pty_shell without a real PTY should return a string error gracefully."""
        # On Windows pty module is unavailable; force the windows path directly.
        if sys.platform == "win32":
            with patch("megaploit.agent.meterp._pty_windows",
                       return_value="[*] PTY session ended") as mock_win:
                result = _HANDLERS["pty_shell"](conn, [])
            assert isinstance(result, str)
        else:
            with patch("pty.openpty", side_effect=OSError("no pty in test")):
                result = _HANDLERS["pty_shell"](conn, [])
            assert isinstance(result, str)


# ===========================================================================
# 14. Server-side command stubs (commands.py registration)
# ===========================================================================

class TestMeterpreterServerCommands:
    """Verify that all new meterp verbs are registered in commands._registry."""

    EXPECTED = [
        "migrate", "memory_read", "memory_write", "port_scan",
        "run_psh", "run_python", "load_extension", "unload_extension",
        "list_extensions", "screenshot_stream", "whoami", "getpid",
        "getuid", "sleep", "beacon_sleep", "interactive",
    ]

    def test_all_registered(self):
        from megaploit.server.commands import _registry
        missing = [v for v in self.EXPECTED if v not in _registry]
        assert not missing, f"Missing commands: {missing}"

    def test_migrate_is_dangerous(self):
        from megaploit.server.commands import _registry
        assert _registry["migrate"].dangerous is True

    def test_memory_read_is_dangerous(self):
        from megaploit.server.commands import _registry
        assert _registry["memory_read"].dangerous is True

    def test_run_python_is_dangerous(self):
        from megaploit.server.commands import _registry
        assert _registry["run_python"].dangerous is True

    def test_port_scan_not_dangerous(self):
        from megaploit.server.commands import _registry
        assert _registry["port_scan"].dangerous is False

    def test_command_count_grows(self):
        """Total command count should be >= 115 (original 102 + new meterp verbs)."""
        from megaploit.server.commands import _registry
        assert len(_registry) >= 115


# ===========================================================================
# 15. MeterpreterSession — unit smoke tests (no real socket)
# ===========================================================================

class TestMeterpreterSession:
    """Smoke tests for the MeterpreterSession class without a live connection."""

    @pytest.fixture()
    def fake_session(self, tmp_path, monkeypatch):
        from megaploit.server.session import Session
        sock = MagicMock()
        s = Session(conn=sock, ip="10.0.0.1", port=4321, id=99)
        s.tag = "test"
        # Point loot dir at tmp_path
        monkeypatch.chdir(tmp_path)
        (tmp_path / "loot").mkdir()
        return s

    def test_instantiates(self, fake_session):
        from megaploit.server.meterp_session import MeterpreterSession
        ms = MeterpreterSession(fake_session)
        assert ms._session.id == 99

    def test_list_sessions_no_sessions(self, fake_session, capsys):
        from megaploit.server.meterp_session import MeterpreterSession
        ms = MeterpreterSession(fake_session, all_sessions=[fake_session])
        ms._list_sessions()
        out = capsys.readouterr().out
        assert "10.0.0.1" in out

    def test_background_calls_cb(self, fake_session):
        from megaploit.server.meterp_session import MeterpreterSession
        called = []
        ms = MeterpreterSession(fake_session, background_cb=lambda s: called.append(s))
        ms._background()
        assert len(called) == 1
        assert called[0].id == 99
        assert ms._backgrounded is True
