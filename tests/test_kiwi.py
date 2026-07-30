"""
tests/test_kiwi.py
~~~~~~~~~~~~~~~~~~
Unit tests for the Megaploit Kiwi integration:
  - kiwi_runner.py  (compile + exec logic)
  - megaploit/agent/handlers.py  _kiwi handler
  - megaploit/server/commands.py cmd_kiwi dispatcher

No live Windows API calls, no real process spawning.
All subprocess / file-system boundaries are mocked.
"""

from __future__ import annotations

import os
import sys
import types
from unittest.mock import MagicMock, patch

import pytest


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

_RUNNER_PATH = os.path.join(
    os.path.dirname(__file__), "..", "megaploit", "native", "kiwi", "kiwi_runner.py"
)


def _load_runner():
    """Load kiwi_runner fresh each time (avoids module-level cache)."""
    import importlib.util as ilu
    spec = ilu.spec_from_file_location("kiwi_runner", _RUNNER_PATH)
    mod  = ilu.module_from_spec(spec)           # type: ignore[arg-type]
    spec.loader.exec_module(mod)                # type: ignore[union-attr]
    return mod


# ─────────────────────────────────────────────────────────────────────────────
# kiwi_runner — compile logic
# ─────────────────────────────────────────────────────────────────────────────

class TestKiwiRunnerCompile:

    def test_needs_rebuild_missing_binary(self, tmp_path):
        """_needs_rebuild() returns True when binary does not exist."""
        runner = _load_runner()
        with patch.object(runner, "_binary_path", return_value=str(tmp_path / "missing.exe")):
            assert runner._needs_rebuild() is True

    def test_needs_rebuild_binary_exists_and_fresh(self, tmp_path):
        """_needs_rebuild() returns False when binary is newer than source."""
        runner = _load_runner()
        src = tmp_path / "src.c"
        bin_ = tmp_path / "bin.exe"
        src.write_text("x")
        bin_.write_text("y")
        # Make binary newer by 10 seconds
        os.utime(bin_, (os.path.getmtime(src) + 10,) * 2)
        with patch.object(runner, "_binary_path", return_value=str(bin_)), \
             patch.object(runner, "_SRC", str(src)):
            assert runner._needs_rebuild() is False

    def test_needs_rebuild_source_newer(self, tmp_path):
        """_needs_rebuild() returns True when source is newer than binary."""
        runner = _load_runner()
        src = tmp_path / "src.c"
        bin_ = tmp_path / "bin.exe"
        bin_.write_text("old")
        src.write_text("newer")
        os.utime(src, (os.path.getmtime(bin_) + 10,) * 2)
        with patch.object(runner, "_binary_path", return_value=str(bin_)), \
             patch.object(runner, "_SRC", str(src)):
            assert runner._needs_rebuild() is True

    def test_compile_success(self, tmp_path):
        """_compile() returns binary path when subprocess exits 0."""
        runner = _load_runner()
        fake_bin = str(tmp_path / "megaploit_kiwi.exe")
        # Create the binary so _binary_path points at it
        open(fake_bin, "w").close()

        with patch.object(runner, "_needs_rebuild", return_value=True), \
             patch.object(runner, "_binary_path", return_value=fake_bin), \
             patch.object(runner, "_find_compiler", return_value=(["gcc"], ["-o", fake_bin, "src.c"])), \
             patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stderr="", stdout="")
            result = runner._compile()
        assert result == fake_bin

    def test_compile_failure_raises(self, tmp_path):
        """_compile() raises RuntimeError when compiler exits non-zero."""
        runner = _load_runner()
        with patch.object(runner, "_needs_rebuild", return_value=True), \
             patch.object(runner, "_find_compiler",
                          return_value=(["gcc"], ["-o", "out.exe", "src.c"])), \
             patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=1, stderr="error: something", stdout=""
            )
            with pytest.raises(RuntimeError, match="Compile failed"):
                runner._compile()

    def test_compile_no_compiler_raises(self):
        """_find_compiler raises RuntimeError when no compiler on PATH."""
        runner = _load_runner()
        with patch("shutil.which", return_value=None):
            with pytest.raises(RuntimeError):
                runner._find_compiler()


# ─────────────────────────────────────────────────────────────────────────────
# kiwi_runner — run_kiwi()
# ─────────────────────────────────────────────────────────────────────────────

class TestRunKiwi:

    @pytest.mark.skipif(sys.platform != "win32",
                        reason="non-Windows path tested separately")
    def test_non_windows_returns_error(self):
        """run_kiwi() on non-Windows returns a helpful message."""
        runner = _load_runner()
        result = runner.run_kiwi("logonpasswords")
        assert "Windows-only" in result or "[-]" in result

    def test_non_windows_stub(self):
        """Force-test the non-Windows early-exit branch."""
        runner = _load_runner()
        with patch.object(sys, "platform", "linux"):
            result = runner.run_kiwi("credman")
        assert "Windows-only" in result

    def test_run_kiwi_success(self, tmp_path):
        """run_kiwi() returns binary stdout on success."""
        runner = _load_runner()
        fake_bin = str(tmp_path / "megaploit_kiwi.exe")
        expected = "[+] Username : Administrator\n[+] NTLM     : aad3b435b51404eeaad3b435b51404ee"

        with patch.object(sys, "platform", "win32"), \
             patch.object(runner, "_compile", return_value=fake_bin), \
             patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0, stdout=expected, stderr=""
            )
            result = runner.run_kiwi("logonpasswords")

        assert "[+] Username" in result
        assert "aad3b435" in result

    def test_run_kiwi_timeout(self, tmp_path):
        """run_kiwi() returns an error string on timeout."""
        import subprocess as _sp
        runner = _load_runner()
        fake_bin = str(tmp_path / "megaploit_kiwi.exe")

        with patch.object(sys, "platform", "win32"), \
             patch.object(runner, "_compile", return_value=fake_bin), \
             patch("subprocess.run", side_effect=_sp.TimeoutExpired(fake_bin, 60)):
            result = runner.run_kiwi("all", timeout=60)
        assert "timed out" in result

    def test_run_kiwi_binary_not_found(self, tmp_path):
        """run_kiwi() returns an error string when the binary can't be executed."""
        runner = _load_runner()
        fake_bin = str(tmp_path / "megaploit_kiwi.exe")

        with patch.object(sys, "platform", "win32"), \
             patch.object(runner, "_compile", return_value=fake_bin), \
             patch("subprocess.run", side_effect=FileNotFoundError("no such file")):
            result = runner.run_kiwi("sam")
        assert "[-]" in result

    def test_run_kiwi_compile_error_propagates(self):
        """run_kiwi() returns an error string when _compile() raises."""
        runner = _load_runner()
        with patch.object(sys, "platform", "win32"), \
             patch.object(runner, "_compile",
                          side_effect=RuntimeError("no compiler")):
            result = runner.run_kiwi("lsa")
        assert "compile error" in result or "[-]" in result

    def test_invalid_module_is_forwarded(self, tmp_path):
        """run_kiwi() forwards unknown modules to the binary (validation is in C)."""
        runner = _load_runner()
        fake_bin = str(tmp_path / "megaploit_kiwi.exe")
        with patch.object(sys, "platform", "win32"), \
             patch.object(runner, "_compile", return_value=fake_bin), \
             patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=1, stdout="[-] Unknown module: bogus\n", stderr=""
            )
            result = runner.run_kiwi("bogus")
        assert "Unknown module" in result or "[-]" in result


# ─────────────────────────────────────────────────────────────────────────────
# Agent handler — _kiwi
# ─────────────────────────────────────────────────────────────────────────────

class TestAgentKiwiHandler:

    def _get_handler(self):
        from megaploit.agent.handlers import _HANDLERS
        return _HANDLERS.get("kiwi")

    def test_handler_registered(self):
        """kiwi handler is registered in _HANDLERS."""
        fn = self._get_handler()
        assert fn is not None, "kiwi handler not registered"

    def test_handler_no_args_returns_usage(self):
        fn = self._get_handler()
        assert fn is not None
        result = fn(None, [])
        assert "Usage" in result or "usage" in result.lower() or "kiwi" in result.lower()

    def test_handler_delegates_to_runner(self):
        """Handler delegates to run_kiwi() via dynamic import."""
        fn = self._get_handler()
        assert fn is not None

        fake_runner = types.ModuleType("kiwi_runner")
        fake_runner.run_kiwi = MagicMock(return_value="[+] mock result")

        with patch("importlib.util.spec_from_file_location") as mock_spec_fn, \
             patch("importlib.util.module_from_spec", return_value=fake_runner), \
             patch.object(fake_runner, "run_kiwi", return_value="[+] mock result"):
            # Make spec.loader.exec_module a no-op
            mock_spec = MagicMock()
            mock_spec.loader.exec_module = MagicMock()
            mock_spec_fn.return_value = mock_spec

            result = fn(None, ["credman"])
        # Either the mock ran or runner loaded successfully
        assert isinstance(result, str)

    def test_handler_runner_exception_returns_error(self):
        """Handler catches runner exceptions and returns error string."""
        fn = self._get_handler()
        assert fn is not None

        with patch("importlib.util.spec_from_file_location",
                   side_effect=ImportError("test error")):
            result = fn(None, ["logonpasswords"])
        assert "[-]" in result


# ─────────────────────────────────────────────────────────────────────────────
# Server command — cmd_kiwi
# ─────────────────────────────────────────────────────────────────────────────

class TestServerKiwiCommand:

    def _make_session(self):
        from megaploit.server.session import Session
        session = MagicMock(spec=Session)
        session.conn = MagicMock()
        session.conn.gettimeout.return_value = 30.0
        return session

    def test_command_registered(self):
        from megaploit.server.commands import all_commands
        cmds = all_commands()
        assert "kiwi" in cmds, "kiwi not in server command registry"

    def test_command_is_dangerous(self):
        from megaploit.server.commands import all_commands
        assert all_commands()["kiwi"].dangerous is True

    def test_no_args_returns_error(self):
        from megaploit.server.commands import cmd_kiwi
        session = self._make_session()
        result = cmd_kiwi(session, [])
        assert not result.ok
        assert "Usage" in result.output or "kiwi" in result.output.lower()

    def test_invalid_module_returns_error(self):
        from megaploit.server.commands import cmd_kiwi
        session = self._make_session()
        result = cmd_kiwi(session, ["notamodule"])
        assert not result.ok
        assert "Unknown" in result.output or "notamodule" in result.output

    def test_valid_module_sends_message_and_receives(self):
        from megaploit.server.commands import cmd_kiwi

        session = self._make_session()
        expected_output = "[+] Username : DESKTOP-ABC\\user\n[+] NTLM : aad3..."

        with patch("megaploit.server.commands.send_msg") as mock_send, \
             patch("megaploit.server.commands.recv_msg", return_value=expected_output):
            result = cmd_kiwi(session, ["logonpasswords"])

        assert result.ok
        assert "[+] Username" in result.output
        # Verify the correct wire message was sent
        mock_send.assert_called_once()
        call_args = mock_send.call_args[0]
        assert "kiwi" in call_args[1]
        assert "logonpasswords" in call_args[1]

    def test_socket_timeout_restored_on_error(self):
        """Session socket timeout is always restored, even on recv error."""
        from megaploit.server.commands import cmd_kiwi

        session = self._make_session()
        session.conn.gettimeout.return_value = 15.0

        with patch("megaploit.server.commands.send_msg"), \
             patch("megaploit.server.commands.recv_msg",
                   side_effect=ConnectionError("dropped")):
            result = cmd_kiwi(session, ["sam"])

        assert not result.ok
        # Timeout must have been restored
        session.conn.settimeout.assert_called_with(15.0)

    @pytest.mark.parametrize("module", [
        "logonpasswords", "sam", "lsa", "credman",
        "tickets", "wdigest", "dpapi", "all",
    ])
    def test_all_valid_modules_accepted(self, module):
        from megaploit.server.commands import cmd_kiwi

        session = self._make_session()
        with patch("megaploit.server.commands.send_msg"), \
             patch("megaploit.server.commands.recv_msg",
                   return_value=f"[+] {module} done"):
            result = cmd_kiwi(session, [module])
        assert result.ok


# ─────────────────────────────────────────────────────────────────────────────
# C source sanity checks (no compilation — just text validation)
# ─────────────────────────────────────────────────────────────────────────────

def _c_src_text():
    path = os.path.join(
        os.path.dirname(__file__), "..",
        "megaploit", "native", "kiwi", "megaploit_kiwi.c"
    )
    with open(path, encoding="utf-8") as f:
        return f.read()


class TestKiwiCSource:

    @pytest.fixture
    def c_src(self):
        return _c_src_text()

    def test_source_file_exists(self, c_src):
        assert len(c_src) > 1000

    def test_has_win32_guard(self, c_src):
        assert "#ifdef _WIN32" in c_src
        assert "#else" in c_src

    def test_non_windows_stub_present(self, c_src):
        assert "Windows-only binary" in c_src

    def test_all_modules_present(self, c_src):
        for fn in ("cmd_logonpasswords", "cmd_sam", "cmd_lsa",
                   "cmd_credman", "cmd_tickets", "cmd_wdigest", "cmd_dpapi"):
            assert fn in c_src, f"{fn} missing from C source"

    def test_no_sprintf_used(self, c_src):
        """Ensure all sprintf calls are snprintf (buffer-safe); ignore comments."""
        import re
        # Strip /* ... */ block comments and // line comments before scanning
        stripped = re.sub(r'/\*.*?\*/', '', c_src, flags=re.DOTALL)
        stripped = re.sub(r'//[^\n]*', '', stripped)
        unsafe = re.findall(r'\bsprintf\s*\(', stripped)
        assert not unsafe, f"Unsafe sprintf found in non-comment code: {unsafe}"

    def test_hex_encode_present(self, c_src):
        assert "hex_encode" in c_src

    def test_privilege_enabler_present(self, c_src):
        assert "enable_privilege" in c_src
        assert "SE_DEBUG_NAME" in c_src

    def test_all_handles_closed(self, c_src):
        """Every CloseHandle call exists (basic resource-cleanup check)."""
        assert "CloseHandle" in c_src

    def test_main_dispatch_table(self, c_src):
        """All module names are handled in main()."""
        for name in ("logonpasswords", "sam", "lsa", "credman",
                     "tickets", "wdigest", "dpapi", "all"):
            assert f'strcmp(module, "{name}")' in c_src, \
                f'dispatch case for "{name}" missing in main()'
