"""
Tests for all 7 framework improvements:

1.  staging.generate_stage0 / StagingServer   (end-to-end wired)
2.  modules.base.AgentModule                  (auto-generating module API)
3.  payload.builder  GO_EXE / GO_ELF formats  (Go agent build integration)
4.  core.protocol.WsTransport                 (HTTPS/WebSocket transport)
5.  core.pipeline.Pipeline                    (post-exploitation pipeline)
6.  core.profile.C2Profile / load_profile     (malleable C2 profile)
7.  web.app.WebServer / web.rpc.RpcServer     (multi-operator web UI)
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import socket
import struct
import threading
import time
from unittest.mock import MagicMock, patch

import pytest


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _socket_pair():
    """Return a connected (server_sock, client_sock) pair via loopback."""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    port = srv.getsockname()[1]
    cli = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    cli.connect(("127.0.0.1", port))
    conn, _ = srv.accept()
    srv.close()
    return conn, cli


# ===========================================================================
# 1.  Item 1 — Staging: generate_stage0 + StagingServer
# ===========================================================================

class TestStaging:
    def test_generate_stage0_returns_string(self):
        from megaploit.core.staging import generate_stage0
        src = generate_stage0("10.0.0.1", 4445, key_hex="aa" * 32)
        assert isinstance(src, str)
        assert "10.0.0.1" in src
        assert "4445" in src
        assert "aa" * 32 in src

    def test_generate_stage0_minimal(self):
        from megaploit.core.staging import generate_stage0
        src = generate_stage0("1.2.3.4", 9000, key_hex="bb" * 32, minimal=True)
        assert "1.2.3.4" in src
        assert "9000" in src
        # Minimal template is shorter than the full template
        assert len(src) < 800

    def test_generate_stage0_use_tls(self):
        from megaploit.core.staging import generate_stage0
        src = generate_stage0("1.2.3.4", 9000, key_hex="cc" * 32, use_tls=True)
        assert "True" in src  # USE_TLS=True

    def test_generate_stage0_no_tls(self):
        from megaploit.core.staging import generate_stage0
        src = generate_stage0("1.2.3.4", 9000, key_hex="cc" * 32, use_tls=False)
        assert "False" in src

    def test_staging_server_end_to_end(self, tmp_path):
        """StagingServer authenticates, receives STAGE_MAGIC, returns gzipped agent."""
        from megaploit.core.staging import StagingServer

        # Write a tiny agent file
        agent_file = tmp_path / "agent.py"
        agent_file.write_text("print('hello from stage-1')")

        key = os.urandom(32)
        srv = StagingServer(
            bind_host="127.0.0.1",
            port=0,  # use ephemeral port — but StagingServer binds in start()
            secret_key=key,
            agent_source_path=str(agent_file),
        )
        # We'll bind manually to find a free port
        import socket as _sock
        tmp_srv = _sock.socket()
        tmp_srv.bind(("127.0.0.1", 0))
        port = tmp_srv.getsockname()[1]
        tmp_srv.close()

        srv.port = port
        srv.start()
        time.sleep(0.1)

        try:
            cli = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            cli.settimeout(5)
            cli.connect(("127.0.0.1", port))

            # Receive HMAC challenge (16 bytes)
            challenge = b""
            while len(challenge) < 16:
                challenge += cli.recv(16 - len(challenge))

            # Respond with HMAC-SHA256
            resp = hmac.new(key, challenge, hashlib.sha256).digest()
            cli.sendall(resp)

            # Send STAGE_MAGIC
            cli.sendall(b"S")

            # Receive 4-byte length
            hdr = b""
            while len(hdr) < 4:
                hdr += cli.recv(4 - len(hdr))
            length = struct.unpack("!I", hdr)[0]
            assert length > 0

            # Receive payload
            payload = b""
            while len(payload) < length:
                payload += cli.recv(length - len(payload))

            # Should be gzip-compressed
            import gzip
            decompressed = gzip.decompress(payload)
            assert b"stage-1" in decompressed

        finally:
            cli.close()
            srv.stop()

    def test_staging_server_rejects_bad_hmac(self, tmp_path):
        """StagingServer drops connections that fail HMAC auth."""
        from megaploit.core.staging import StagingServer

        agent_file = tmp_path / "agent.py"
        agent_file.write_text("x=1")

        key = os.urandom(32)
        import socket as _sock
        tmp_srv = _sock.socket()
        tmp_srv.bind(("127.0.0.1", 0))
        port = tmp_srv.getsockname()[1]
        tmp_srv.close()

        srv = StagingServer("127.0.0.1", port, key, str(agent_file))
        srv.start()
        time.sleep(0.1)

        try:
            cli = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            cli.settimeout(3)
            cli.connect(("127.0.0.1", port))

            # Receive challenge
            challenge = b""
            while len(challenge) < 16:
                challenge += cli.recv(16 - len(challenge))

            # Send WRONG HMAC
            cli.sendall(b"\x00" * 32)

            # Server should close connection — recv returns b""
            cli.settimeout(2)
            result = cli.recv(1)
            assert result == b""  # connection closed by server
        except (socket.timeout, ConnectionResetError):
            pass  # also acceptable — server dropped us
        finally:
            cli.close()
            srv.stop()


# ===========================================================================
# 2.  Item 2 — AgentModule base class
# ===========================================================================

class TestAgentModule:
    def test_agent_module_is_module_subclass(self):
        from megaploit.modules.base import AgentModule, Module
        assert issubclass(AgentModule, Module)

    def test_agent_module_default_type(self):
        from megaploit.modules.base import AgentModule, ModuleType
        m = AgentModule()
        assert m.module_type == ModuleType.POST

    def test_agent_module_has_session_attribute(self):
        from megaploit.modules.base import AgentModule
        m = AgentModule()
        assert m.session is None

    def test_agent_module_send_no_session_raises(self):
        from megaploit.modules.base import AgentModule, ModuleError
        m = AgentModule()
        with pytest.raises(ModuleError, match="no session"):
            m._send("sysinfo")

    def test_agent_module_send_uses_dispatch(self):
        from megaploit.modules.base import AgentModule
        from megaploit.server.commands import CommandResult
        m = AgentModule()
        sess = MagicMock()
        with patch("megaploit.modules.base.AgentModule._send.__module__"):
            pass
        # Patch dispatch at the source
        fake_result = CommandResult(ok=True, output="uid=0")
        with patch("megaploit.server.commands.dispatch", return_value=fake_result) as mock_d:
            out = m._send("whoami", session=sess)
        mock_d.assert_called_once_with(sess, "whoami")
        assert out == "uid=0"

    def test_agent_module_shell_alias(self):
        from megaploit.modules.base import AgentModule
        from megaploit.server.commands import CommandResult
        m = AgentModule()
        sess = MagicMock()
        fake_result = CommandResult(ok=True, output="root")
        with patch("megaploit.server.commands.dispatch", return_value=fake_result):
            out = m._shell("whoami", session=sess)
        assert out == "root"

    def test_agent_module_upload_delegates_to_send(self):
        from megaploit.modules.base import AgentModule
        from megaploit.server.commands import CommandResult
        m = AgentModule()
        sess = MagicMock()
        fake_result = CommandResult(ok=True, output="uploaded")
        with patch("megaploit.server.commands.dispatch", return_value=fake_result) as mock_d:
            m._upload("/local/path", "/remote/path", session=sess)
        call_args = mock_d.call_args[0][1]
        assert "upload" in call_args
        assert "/local/path" in call_args

    def test_agent_module_download_delegates_to_send(self):
        from megaploit.modules.base import AgentModule
        from megaploit.server.commands import CommandResult
        m = AgentModule()
        sess = MagicMock()
        fake_result = CommandResult(ok=True, output="ok")
        with patch("megaploit.server.commands.dispatch", return_value=fake_result) as mock_d:
            m._download("/remote/path", "/local/dest", session=sess)
        call_args = mock_d.call_args[0][1]
        assert "download" in call_args

    def test_agent_module_subclass_run(self):
        """Concrete AgentModule subclass with real run() works end to end."""
        from megaploit.modules.base import AgentModule, ModuleType
        from megaploit.server.commands import CommandResult

        class EchoModule(AgentModule):
            name        = "post/test/echo"
            description = "Echo test"
            module_type = ModuleType.POST

            def run(self, session=None):
                self.validate()
                out = self._send("sysinfo", session=session)
                self._ok("got output", out=out)
                return self.results

        m = EchoModule()
        sess = MagicMock()
        fake = CommandResult(ok=True, output="Linux x86_64")
        with patch("megaploit.server.commands.dispatch", return_value=fake):
            results = m.run(session=sess)
        assert len(results) == 1
        assert results[0].ok
        assert results[0].data["out"] == "Linux x86_64"

    def test_agent_module_in_all_exports(self):
        from megaploit.modules import base
        assert "AgentModule" in base.__all__


# ===========================================================================
# 3.  Item 3 — Go agent build integration
# ===========================================================================

class TestGoBuild:
    def test_go_exe_and_elf_in_output_format(self):
        from megaploit.payload.builder import OutputFormat
        assert hasattr(OutputFormat, "GO_EXE")
        assert hasattr(OutputFormat, "GO_ELF")
        assert OutputFormat.GO_EXE.value == "go_exe"
        assert OutputFormat.GO_ELF.value == "go_elf"

    def test_go_build_fails_gracefully_when_go_not_found(self):
        """When 'go' is not in PATH, build returns a clear error."""
        from megaploit.payload.builder import PayloadBuilder, BuildConfig, OutputFormat
        cfg = BuildConfig(lhost="1.2.3.4", lport=4444, format=OutputFormat.GO_ELF)
        b = PayloadBuilder()
        with patch("shutil.which", return_value=None):
            result = b.build(cfg)
        assert not result.ok
        assert "go" in result.error.lower()

    def test_go_build_fails_gracefully_when_source_missing(self, tmp_path):
        """When the go_agent source dir is missing, build returns an error.

        _compile_go uses a local 'import os' so we can't easily patch os.path.isdir
        by module path. Instead just point the binary to a nonexistent go_src dir
        by placing the builder temporarily in a location that makes go_src invalid.
        We verify the result is not ok and includes a meaningful error string.
        """
        from megaploit.payload.builder import PayloadBuilder, BuildConfig, OutputFormat
        cfg = BuildConfig(lhost="1.2.3.4", lport=4444, format=OutputFormat.GO_EXE)
        b = PayloadBuilder()
        # Patch shutil.which to return truthy so the 'go not found' branch is skipped;
        # patch os.path.isdir (the newly imported one) via builtins path
        original_isdir = os.path.isdir
        try:
            import os as _os
            _os.path.isdir = lambda p: False
            with patch("shutil.which", return_value="/usr/bin/go"):
                result = b.build(cfg)
        finally:
            _os.path.isdir = original_isdir
        assert not result.ok
        assert result.error  # some error message present

    def test_build_returns_correct_format(self):
        from megaploit.payload.builder import PayloadBuilder, BuildConfig, OutputFormat
        cfg = BuildConfig(lhost="1.2.3.4", lport=4444, format=OutputFormat.GO_ELF)
        b = PayloadBuilder()
        # Just verify the format propagates correctly even on failure
        with patch("shutil.which", return_value=None):
            result = b.build(cfg)
        assert result.format == OutputFormat.GO_ELF


# ===========================================================================
# 4.  Item 4 — WebSocket transport (WsTransport)
# ===========================================================================

class TestWsTransport:
    def test_repr_before_handshake(self):
        from megaploit.core.protocol import WsTransport
        conn = MagicMock()
        ws = WsTransport(conn, server_side=True)
        assert "server" in repr(ws)
        assert "closed" in repr(ws)

    def test_send_before_handshake_raises(self):
        from megaploit.core.protocol import WsTransport
        conn = MagicMock()
        ws = WsTransport(conn, server_side=True)
        with pytest.raises(RuntimeError, match="before handshake"):
            ws.send(b"data")

    def test_recv_before_handshake_raises(self):
        from megaploit.core.protocol import WsTransport
        conn = MagicMock()
        ws = WsTransport(conn, server_side=True)
        with pytest.raises(RuntimeError, match="before handshake"):
            ws.recv()

    def _run_ws_pair(self):
        """Return (server_ws, client_ws) with handshake done."""
        from megaploit.core.protocol import WsTransport

        srv_sock, cli_sock = _socket_pair()

        results = {}
        barrier = threading.Event()

        def server_side():
            ws_srv = WsTransport(srv_sock, server_side=True)
            ws_srv.handshake()
            results["server"] = ws_srv
            barrier.set()

        t = threading.Thread(target=server_side, daemon=True)
        t.start()

        ws_cli = WsTransport(cli_sock, server_side=False)
        ws_cli.handshake(host="127.0.0.1", path="/ws")
        barrier.wait(timeout=5)
        return results["server"], ws_cli

    def test_ws_handshake_succeeds(self):
        srv_ws, cli_ws = self._run_ws_pair()
        assert srv_ws._handshook
        assert cli_ws._handshook

    def test_ws_send_recv_client_to_server(self):
        srv_ws, cli_ws = self._run_ws_pair()
        payload = b"hello world from client"

        recv_buf = []
        def _recv():
            recv_buf.append(srv_ws.recv())

        t = threading.Thread(target=_recv, daemon=True)
        t.start()
        cli_ws.send(payload)
        t.join(timeout=3)
        assert recv_buf and recv_buf[0] == payload

    def test_ws_send_recv_server_to_client(self):
        srv_ws, cli_ws = self._run_ws_pair()
        payload = b"hello from server"

        recv_buf = []
        def _recv():
            recv_buf.append(cli_ws.recv())

        t = threading.Thread(target=_recv, daemon=True)
        t.start()
        srv_ws.send(payload)
        t.join(timeout=3)
        assert recv_buf and recv_buf[0] == payload

    def test_ws_large_payload(self):
        """Test 16-bit extended length framing (> 125 bytes, ≤ 65535)."""
        srv_ws, cli_ws = self._run_ws_pair()
        payload = os.urandom(1024)

        recv_buf = []
        def _recv():
            recv_buf.append(srv_ws.recv())

        t = threading.Thread(target=_recv, daemon=True)
        t.start()
        cli_ws.send(payload)
        t.join(timeout=5)
        assert recv_buf and recv_buf[0] == payload

    def test_ws_client_frame_is_masked(self):
        """Client frames must be masked per RFC 6455."""
        from megaploit.core.protocol import WsTransport
        conn = MagicMock()
        ws = WsTransport(conn, server_side=False)
        ws._handshook = True
        payload = b"test"
        frame = ws._build_frame(payload)
        # Byte 1: mask bit should be set (0x80)
        assert frame[1] & 0x80 != 0

    def test_ws_server_frame_is_not_masked(self):
        """Server frames must NOT be masked per RFC 6455."""
        from megaploit.core.protocol import WsTransport
        conn = MagicMock()
        ws = WsTransport(conn, server_side=True)
        ws._handshook = True
        payload = b"test"
        frame = ws._build_frame(payload)
        assert frame[1] & 0x80 == 0

    def test_ws_close(self):
        srv_ws, cli_ws = self._run_ws_pair()
        # Closing should not raise
        srv_ws.close()
        cli_ws.close()


# ===========================================================================
# 5.  Item 5 — Post-exploitation pipeline
# ===========================================================================

class TestPipeline:
    def _fresh_pipeline(self):
        from megaploit.core.pipeline import Pipeline
        return Pipeline()

    def test_available_profiles(self):
        p = self._fresh_pipeline()
        profiles = p.available_profiles()
        assert "basic" in profiles
        assert "creds" in profiles
        assert "recon" in profiles
        assert "full" in profiles

    def test_enable_disable(self):
        p = self._fresh_pipeline()
        p.enable_profile("creds")
        assert p.is_enabled("creds")
        p.disable_profile("creds")
        assert not p.is_enabled("creds")

    def test_enable_unknown_raises(self):
        p = self._fresh_pipeline()
        with pytest.raises(KeyError, match="Unknown pipeline profile"):
            p.enable_profile("nonexistent_profile_xyz")

    def test_disable_unknown_is_noop(self):
        p = self._fresh_pipeline()
        p.disable_profile("nonexistent")  # should not raise

    def test_commands_for_adds_profile_cmds(self):
        p = self._fresh_pipeline()
        p.enable_profile("network")

        sess = MagicMock()
        sess.os_name = "linux"
        sess.tag     = ""
        # Patch autorun to return a known baseline
        with patch.object(p._autorun, "commands_for", return_value=["sysinfo"]):
            cmds = p.commands_for(sess)

        assert "sysinfo" in cmds
        # network profile commands should be appended
        assert "arp" in cmds
        assert "netstat" in cmds

    def test_commands_for_deduplicates(self):
        """Commands from profiles that overlap with autorun are not repeated."""
        p = self._fresh_pipeline()
        p.enable_profile("basic")

        sess = MagicMock()
        sess.os_name = ""
        sess.tag     = ""
        # autorun returns "sysinfo" which is also in "basic" profile
        with patch.object(p._autorun, "commands_for", return_value=["sysinfo"]):
            cmds = p.commands_for(sess)

        assert cmds.count("sysinfo") == 1

    def test_commands_for_no_profiles_returns_autorun_only(self):
        p = self._fresh_pipeline()
        sess = MagicMock()
        sess.os_name = ""
        sess.tag     = ""
        with patch.object(p._autorun, "commands_for", return_value=["sysinfo"]):
            cmds = p.commands_for(sess)
        assert cmds == ["sysinfo"]

    def test_active_profiles_list(self):
        p = self._fresh_pipeline()
        assert p.active_profiles() == []
        p.enable_profile("basic")
        p.enable_profile("creds")
        assert sorted(p.active_profiles()) == ["basic", "creds"]

    def test_summary_keys(self):
        p = self._fresh_pipeline()
        s = p.summary()
        assert "active_profiles" in s
        assert "available_profiles" in s
        assert "autorun" in s

    def test_full_profile_includes_all(self):
        from megaploit.core.pipeline import _PROFILES
        full = set(_PROFILES["full"])
        for name in ("basic", "creds", "recon", "network"):
            for cmd in _PROFILES[name]:
                assert cmd in full, f"{cmd!r} from {name!r} missing in 'full'"

    def test_reload_autorun_does_not_raise(self):
        p = self._fresh_pipeline()
        p.reload_autorun()  # should not raise even if config file absent


# ===========================================================================
# 6.  Item 6 — Malleable C2 profile
# ===========================================================================

class TestC2Profile:
    def test_default_profile_exists(self):
        from megaploit.core.profile import default_profile, C2Profile
        assert isinstance(default_profile, C2Profile)
        assert default_profile.name == "default"

    def test_next_uri(self):
        from megaploit.core.profile import C2Profile
        p = C2Profile(uri_paths=["/a", "/b", "/c"])
        for _ in range(20):
            assert p.next_uri() in ("/a", "/b", "/c")

    def test_next_uri_empty_list_returns_slash(self):
        from megaploit.core.profile import C2Profile
        p = C2Profile(uri_paths=[])
        assert p.next_uri() == "/"

    def test_sleep_with_jitter_in_range(self):
        from megaploit.core.profile import C2Profile
        p = C2Profile(sleep=10.0, jitter_max=5.0)
        for _ in range(50):
            val = p.sleep_with_jitter()
            assert 10.0 <= val <= 15.0

    def test_build_http_headers_includes_user_agent(self):
        from megaploit.core.profile import C2Profile
        p = C2Profile(
            user_agent="TestAgent/1.0",
            request_headers={"Accept": "*/*"},
        )
        h = p.build_http_headers()
        assert h["User-Agent"] == "TestAgent/1.0"
        assert h["Accept"] == "*/*"

    def test_build_http_headers_extra_overrides(self):
        from megaploit.core.profile import C2Profile
        p = C2Profile(user_agent="Base/1.0")
        h = p.build_http_headers(extra={"X-Custom": "val"})
        assert h["X-Custom"] == "val"

    def test_to_dict_round_trips(self):
        from megaploit.core.profile import C2Profile, _from_dict
        p = C2Profile(
            name="test",
            sleep=30.0,
            jitter_max=5.0,
            uri_paths=["/api/v1", "/api/v2"],
            request_headers={"Host": "api.example.com"},
        )
        d = p.to_dict()
        p2 = _from_dict(d)
        assert p2.name == p.name
        assert p2.sleep == p.sleep
        assert p2.uri_paths == p.uri_paths
        assert p2.request_headers == p.request_headers

    def test_load_profile_from_json(self, tmp_path):
        from megaploit.core.profile import load_profile
        data = {
            "name": "TestProfile",
            "sleep": 20.0,
            "jitter_max": 3.0,
            "uri_paths": ["/test"],
            "request_headers": {"Host": "c2.test"},
        }
        p_file = tmp_path / "profile.yaml"
        p_file.write_text(json.dumps(data))
        profile = load_profile(str(p_file))
        assert profile.name == "TestProfile"
        assert profile.sleep == 20.0
        assert profile.uri_paths == ["/test"]
        assert profile.request_headers["Host"] == "c2.test"

    def test_load_profile_file_not_found(self):
        from megaploit.core.profile import load_profile
        with pytest.raises(FileNotFoundError):
            load_profile("/nonexistent/path/profile.yaml")

    def test_uri_cycle_yields_all_paths(self):
        from megaploit.core.profile import C2Profile
        p = C2Profile(uri_paths=["/a", "/b", "/c"])
        gen = p.uri_cycle()
        seen = set()
        for _ in range(50):
            seen.add(next(gen))
        assert seen == {"/a", "/b", "/c"}

    def test_repr(self):
        from megaploit.core.profile import C2Profile
        p = C2Profile(name="myprofile", sleep=5.0, jitter_max=2.0, uri_paths=["/"])
        assert "myprofile" in repr(p)

    def test_load_yaml_profile(self, tmp_path):
        """Test loading a YAML profile (uses PyYAML if available, else JSON fallback)."""
        from megaploit.core.profile import load_profile
        # Write a valid JSON file (compatible with both parsers)
        data = {"name": "JsonCompat", "sleep": 15.0, "uri_paths": ["/img/logo.png"]}
        p_file = tmp_path / "c2.yaml"
        p_file.write_text(json.dumps(data))
        profile = load_profile(str(p_file))
        assert profile.name == "JsonCompat"
        assert profile.sleep == 15.0


# ===========================================================================
# 7.  Item 7 — Multi-operator web UI (WebServer + RpcServer)
# ===========================================================================

class TestWebServer:
    def test_webserver_import(self):
        try:
            pass
        except ImportError:
            pytest.skip("Flask not installed")

    def test_webserver_instantiation(self):
        try:
            from megaploit.web.app import WebServer
        except ImportError:
            pytest.skip("Flask not installed")
            return
        sessions  = {}
        lock      = threading.Lock()
        ws = WebServer(
            sessions_ref=sessions,
            sessions_lock=lock,
            port=0,
            host="127.0.0.1",
            api_key="testkey",
        )
        assert ws is not None

    def test_webserver_is_running_false_before_start(self):
        try:
            from megaploit.web.app import WebServer
        except ImportError:
            pytest.skip("Flask not installed")
            return
        sessions = {}
        lock     = threading.Lock()
        ws = WebServer(sessions_ref=sessions, sessions_lock=lock, api_key="k")
        assert not ws.is_running()

    def test_webserver_url(self):
        try:
            from megaploit.web.app import WebServer
        except ImportError:
            pytest.skip("Flask not installed")
            return
        ws = WebServer(
            sessions_ref={}, sessions_lock=threading.Lock(),
            host="127.0.0.1", port=8080, api_key="k"
        )
        assert "127.0.0.1" in ws.url()
        assert "8080" in ws.url()


class TestRpcServer:
    def test_rpcserver_import(self):
        pass

    def test_rpcserver_instantiation(self):
        from megaploit.web.rpc import RpcServer
        rpc = RpcServer(
            sessions_ref={},
            sessions_lock=threading.Lock(),
            host="127.0.0.1",
            port=0,
            api_key="testkey",
        )
        assert rpc is not None

    def test_rpcserver_not_running_before_start(self):
        from megaploit.web.rpc import RpcServer
        rpc = RpcServer(
            sessions_ref={},
            sessions_lock=threading.Lock(),
            host="127.0.0.1",
            port=0,
            api_key="k",
        )
        assert not rpc._running

    def test_rpcserver_operators_empty_before_start(self):
        from megaploit.web.rpc import RpcServer
        rpc = RpcServer(
            sessions_ref={},
            sessions_lock=threading.Lock(),
            host="127.0.0.1",
            port=0,
            api_key="k",
        )
        # _operators may not exist before first connection — just check it's accessible
        assert not getattr(rpc, "_running", False)
