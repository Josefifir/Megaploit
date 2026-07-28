"""
Unit tests for megaploit.payload.builder — PayloadBuilder.
"""
from __future__ import annotations

import base64
import gzip
import os

import pytest

from megaploit.payload.builder import (
    BuildConfig,
    BuildResult,
    OutputFormat,
    PayloadBuilder,
    builder,
)


LHOST = "10.0.0.1"
LPORT = 4444
KEY   = b"\x01" * 32


class TestBuildConfig:
    def test_defaults(self):
        cfg = BuildConfig(lhost=LHOST, lport=LPORT)
        assert cfg.format  == OutputFormat.PY
        assert cfg.use_tls is False
        assert cfg.encoders == []

    def test_custom_format(self):
        cfg = BuildConfig(lhost=LHOST, lport=LPORT, format=OutputFormat.PS1)
        assert cfg.format == OutputFormat.PS1


class TestPayloadBuilderFormats:

    def _build(self, fmt: str, **kwargs) -> BuildResult:
        cfg = BuildConfig(
            lhost=LHOST, lport=LPORT,
            format=OutputFormat(fmt),
            secret_key=KEY,
            **kwargs,
        )
        return builder.build(cfg)

    def test_py_format_is_python_source(self):
        r = self._build("py")
        assert r.ok, r.error
        src = r.data.decode()
        assert "LHOST" in src
        assert str(LPORT) in src
        assert "def main" in src

    def test_ps1_format_is_powershell(self):
        r = self._build("ps1")
        assert r.ok, r.error
        src = r.data.decode()
        assert "Base64String" in src or "base64" in src.lower()

    def test_sh_format_is_bash(self):
        r = self._build("sh")
        assert r.ok, r.error
        src = r.data.decode()
        assert "#!/bin/sh" in src
        assert "base64" in src.lower()

    def test_bat_format(self):
        r = self._build("bat")
        assert r.ok, r.error
        src = r.data.decode()
        assert "@echo off" in src

    def test_hta_format(self):
        r = self._build("hta")
        assert r.ok, r.error
        src = r.data.decode()
        assert "hta:application" in src.lower() or "VBScript" in src

    def test_vba_format(self):
        r = self._build("vba")
        assert r.ok, r.error
        src = r.data.decode()
        assert "Sub AutoOpen" in src or "Sub Document_Open" in src

    def test_raw_same_as_py(self):
        py  = self._build("py")
        raw = self._build("raw")
        assert py.data == raw.data

    def test_oneliner_py_format(self):
        r = self._build("oneliner_py")
        assert r.ok, r.error
        src = r.data.decode()
        assert "python3" in src
        assert "base64" in src.lower()

    def test_oneliner_ps1_format(self):
        r = self._build("oneliner_ps1")
        assert r.ok, r.error
        src = r.data.decode()
        assert "powershell" in src.lower()

    def test_oneliner_py_decompresses(self):
        """The base64+gzip payload must decompress to valid Python."""
        r = self._build("oneliner_py")
        src = r.data.decode()
        # Extract the base64 blob
        import re
        m = re.search(r"base64\.b64decode\('([A-Za-z0-9+/=]+)'\)", src)
        if m is None:
            # Try alternate pattern with double quotes
            m = re.search(r'base64\.b64decode\("([A-Za-z0-9+/=]+)"\)', src)
        assert m is not None, f"No base64 blob found in: {src[:200]}"
        decoded = base64.b64decode(m.group(1))
        decompressed = gzip.decompress(decoded).decode()
        assert "LHOST" in decompressed

    def test_tls_flag_in_agent(self):
        r = self._build("py", use_tls=True)
        assert r.ok, r.error
        src = r.data.decode()
        assert "USE_TLS = True" in src

    def test_secret_key_in_agent(self):
        r = self._build("py")
        src = r.data.decode()
        expected_b64 = base64.b64encode(KEY).decode()
        assert expected_b64 in src

    def test_write_to_file(self, tmp_path):
        out = str(tmp_path / "agent.py")
        cfg = BuildConfig(lhost=LHOST, lport=LPORT, output_path=out, secret_key=KEY)
        r = builder.build(cfg)
        assert r.ok, r.error
        assert r.output_path == out
        assert os.path.isfile(out)
        assert r.data == b""  # data not returned when writing to file

    def test_build_result_sha256(self):
        r = self._build("py")
        assert len(r.sha256) == 64
        import hashlib
        assert r.sha256 == hashlib.sha256(r.data).hexdigest()

    def test_build_result_size(self):
        r = self._build("py")
        assert r.size == len(r.data)
        assert r.size > 100

    def test_build_time_is_set(self):
        r = self._build("py")
        assert r.build_time_s >= 0

    def test_invalid_format_is_caught(self):
        """An unsupported format string should produce BuildResult.ok=False."""
        # Bypass the Enum to simulate a bad format directly
        cfg = BuildConfig(lhost=LHOST, lport=LPORT, format=OutputFormat.PY)
        b = PayloadBuilder()
        # Monkeypatch _render to raise
        original = b._render
        def bad_render(c):
            raise ValueError("Unsupported")
        b._render = bad_render
        r = b.build(cfg)
        assert r.ok is False
        assert "Unsupported" in r.error

    def test_supported_formats_list(self):
        fmts = builder.supported_formats()
        for f in ("py", "ps1", "sh", "bat", "hta", "vba", "raw",
                   "exe", "elf", "oneliner_py", "oneliner_ps1"):
            assert f in fmts

    def test_quick_helpers(self):
        assert builder.build_py(LHOST, LPORT).ok
        assert builder.build_ps1(LHOST, LPORT).ok
        assert builder.build_sh(LHOST, LPORT).ok
        assert builder.build_oneliner(LHOST, LPORT).ok
        assert builder.build_oneliner(LHOST, LPORT, ps1=True).ok
