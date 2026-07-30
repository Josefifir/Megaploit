"""
tests/test_tls_autocert.py
~~~~~~~~~~~~~~~~~~~~~~~~~~
Unit tests for TLS auto-cert generation in megaploit.server.listener.

All disk I/O and subprocess calls are mocked — no files are actually
written and no real ``openssl`` binary is required.
"""

from __future__ import annotations

import hashlib
import os
import sys
import types
from unittest.mock import MagicMock, patch

import pytest


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_fake_cryptography(cert_der: bytes = b"FAKE-DER"):
    """Return a minimal mock of the ``cryptography`` package tree."""
    x509_mod = types.ModuleType("cryptography.x509")
    oid_mod   = types.ModuleType("cryptography.x509.oid")
    hashes_mod = types.ModuleType("cryptography.hazmat.primitives.hashes")
    serial_mod = types.ModuleType("cryptography.hazmat.primitives.serialization")
    rsa_mod    = types.ModuleType("cryptography.hazmat.primitives.asymmetric.rsa")

    # Fake key
    fake_pub_key = MagicMock()
    fake_key = MagicMock()
    fake_key.public_key.return_value = fake_pub_key
    fake_key.private_bytes.return_value = b"FAKE-KEY-PEM"
    rsa_mod.generate_private_key = MagicMock(return_value=fake_key)

    # NameOID stub
    class _NameOID:
        COMMON_NAME = "CN"
    oid_mod.NameOID = _NameOID

    # Encoding / Format / NoEncryption stubs
    class _Enc:
        PEM = "PEM"
        DER = "DER"
    class _Fmt:
        TraditionalOpenSSL = "TraditionalOpenSSL"
    serial_mod.Encoding = _Enc
    serial_mod.PrivateFormat = _Fmt
    serial_mod.NoEncryption = MagicMock(return_value=None)

    # Fake cert
    fake_cert = MagicMock()
    fake_cert.public_bytes.side_effect = lambda enc: (
        b"FAKE-CERT-PEM" if enc == "PEM" else cert_der
    )

    # CertificateBuilder chain
    builder = MagicMock()
    builder.subject_name.return_value = builder
    builder.issuer_name.return_value  = builder
    builder.public_key.return_value   = builder
    builder.serial_number.return_value = builder
    builder.not_valid_before.return_value = builder
    builder.not_valid_after.return_value  = builder
    builder.add_extension.return_value    = builder
    builder.sign.return_value = fake_cert
    x509_mod.CertificateBuilder = MagicMock(return_value=builder)

    x509_mod.Name = MagicMock(return_value="NAME")
    x509_mod.NameAttribute = MagicMock()
    x509_mod.BasicConstraints = MagicMock()
    x509_mod.random_serial_number = MagicMock(return_value=1)

    hashes_mod.SHA256 = MagicMock(return_value=None)

    crypto_mod = types.ModuleType("cryptography")

    return {
        "cryptography":                                    crypto_mod,
        "cryptography.x509":                               x509_mod,
        "cryptography.x509.oid":                           oid_mod,
        "cryptography.hazmat.primitives.hashes":           hashes_mod,
        "cryptography.hazmat.primitives.serialization":    serial_mod,
        "cryptography.hazmat.primitives.asymmetric.rsa":   rsa_mod,
        "cryptography.hazmat":                             types.ModuleType("cryptography.hazmat"),
        "cryptography.hazmat.primitives":                  types.ModuleType("cryptography.hazmat.primitives"),
        "cryptography.hazmat.primitives.asymmetric":       types.ModuleType("cryptography.hazmat.primitives.asymmetric"),
    }


# ---------------------------------------------------------------------------
# Tests — cryptography backend
# ---------------------------------------------------------------------------

class TestGenerateCertCryptography:
    """generate_self_signed_cert() using the cryptography package."""

    def test_returns_correct_paths(self, tmp_path):
        cert_der = b"CERT-DER-BYTES"
        mods = _make_fake_cryptography(cert_der)

        with patch.dict(sys.modules, mods):
            from importlib import reload
            import megaploit.server.listener as _listener
            reload(_listener)

            cert_out = str(tmp_path / "test.crt")
            key_out  = str(tmp_path / "test.key")
            c, k, fp = _listener.generate_self_signed_cert(cert_out, key_out, cn="10.0.0.1")

        assert c == cert_out
        assert k == key_out

    def test_fingerprint_is_sha256_of_der(self, tmp_path):
        cert_der = b"DETERMINISTIC-DER"
        expected_fp = hashlib.sha256(cert_der).hexdigest()
        mods = _make_fake_cryptography(cert_der)

        with patch.dict(sys.modules, mods):
            from importlib import reload
            import megaploit.server.listener as _listener
            reload(_listener)

            c, k, fp = _listener.generate_self_signed_cert(
                str(tmp_path / "a.crt"), str(tmp_path / "a.key"), cn="host"
            )

        assert fp == expected_fp

    def test_cert_and_key_files_written(self, tmp_path):
        cert_der = b"DER-DATA"
        mods = _make_fake_cryptography(cert_der)

        with patch.dict(sys.modules, mods):
            from importlib import reload
            import megaploit.server.listener as _listener
            reload(_listener)

            cert_out = str(tmp_path / "out.crt")
            key_out  = str(tmp_path / "out.key")
            _listener.generate_self_signed_cert(cert_out, key_out, cn="host")

        assert os.path.exists(cert_out)
        assert os.path.exists(key_out)
        with open(cert_out, "rb") as f:
            assert f.read() == b"FAKE-CERT-PEM"
        with open(key_out, "rb") as f:
            assert f.read() == b"FAKE-KEY-PEM"

    def test_creates_parent_directory(self, tmp_path):
        cert_der = b"DER"
        mods = _make_fake_cryptography(cert_der)
        nested_cert = str(tmp_path / "a" / "b" / "cert.crt")
        nested_key  = str(tmp_path / "a" / "b" / "cert.key")

        with patch.dict(sys.modules, mods):
            from importlib import reload
            import megaploit.server.listener as _listener
            reload(_listener)
            _listener.generate_self_signed_cert(nested_cert, nested_key, cn="h")

        assert os.path.exists(nested_cert)


# ---------------------------------------------------------------------------
# Tests — openssl subprocess fallback
# ---------------------------------------------------------------------------

class TestGenerateCertOpenSSLFallback:
    """generate_self_signed_cert() using the openssl subprocess fallback."""

    def test_openssl_called_when_no_cryptography(self, tmp_path):
        cert_out = str(tmp_path / "fb.crt")
        key_out  = str(tmp_path / "fb.key")
        der_bytes = b"OPENSSL-DER"

        # Write fake cert so the file-read path works
        with open(cert_out, "wb") as f:
            f.write(b"FAKE-PEM")

        with patch.dict(sys.modules, {"cryptography": None}):
            with patch("megaploit.server.listener.subprocess.run") as mock_run:
                mock_run.return_value = MagicMock(stdout=der_bytes, returncode=0)

                from importlib import reload
                import megaploit.server.listener as _listener
                reload(_listener)

                c, k, fp = _listener.generate_self_signed_cert(cert_out, key_out, cn="host")

        assert mock_run.called
        assert fp == hashlib.sha256(der_bytes).hexdigest()

    def test_raises_runtime_error_when_openssl_missing(self, tmp_path):
        cert_out = str(tmp_path / "err.crt")
        key_out  = str(tmp_path / "err.key")


        with patch.dict(sys.modules, {"cryptography": None}):
            with patch("megaploit.server.listener.subprocess.run",
                       side_effect=FileNotFoundError("openssl not found")):
                from importlib import reload
                import megaploit.server.listener as _listener
                reload(_listener)

                with pytest.raises(RuntimeError, match="cryptography"):
                    _listener.generate_self_signed_cert(cert_out, key_out, cn="h")
