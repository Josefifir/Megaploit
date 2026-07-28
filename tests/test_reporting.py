"""
Unit tests for megaploit.reporting.report — HTML + JSON report generator.
"""
from __future__ import annotations

import json
import os

import pytest

from megaploit.reporting.report import generate_report, _esc, _fmt_size


def _mock_session(id_=1, ip="10.0.0.1", port=54321,
                   os_name="Linux", hostname="host1",
                   username="root", tag="server", notes=None):
    from unittest.mock import MagicMock
    sess = MagicMock()
    sess.id       = id_
    sess.ip       = ip
    sess.port     = port
    sess.os_name  = os_name
    sess.hostname = hostname
    sess.username = username
    sess.tag      = tag
    sess.uptime   = "00:10:00"
    sess.notes    = notes or []
    sess.to_dict.return_value = {
        "id": id_, "ip": ip, "port": port,
        "os_name": os_name, "hostname": hostname,
        "username": username, "tag": tag, "uptime": "00:10:00",
    }
    return sess


class TestEscHelper:
    def test_escapes_ampersand(self):
        assert _esc("a & b") == "a &amp; b"

    def test_escapes_lt_gt(self):
        assert _esc("<script>") == "&lt;script&gt;"

    def test_escapes_quotes(self):
        assert _esc('"hello"') == "&quot;hello&quot;"

    def test_plain_text_unchanged(self):
        assert _esc("hello world") == "hello world"


class TestFmtSize:
    def test_bytes(self):
        assert "B" in _fmt_size(512)

    def test_kilobytes(self):
        assert "KB" in _fmt_size(2048)

    def test_megabytes(self):
        assert "MB" in _fmt_size(2 * 1024 * 1024)


class TestGenerateHtmlReport:
    def test_creates_html_file(self, tmp_path):
        out = str(tmp_path / "report.html")
        sessions = [_mock_session()]
        generate_report(output_path=out, fmt="html",
                        engagement_name="Test Engagement",
                        sessions=sessions)
        assert os.path.isfile(out)
        with open(out, encoding="utf-8") as f:
            html = f.read()
        assert "<!DOCTYPE html>" in html

    def test_html_contains_engagement_name(self, tmp_path):
        out = str(tmp_path / "report.html")
        generate_report(output_path=out, fmt="html",
                        engagement_name="Acme Corp Pentest",
                        sessions=[])
        with open(out, encoding="utf-8") as f:
            html = f.read()
        assert "Acme Corp Pentest" in html

    def test_html_contains_session_ip(self, tmp_path):
        out = str(tmp_path / "report.html")
        sessions = [_mock_session(ip="192.168.1.100")]
        generate_report(output_path=out, fmt="html", sessions=sessions)
        with open(out, encoding="utf-8") as f:
            html = f.read()
        assert "192.168.1.100" in html

    def test_html_contains_session_os_badge(self, tmp_path):
        out = str(tmp_path / "report.html")
        sessions = [_mock_session(os_name="Windows 10")]
        generate_report(output_path=out, fmt="html", sessions=sessions)
        with open(out, encoding="utf-8") as f:
            html = f.read()
        assert "Windows 10" in html

    def test_html_no_sessions_message(self, tmp_path):
        out = str(tmp_path / "report.html")
        generate_report(output_path=out, fmt="html", sessions=[])
        with open(out, encoding="utf-8") as f:
            html = f.read()
        assert "No sessions recorded" in html

    def test_html_escapes_xss(self, tmp_path):
        out = str(tmp_path / "report.html")
        sessions = [_mock_session(hostname="<script>alert(1)</script>")]
        generate_report(output_path=out, fmt="html", sessions=sessions)
        with open(out, encoding="utf-8") as f:
            html = f.read()
        assert "<script>alert(1)</script>" not in html
        assert "&lt;script&gt;" in html

    def test_html_notes_included(self, tmp_path):
        out = str(tmp_path / "report.html")
        sessions = [_mock_session(notes=["Found open SMB share", "Dumped hashes"])]
        generate_report(output_path=out, fmt="html", sessions=sessions)
        with open(out, encoding="utf-8") as f:
            html = f.read()
        assert "Found open SMB share" in html

    def test_html_self_contained(self, tmp_path):
        """HTML file should not reference external CSS/JS."""
        out = str(tmp_path / "report.html")
        generate_report(output_path=out, fmt="html", sessions=[])
        with open(out, encoding="utf-8") as f:
            html = f.read()
        # No external stylesheet links
        import re
        assert not re.search(r'<link[^>]+href=["\']https?://', html)
        # No external script srcs
        assert not re.search(r'<script[^>]+src=["\']https?://', html)

    def test_html_multiple_sessions(self, tmp_path):
        out = str(tmp_path / "report.html")
        sessions = [_mock_session(id_=i, ip=f"10.0.0.{i}") for i in range(1, 4)]
        generate_report(output_path=out, fmt="html", sessions=sessions)
        with open(out, encoding="utf-8") as f:
            html = f.read()
        for i in range(1, 4):
            assert f"10.0.0.{i}" in html


class TestGenerateJsonReport:
    def test_creates_json_file(self, tmp_path):
        out = str(tmp_path / "report.json")
        sessions = [_mock_session()]
        generate_report(output_path=out, fmt="json",
                        engagement_name="Test",
                        sessions=sessions)
        assert os.path.isfile(out)

    def test_json_is_valid(self, tmp_path):
        out = str(tmp_path / "report.json")
        generate_report(output_path=out, fmt="json",
                        engagement_name="JSON Test",
                        sessions=[_mock_session()])
        with open(out, encoding="utf-8") as f:
            data = json.load(f)
        assert isinstance(data, dict)

    def test_json_contains_engagement_key(self, tmp_path):
        out = str(tmp_path / "report.json")
        generate_report(output_path=out, fmt="json",
                        engagement_name="My Pentest",
                        sessions=[])
        with open(out, encoding="utf-8") as f:
            data = json.load(f)
        assert "engagement" in data
        assert data["engagement"]["name"] == "My Pentest"

    def test_json_contains_sessions(self, tmp_path):
        out = str(tmp_path / "report.json")
        generate_report(output_path=out, fmt="json",
                        sessions=[_mock_session(id_=7)])
        with open(out, encoding="utf-8") as f:
            data = json.load(f)
        assert "sessions" in data
        assert len(data["sessions"]) == 1
        assert data["sessions"][0]["id"] == 7

    def test_json_generated_at_timestamp(self, tmp_path):
        out = str(tmp_path / "report.json")
        generate_report(output_path=out, fmt="json", sessions=[])
        with open(out, encoding="utf-8") as f:
            data = json.load(f)
        assert "generated_at" in data
        assert data["generated_at"].endswith("Z")

    def test_default_format_is_html(self, tmp_path):
        out = str(tmp_path / "report.html")
        generate_report(output_path=out, sessions=[])
        with open(out, encoding="utf-8") as f:
            content = f.read()
        assert "<!DOCTYPE html>" in content
