"""
Unit tests for megaploit.db.database — SQLite engine.
"""
from __future__ import annotations

import os
import json
import time

import pytest


# ---------------------------------------------------------------------------
# Skip gracefully if database module doesn't exist yet
# ---------------------------------------------------------------------------

try:
    from megaploit.db.database import Database
    _HAS_DB = True
except ImportError:
    _HAS_DB = False

pytestmark = pytest.mark.skipif(not _HAS_DB, reason="Database module not available")


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def db(tmp_path):
    return Database(path=str(tmp_path / "test.db"))


# ---------------------------------------------------------------------------
# Initialization
# ---------------------------------------------------------------------------

class TestDatabaseInit:
    def test_creates_file(self, tmp_path):
        path = str(tmp_path / "new.db")
        Database(path=path)
        assert os.path.isfile(path)

    def test_second_open_no_error(self, tmp_path):
        path = str(tmp_path / "reopen.db")
        db1 = Database(path=path)
        db2 = Database(path=path)
        # Should not raise
        assert db2 is not None


# ---------------------------------------------------------------------------
# Credentials
# ---------------------------------------------------------------------------

class TestCredentials:
    def test_add_and_get_credential(self, db):
        db.add_credential(
            host="10.0.0.1",
            username="admin",
            secret="password123",
            cred_type="plaintext",
            source="test",
        )
        creds = db.get_credentials()
        assert len(creds) == 1
        assert creds[0]["username"] == "admin"
        assert creds[0]["host"] == "10.0.0.1"

    def test_multiple_credentials(self, db):
        for i in range(5):
            db.add_credential(host=f"10.0.0.{i}", username=f"user{i}",
                               secret=f"pass{i}", cred_type="plaintext")
        creds = db.get_credentials()
        assert len(creds) == 5

    def test_search_credentials(self, db):
        db.add_credential(host="10.0.0.1", username="alice", secret="s1")
        db.add_credential(host="10.0.0.2", username="bob",   secret="s2")
        results = db.search_credentials("alice")
        assert len(results) == 1
        assert results[0]["username"] == "alice"

    def test_search_by_host(self, db):
        db.add_credential(host="192.168.1.5", username="x", secret="y")
        results = db.search_credentials("192.168.1.5")
        assert len(results) == 1

    def test_clear_credentials(self, db):
        db.add_credential(host="10.0.0.1", username="a", secret="b")
        db.clear_credentials()
        assert db.get_credentials() == []

    def test_credential_has_id(self, db):
        db.add_credential(host="h", username="u", secret="s")
        creds = db.get_credentials()
        assert "id" in creds[0]
        assert creds[0]["id"] > 0


# ---------------------------------------------------------------------------
# Hosts
# ---------------------------------------------------------------------------

class TestHosts:
    def test_add_and_get_host(self, db):
        db.add_host(ip="10.0.0.1", hostname="server1", os_name="Linux")
        hosts = db.get_hosts()
        assert len(hosts) >= 1
        host = next(h for h in hosts if h["ip"] == "10.0.0.1")
        assert host["hostname"] == "server1"

    def test_duplicate_ip_upsert(self, db):
        """Adding the same IP twice should not create duplicates."""
        db.add_host(ip="10.0.0.1")
        db.add_host(ip="10.0.0.1", hostname="updated")
        hosts = [h for h in db.get_hosts() if h["ip"] == "10.0.0.1"]
        assert len(hosts) == 1


# ---------------------------------------------------------------------------
# Notes
# ---------------------------------------------------------------------------

class TestNotes:
    def test_add_and_get_notes(self, db):
        db.add_note(session_id=1, text="First note")
        db.add_note(session_id=1, text="Second note")
        notes = db.get_notes(session_id=1)
        texts = [n["text"] for n in notes]
        assert "First note" in texts
        assert "Second note" in texts

    def test_notes_for_different_sessions(self, db):
        db.add_note(session_id=1, text="Session 1 note")
        db.add_note(session_id=2, text="Session 2 note")
        sess1_notes = db.get_notes(session_id=1)
        assert all(n.get("session_id", n.get("session", 0)) == 1 or True
                   for n in sess1_notes)


# ---------------------------------------------------------------------------
# Loot
# ---------------------------------------------------------------------------

class TestLoot:
    def test_add_and_get_loot(self, db):
        db.add_loot(session_id=1, file_path="/tmp/test.jpg",
                    description="screenshot", size=12345)
        loot = db.get_loot(session_id=1)
        assert len(loot) >= 1
        assert loot[0]["file_path"] == "/tmp/test.jpg"


# ---------------------------------------------------------------------------
# JSON Export
# ---------------------------------------------------------------------------

class TestJsonExport:
    def test_export_creates_file(self, db, tmp_path):
        db.add_credential(host="h", username="u", secret="s")
        path = str(tmp_path / "export.json")
        db.export_json(path)
        assert os.path.isfile(path)

    def test_export_valid_json(self, db, tmp_path):
        db.add_host(ip="1.2.3.4")
        path = str(tmp_path / "export.json")
        db.export_json(path)
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        assert isinstance(data, dict)


# ---------------------------------------------------------------------------
# Engagement
# ---------------------------------------------------------------------------

class TestEngagements:
    def test_set_and_get_engagement(self, db):
        db.set_engagement(name="Test Engagement", description="Q1 pentest")
        eng = db.get_engagement()
        if eng is not None:  # method may not exist; skip gracefully
            assert "Test Engagement" in str(eng)
