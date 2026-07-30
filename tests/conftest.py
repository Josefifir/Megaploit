"""
Shared pytest fixtures and configuration.
"""
from __future__ import annotations

import os
import sys

import pytest

# Ensure the project root is on the path so imports work without installation
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def tmp_dir(tmp_path):
    """Temporary directory that is cleaned up after each test."""
    return tmp_path


@pytest.fixture
def mock_session():
    """A minimal mock session object for testing commands and modules."""
    from unittest.mock import MagicMock

    sess = MagicMock()
    sess.id       = 1
    sess.ip       = "10.0.0.1"
    sess.port     = 54321
    sess.tag      = ""
    sess.notes    = []
    sess.os_name  = "Linux"
    sess.hostname = "testhost"
    sess.username = "testuser"
    sess.uptime   = "00:01:23"
    sess.connected_at = 0.0
    sess.to_dict.return_value = {
        "id":       1,
        "ip":       "10.0.0.1",
        "port":     54321,
        "os_name":  "Linux",
        "hostname": "testhost",
        "username": "testuser",
        "tag":      "",
        "uptime":   "00:01:23",
    }
    return sess


@pytest.fixture
def db_path(tmp_path):
    """Return path for a fresh SQLite database."""
    return str(tmp_path / "test.db")


@pytest.fixture
def fresh_db(db_path):
    """A fresh Database instance backed by a temp file."""
    from megaploit.db.database import Database
    return Database(path=db_path)


@pytest.fixture
def loot_dir(tmp_path):
    """Temporary loot directory."""
    d = tmp_path / "loot"
    d.mkdir()
    return d
