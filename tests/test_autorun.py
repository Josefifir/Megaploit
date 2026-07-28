"""
Unit tests for megaploit.core.autorun — AutoRunScript.
"""
from __future__ import annotations

import json
import os

import pytest

from megaploit.core.autorun import AutoRunScript


def _make_config(tmp_path: object, data: dict) -> str:
    """Write a config file and return its path."""
    p = str(tmp_path / "autorun.json")
    with open(p, "w", encoding="utf-8") as f:
        json.dump(data, f)
    return p


def _mock_session(os_name: str = "", tag: str = "") -> object:
    """Minimal mock session."""
    from unittest.mock import MagicMock
    s = MagicMock()
    s.os_name = os_name
    s.tag     = tag
    return s


class TestAutoRunScriptLoad:
    def test_loads_from_file(self, tmp_path):
        cfg = {"global": ["sysinfo"], "windows": [], "linux": [], "darwin": [], "tags": {}}
        path = _make_config(tmp_path, cfg)
        ar = AutoRunScript(config_path=path)
        assert "sysinfo" in ar.summary()["global"]

    def test_missing_file_uses_defaults(self, tmp_path):
        path = str(tmp_path / "nonexistent.json")
        ar = AutoRunScript(config_path=path)
        summary = ar.summary()
        # Should have default keys without raising
        assert "global" in summary
        assert "windows" in summary

    def test_reload(self, tmp_path):
        cfg_v1 = {"global": ["sysinfo"], "tags": {}, "windows": [], "linux": [], "darwin": []}
        path = _make_config(tmp_path, cfg_v1)
        ar = AutoRunScript(config_path=path)
        assert ar.summary()["global"] == ["sysinfo"]

        cfg_v2 = {"global": ["sysinfo", "ps"], "tags": {}, "windows": [], "linux": [], "darwin": []}
        with open(path, "w") as f:
            json.dump(cfg_v2, f)
        ar.reload()
        assert "ps" in ar.summary()["global"]


class TestCommandsFor:
    def test_global_always_runs(self, tmp_path):
        path = _make_config(tmp_path, {
            "global": ["sysinfo", "whoami"],
            "windows": [], "linux": [], "darwin": [], "tags": {}
        })
        ar = AutoRunScript(config_path=path)
        cmds = ar.commands_for(_mock_session("Linux"))
        assert "sysinfo" in cmds
        assert "whoami" in cmds

    def test_linux_platform_commands(self, tmp_path):
        path = _make_config(tmp_path, {
            "global": [],
            "linux":  ["find_suid", "users"],
            "windows": [], "darwin": [], "tags": {}
        })
        ar = AutoRunScript(config_path=path)
        cmds = ar.commands_for(_mock_session("Linux 5.15"))
        assert "find_suid" in cmds
        assert "users" in cmds

    def test_windows_platform_commands(self, tmp_path):
        path = _make_config(tmp_path, {
            "global": [],
            "windows": ["ps", "scheduled_tasks"],
            "linux": [], "darwin": [], "tags": {}
        })
        ar = AutoRunScript(config_path=path)
        cmds = ar.commands_for(_mock_session("Windows 10"))
        assert "ps" in cmds
        assert "scheduled_tasks" in cmds

    def test_darwin_platform_commands(self, tmp_path):
        path = _make_config(tmp_path, {
            "global": [],
            "darwin": ["startup_items"],
            "windows": [], "linux": [], "tags": {}
        })
        ar = AutoRunScript(config_path=path)
        cmds = ar.commands_for(_mock_session("Darwin 22.3"))
        assert "startup_items" in cmds

    def test_tag_commands(self, tmp_path):
        path = _make_config(tmp_path, {
            "global": [],
            "windows": [], "linux": [], "darwin": [],
            "tags": {"dc": ["hashdump", "users"]}
        })
        ar = AutoRunScript(config_path=path)
        cmds = ar.commands_for(_mock_session(tag="dc"))
        assert "hashdump" in cmds
        assert "users" in cmds

    def test_tag_not_matched(self, tmp_path):
        path = _make_config(tmp_path, {
            "global": [],
            "windows": [], "linux": [], "darwin": [],
            "tags": {"dc": ["hashdump"]}
        })
        ar = AutoRunScript(config_path=path)
        cmds = ar.commands_for(_mock_session(tag="workstation"))
        assert "hashdump" not in cmds

    def test_deduplication(self, tmp_path):
        """Same command in global and platform should appear only once."""
        path = _make_config(tmp_path, {
            "global":  ["sysinfo"],
            "linux":   ["sysinfo", "users"],
            "windows": [], "darwin": [], "tags": {}
        })
        ar = AutoRunScript(config_path=path)
        cmds = ar.commands_for(_mock_session("Linux"))
        assert cmds.count("sysinfo") == 1

    def test_order_preserved(self, tmp_path):
        path = _make_config(tmp_path, {
            "global": ["a", "b", "c"],
            "linux": [], "windows": [], "darwin": [], "tags": {}
        })
        ar = AutoRunScript(config_path=path)
        cmds = ar.commands_for(_mock_session())
        assert cmds.index("a") < cmds.index("b") < cmds.index("c")

    def test_empty_config(self, tmp_path):
        path = _make_config(tmp_path, {
            "global": [], "linux": [], "windows": [], "darwin": [], "tags": {}
        })
        ar = AutoRunScript(config_path=path)
        cmds = ar.commands_for(_mock_session("Linux"))
        assert cmds == []

    def test_no_os_name(self, tmp_path):
        """Session with no os_name should only get global commands."""
        path = _make_config(tmp_path, {
            "global": ["sysinfo"],
            "linux": ["find_suid"],
            "windows": [], "darwin": [], "tags": {}
        })
        ar = AutoRunScript(config_path=path)
        cmds = ar.commands_for(_mock_session(os_name=""))
        assert "sysinfo" in cmds
        assert "find_suid" not in cmds


class TestApply:
    def test_apply_calls_send_fn(self, tmp_path):
        path = _make_config(tmp_path, {
            "global": ["sysinfo", "ps"],
            "linux": [], "windows": [], "darwin": [], "tags": {}
        })
        ar = AutoRunScript(config_path=path)
        sess = _mock_session()
        dispatched = []
        ar.apply(sess, send_fn=lambda s, c: dispatched.append(c))
        assert "sysinfo" in dispatched
        assert "ps" in dispatched

    def test_apply_without_send_fn_returns_list(self, tmp_path):
        path = _make_config(tmp_path, {
            "global": ["sysinfo"],
            "linux": [], "windows": [], "darwin": [], "tags": {}
        })
        ar = AutoRunScript(config_path=path)
        cmds = ar.apply(_mock_session())
        assert "sysinfo" in cmds


class TestSaveDefault:
    def test_saves_file(self, tmp_path):
        path = str(tmp_path / "new_autorun.json")
        ar = AutoRunScript(config_path=path)
        ar.save_default()
        assert os.path.isfile(path)
        with open(path) as f:
            data = json.load(f)
        assert "global" in data
        assert "tags" in data


class TestSummary:
    def test_summary_keys(self, tmp_path):
        path = _make_config(tmp_path, {
            "global": ["sysinfo"], "linux": ["users"],
            "windows": [], "darwin": [], "tags": {"dc": ["hashdump"]}
        })
        ar = AutoRunScript(config_path=path)
        s = ar.summary()
        assert s["path"] == path
        assert s["global"] == ["sysinfo"]
        assert s["linux"] == ["users"]
        assert s["tags"]["dc"] == ["hashdump"]

    def test_repr(self, tmp_path):
        path = _make_config(tmp_path, {
            "global": ["sysinfo"],
            "linux": [], "windows": [], "darwin": [], "tags": {}
        })
        ar = AutoRunScript(config_path=path)
        assert "AutoRunScript" in repr(ar)
