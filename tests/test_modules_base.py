"""
Unit tests for megaploit.modules.base — Module base class.
"""
from __future__ import annotations

import pytest

from megaploit.modules.base import (
    Module,
    ModuleError,
    ModuleOption,
    ModuleResult,
    ModuleType,
    OptionType,
)


# ---------------------------------------------------------------------------
# Helper: minimal concrete module
# ---------------------------------------------------------------------------

class _DummyModule(Module):
    name        = "auxiliary/test/dummy"
    description = "Test module"
    module_type = ModuleType.AUXILIARY
    author      = "test"
    rank        = 300

    def _define_options(self) -> None:
        self._opt("RHOSTS",  OptionType.STRING,  required=True,
                  description="Target IP or CIDR")
        self._opt("PORT",    OptionType.PORT,    default=80,  required=False,
                  description="Port")
        self._opt("TIMEOUT", OptionType.INTEGER, default=5,   required=False,
                  description="Timeout seconds")
        self._opt("SSL",     OptionType.BOOLEAN, default=False, required=False,
                  description="Use TLS")
        self._opt("RHOSTS2", OptionType.CIDR,    required=False,
                  description="Optional CIDR")
        self._opt("PROTO",   OptionType.ENUM,    default="http", required=False,
                  choices=["http", "https", "ftp"],
                  description="Protocol")

    def run(self, session=None):
        self.validate()
        self.results.clear()
        self._ok("dummy ran", host=str(self.get("RHOSTS")))
        return self.results


# ---------------------------------------------------------------------------
# ModuleOption
# ---------------------------------------------------------------------------

class TestModuleOption:
    def test_string_default(self):
        opt = ModuleOption("FOO", OptionType.STRING, default="bar")
        assert opt.value == "bar"

    def test_string_set(self):
        opt = ModuleOption("FOO", OptionType.STRING)
        opt.set("hello")
        assert opt.value == "hello"

    def test_integer_set(self):
        opt = ModuleOption("N", OptionType.INTEGER)
        opt.set("42")
        assert opt.value == 42

    def test_integer_bad(self):
        opt = ModuleOption("N", OptionType.INTEGER)
        with pytest.raises(ModuleError, match="expected integer"):
            opt.set("abc")

    def test_port_valid(self):
        opt = ModuleOption("P", OptionType.PORT)
        opt.set("443")
        assert opt.value == 443

    def test_port_out_of_range(self):
        opt = ModuleOption("P", OptionType.PORT)
        with pytest.raises(ModuleError, match="out of range"):
            opt.set("99999")

    def test_boolean_true(self):
        opt = ModuleOption("B", OptionType.BOOLEAN)
        for raw in ("true", "yes", "1", "on", "True", "YES"):
            opt.set(raw)
            assert opt.value is True

    def test_boolean_false(self):
        opt = ModuleOption("B", OptionType.BOOLEAN)
        for raw in ("false", "no", "0", "off"):
            opt.set(raw)
            assert opt.value is False

    def test_boolean_bad(self):
        opt = ModuleOption("B", OptionType.BOOLEAN)
        with pytest.raises(ModuleError, match="expected boolean"):
            opt.set("maybe")

    def test_cidr_valid(self):
        opt = ModuleOption("C", OptionType.CIDR)
        opt.set("192.168.1.0/24")
        assert opt.value == "192.168.1.0/24"

    def test_cidr_invalid(self):
        opt = ModuleOption("C", OptionType.CIDR)
        with pytest.raises(ModuleError, match="invalid CIDR"):
            opt.set("not_a_cidr")

    def test_enum_valid(self):
        opt = ModuleOption("E", OptionType.ENUM, choices=["a", "b"])
        opt.set("a")
        assert opt.value == "a"

    def test_enum_invalid(self):
        opt = ModuleOption("E", OptionType.ENUM, choices=["a", "b"])
        with pytest.raises(ModuleError, match="must be one of"):
            opt.set("c")

    def test_is_set_with_default(self):
        opt = ModuleOption("X", OptionType.STRING, default="def")
        assert opt.is_set is True

    def test_is_set_without_default(self):
        opt = ModuleOption("X", OptionType.STRING, required=True)
        assert opt.is_set is False

    def test_reset(self):
        opt = ModuleOption("X", OptionType.STRING, default="def")
        opt.set("override")
        assert opt.value == "override"
        opt.reset()
        assert opt.value == "def"


# ---------------------------------------------------------------------------
# Module base class
# ---------------------------------------------------------------------------

class TestModuleBase:
    def test_instantiate(self):
        m = _DummyModule()
        assert m.name == "auxiliary/test/dummy"
        assert m.module_type == ModuleType.AUXILIARY

    def test_options_registered(self):
        m = _DummyModule()
        opts = m.options()
        assert "RHOSTS" in opts
        assert "PORT"   in opts
        assert "TIMEOUT" in opts

    def test_validate_raises_when_required_missing(self):
        m = _DummyModule()
        with pytest.raises(ModuleError, match="RHOSTS"):
            m.validate()

    def test_validate_passes_when_set(self):
        m = _DummyModule()
        m.set("RHOSTS", "10.0.0.1")
        m.validate()  # should not raise

    def test_set_unknown_option(self):
        m = _DummyModule()
        with pytest.raises(ModuleError, match="Unknown option"):
            m.set("NONEXISTENT", "value")

    def test_get_value(self):
        m = _DummyModule()
        m.set("RHOSTS", "192.168.1.1")
        assert m.get("RHOSTS") == "192.168.1.1"

    def test_get_default(self):
        m = _DummyModule()
        assert m.get("PORT") == 80

    def test_unset(self):
        m = _DummyModule()
        m.set("RHOSTS", "10.0.0.1")
        m.unset("RHOSTS")
        assert m.get("RHOSTS") is None

    def test_output_callback(self):
        m = _DummyModule()
        collected = []
        m.set_output_callback(collected.append)
        m._emit("[*] hello")
        assert "[*] hello" in collected

    def test_ok_records_result(self):
        m = _DummyModule()
        r = m._ok("found it", host="10.0.0.1")
        assert r.ok is True
        assert r.message == "found it"
        assert r.data == {"host": "10.0.0.1"}
        assert len(m.results) == 1

    def test_fail_records_result(self):
        m = _DummyModule()
        r = m._fail("timed out", host="10.0.0.2")
        assert r.ok is False
        assert len(m.results) == 1

    def test_stop(self):
        m = _DummyModule()
        assert m._stopped() is False
        m.stop()
        assert m._stopped() is True

    def test_run_returns_results(self):
        m = _DummyModule()
        m.set("RHOSTS", "10.0.0.1")
        results = m.run()
        assert len(results) == 1
        assert results[0].ok is True

    def test_info_dict(self):
        m = _DummyModule()
        d = m.info()
        assert d["name"] == "auxiliary/test/dummy"
        assert d["type"] == "auxiliary"
        assert "RHOSTS" in d["options"]

    def test_repr(self):
        m = _DummyModule()
        assert "auxiliary/test/dummy" in repr(m)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

class TestModuleHelpers:
    def test_expand_cidr_returns_ips(self):
        m = _DummyModule()
        ips = list(m.expand_cidr("10.0.0.0/30"))
        # /30 has 2 host addresses
        assert "10.0.0.1" in ips
        assert "10.0.0.2" in ips

    def test_expand_cidr_single_ip(self):
        m = _DummyModule()
        ips = list(m.expand_cidr("10.0.0.5"))
        assert ips == ["10.0.0.5"]

    def test_module_result_str(self):
        r = ModuleResult(ok=True, message="open port")
        assert "[+]" in str(r)

    def test_module_result_fail_str(self):
        r = ModuleResult(ok=False, message="timeout")
        assert "[-]" in str(r)
