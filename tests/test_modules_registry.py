"""
Unit tests for megaploit.modules.registry — ModuleRegistry.
"""
from __future__ import annotations

import os
import textwrap

import pytest

from megaploit.modules.base import Module, ModuleType
from megaploit.modules.registry import ModuleRegistry, ModuleEntry


def _write_module(directory: str, filename: str, content: str) -> str:
    """Write a module file and return its path."""
    path = os.path.join(directory, filename)
    with open(path, "w", encoding="utf-8") as f:
        f.write(textwrap.dedent(content))
    return path


class TestModuleRegistry:

    def test_reload_empty_directory(self, tmp_path):
        """Registry with no module files returns 0 loaded."""
        reg = ModuleRegistry()
        (tmp_path / "auxiliary").mkdir()
        loaded, errors = reg.reload(base_dir=str(tmp_path))
        assert loaded == 0
        assert errors == 0

    def test_loads_valid_module(self, tmp_path):
        """A well-formed module file is discovered and indexed."""
        (tmp_path / "auxiliary").mkdir()
        _write_module(str(tmp_path / "auxiliary"), "my_test.py", """
            from megaploit.modules.base import Module, ModuleType
            class _M(Module):
                name        = "auxiliary/test/my_test"
                description = "Test"
                module_type = ModuleType.AUXILIARY
            MODULE = _M
        """)
        reg = ModuleRegistry()
        loaded, errors = reg.reload(base_dir=str(tmp_path))
        assert loaded == 1
        assert errors == 0
        entry = reg.get("auxiliary/test/my_test")
        assert entry is not None
        assert entry.name == "auxiliary/test/my_test"

    def test_quarantines_file_without_MODULE(self, tmp_path):
        """A file without MODULE variable is reported as an error, not a crash."""
        (tmp_path / "auxiliary").mkdir()
        _write_module(str(tmp_path / "auxiliary"), "bad.py", """
            # No MODULE variable
            x = 1
        """)
        reg = ModuleRegistry()
        loaded, errors = reg.reload(base_dir=str(tmp_path))
        assert loaded == 0
        assert errors == 1

    def test_quarantines_syntax_error(self, tmp_path):
        """A file with a syntax error is quarantined, not loaded."""
        (tmp_path / "auxiliary").mkdir()
        _write_module(str(tmp_path / "auxiliary"), "syntax_err.py", """
            def broken(:
        """)
        reg = ModuleRegistry()
        loaded, errors = reg.reload(base_dir=str(tmp_path))
        assert loaded == 0
        assert errors == 1
        assert len(reg.errors()) == 1

    def test_skips_files_starting_with_underscore(self, tmp_path):
        """Files starting with _ are intentionally skipped."""
        (tmp_path / "auxiliary").mkdir()
        _write_module(str(tmp_path / "auxiliary"), "_private.py", """
            from megaploit.modules.base import Module, ModuleType
            class _P(Module):
                name        = "auxiliary/priv"
                module_type = ModuleType.AUXILIARY
            MODULE = _P
        """)
        reg = ModuleRegistry()
        loaded, _ = reg.reload(base_dir=str(tmp_path))
        assert loaded == 0

    def test_multiple_modules(self, tmp_path):
        """Multiple valid modules across subdirectories all load."""
        for subdir in ("auxiliary", "exploits"):
            (tmp_path / subdir).mkdir()
        _write_module(str(tmp_path / "auxiliary"), "a.py", """
            from megaploit.modules.base import Module, ModuleType
            class A(Module):
                name        = "auxiliary/a"
                module_type = ModuleType.AUXILIARY
            MODULE = A
        """)
        _write_module(str(tmp_path / "exploits"), "b.py", """
            from megaploit.modules.base import Module, ModuleType
            class B(Module):
                name        = "exploits/b"
                module_type = ModuleType.EXPLOIT
            MODULE = B
        """)
        reg = ModuleRegistry()
        loaded, _ = reg.reload(base_dir=str(tmp_path))
        assert loaded == 2
        assert reg.get("auxiliary/a") is not None
        assert reg.get("exploits/b") is not None

    def test_search_by_name(self, tmp_path):
        (tmp_path / "auxiliary").mkdir()
        _write_module(str(tmp_path / "auxiliary"), "scanner.py", """
            from megaploit.modules.base import Module, ModuleType
            class S(Module):
                name        = "auxiliary/scanner/port"
                description = "Port scanner"
                module_type = ModuleType.AUXILIARY
            MODULE = S
        """)
        reg = ModuleRegistry()
        reg.reload(base_dir=str(tmp_path))
        results = reg.search("scanner")
        assert len(results) == 1
        assert results[0].name == "auxiliary/scanner/port"

    def test_search_by_description(self, tmp_path):
        (tmp_path / "auxiliary").mkdir()
        _write_module(str(tmp_path / "auxiliary"), "smb.py", """
            from megaploit.modules.base import Module, ModuleType
            class S(Module):
                name        = "auxiliary/smb"
                description = "SMB share enumeration"
                module_type = ModuleType.AUXILIARY
            MODULE = S
        """)
        reg = ModuleRegistry()
        reg.reload(base_dir=str(tmp_path))
        results = reg.search("share")
        assert len(results) == 1

    def test_search_case_insensitive(self, tmp_path):
        (tmp_path / "auxiliary").mkdir()
        _write_module(str(tmp_path / "auxiliary"), "x.py", """
            from megaploit.modules.base import Module, ModuleType
            class X(Module):
                name        = "auxiliary/xtest"
                description = "XTEST scanner"
                module_type = ModuleType.AUXILIARY
            MODULE = X
        """)
        reg = ModuleRegistry()
        reg.reload(base_dir=str(tmp_path))
        assert len(reg.search("XTEST")) == 1
        assert len(reg.search("xtest")) == 1

    def test_by_type(self, tmp_path):
        for subdir in ("auxiliary", "exploits"):
            (tmp_path / subdir).mkdir()
        _write_module(str(tmp_path / "auxiliary"), "a.py", """
            from megaploit.modules.base import Module, ModuleType
            class A(Module):
                name = "auxiliary/a"; module_type = ModuleType.AUXILIARY
            MODULE = A
        """)
        _write_module(str(tmp_path / "exploits"), "b.py", """
            from megaploit.modules.base import Module, ModuleType
            class B(Module):
                name = "exploits/b"; module_type = ModuleType.EXPLOIT
            MODULE = B
        """)
        reg = ModuleRegistry()
        reg.reload(base_dir=str(tmp_path))
        aux = reg.by_type(ModuleType.AUXILIARY)
        exp = reg.by_type(ModuleType.EXPLOIT)
        assert len(aux) == 1 and aux[0].name == "auxiliary/a"
        assert len(exp) == 1 and exp[0].name == "exploits/b"

    def test_instantiate(self, tmp_path):
        (tmp_path / "auxiliary").mkdir()
        _write_module(str(tmp_path / "auxiliary"), "inst.py", """
            from megaploit.modules.base import Module, ModuleType
            class I(Module):
                name = "auxiliary/inst"; module_type = ModuleType.AUXILIARY
                def _define_options(self):
                    from megaploit.modules.base import OptionType
                    self._opt("HOST", OptionType.STRING, required=True)
            MODULE = I
        """)
        reg = ModuleRegistry()
        reg.reload(base_dir=str(tmp_path))
        entry = reg.get("auxiliary/inst")
        m = entry.instantiate()
        assert isinstance(m, Module)
        assert "HOST" in m.options()

    def test_get_nonexistent_returns_none(self, tmp_path):
        reg = ModuleRegistry()
        reg.reload(base_dir=str(tmp_path))
        assert reg.get("nonexistent/module") is None

    def test_count_and_names(self, tmp_path):
        (tmp_path / "auxiliary").mkdir()
        _write_module(str(tmp_path / "auxiliary"), "c1.py", """
            from megaploit.modules.base import Module, ModuleType
            class C1(Module):
                name = "auxiliary/c1"; module_type = ModuleType.AUXILIARY
            MODULE = C1
        """)
        reg = ModuleRegistry()
        reg.reload(base_dir=str(tmp_path))
        assert reg.count() == 1
        assert "auxiliary/c1" in reg.names()

    def test_built_in_modules_load(self):
        """The 8 built-in auxiliary modules must all load without errors."""
        reg = ModuleRegistry()
        loaded, errors = reg.reload()
        # We expect at least 8 from the built-in auxiliary directory
        assert loaded >= 8, f"Expected ≥8 modules, got {loaded}"
        assert errors == 0, f"Expected 0 errors, got {errors}: {reg.errors()}"
