"""
megaploit.toolbox.installer
~~~~~~~~~~~~~~~~~~~~~~~~~~~
Clone any GitHub repository, detect its language, build it with the correct
toolchain, install dependencies, and register it in the ToolRegistry.

Supported languages & build flows
----------------------------------
Python     requirements.txt   → venv + pip install
           setup.py / pyproject.toml → venv + pip install .
Go         go.mod             → go build ./...   (produces binary in repo root)
Rust       Cargo.toml         → cargo build --release
Node.js    package.json       → npm install
Ruby       Gemfile            → gem install bundler + bundle install
Java       pom.xml            → mvn package -q
           build.gradle       → gradle build -q
Bash/Shell *.sh at root       → chmod +x, run directly
PowerShell *.ps1 at root      → run with powershell/pwsh
C/C++      Makefile / CMake   → make / cmake + make
Unknown    bare binary        → chmod +x entry, run directly

All language-specific tools are run with `shutil.which` guards so a missing
toolchain produces a clear error instead of a cryptic subprocess failure.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from typing import Callable, Optional

from megaploit.toolbox.registry import (
    Tool, registry, TOOLS_DIR,
    LANG_PYTHON, LANG_GO, LANG_RUST, LANG_NODE,
    LANG_RUBY, LANG_JAVA, LANG_BASH, LANG_POWERSHELL,
    LANG_BINARY, LANG_UNKNOWN,
)

ProgressFn = Callable[[str], None]
_NOOP: ProgressFn = lambda _: None


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def install(
    repo_url: str,
    name: str,
    description: str = "",
    entry: str = "",
    tags: Optional[list[str]] = None,
    progress: ProgressFn = _NOOP,
) -> Tool:
    """
    Clone *repo_url* into tools/<name>, detect language, build, register.

    Returns the registered Tool.  Raises RuntimeError on failure.
    """
    dest = os.path.join(TOOLS_DIR, name)

    if os.path.isdir(dest):
        raise RuntimeError(f"Tool '{name}' is already installed at {dest}")

    _require("git")
    progress(f"[*] Cloning {repo_url} → {dest}")
    _git_clone(repo_url, dest, progress)

    # 1. Detect language
    lang = detect_language(dest)
    progress(f"[*] Detected language: {lang}")

    # 2. Build / install deps
    run_cmd = build(dest, name, lang, progress)

    # 3. Detect / override entry-point
    if not entry:
        entry = detect_entry(dest, name, lang)
        progress(f"[*] Entry-point: {entry}")

    tool = Tool(
        name=name,
        repo=repo_url,
        description=description or _infer_description(dest),
        entry=entry,
        lang=lang,
        run_cmd=run_cmd,
        tags=tags or [],
    )
    registry.add(tool)
    progress(f"[+] '{name}' installed and registered.")
    return tool


def uninstall(name: str, progress: ProgressFn = _NOOP) -> None:
    tool = registry.get(name)
    if not tool:
        raise RuntimeError(f"Tool '{name}' not found in registry")
    if os.path.isdir(tool.path):
        shutil.rmtree(tool.path)
        progress(f"[+] Removed {tool.path}")
    registry.remove(name)
    progress(f"[+] '{name}' unregistered.")


def update(name: str, progress: ProgressFn = _NOOP) -> None:
    """git pull + rebuild."""
    tool = registry.get(name)
    if not tool:
        raise RuntimeError(f"Tool '{name}' not found in registry")
    if not os.path.isdir(tool.path):
        raise RuntimeError(f"Tool directory not found: {tool.path}")
    _require("git")
    progress(f"[*] Pulling latest changes for '{name}'…")
    _run(["git", "-C", tool.path, "pull", "--ff-only"], progress)
    # Re-run build to pick up any new deps / recompile
    progress(f"[*] Rebuilding '{name}'…")
    tool.run_cmd = build(tool.path, name, tool.lang, progress)
    registry.add(tool)   # persist updated run_cmd
    progress(f"[+] '{name}' updated.")


# ---------------------------------------------------------------------------
# Language detection
# ---------------------------------------------------------------------------

def detect_language(repo_dir: str) -> str:
    """
    Inspect the repo root for well-known project files and return a lang ID.
    Order matters — check the most specific signals first.
    """
    files = set(os.listdir(repo_dir))

    # Python
    if any(f in files for f in ("requirements.txt", "setup.py", "pyproject.toml", "setup.cfg")):
        return LANG_PYTHON
    if any(f.endswith(".py") for f in files):
        return LANG_PYTHON

    # Go
    if "go.mod" in files or "go.sum" in files:
        return LANG_GO

    # Rust
    if "Cargo.toml" in files:
        return LANG_RUST

    # Node.js
    if "package.json" in files:
        return LANG_NODE

    # Ruby
    if "Gemfile" in files or any(f.endswith(".rb") for f in files):
        return LANG_RUBY

    # Java
    if "pom.xml" in files or "build.gradle" in files or "build.gradle.kts" in files:
        return LANG_JAVA

    # PowerShell
    if any(f.endswith(".ps1") for f in files):
        return LANG_POWERSHELL

    # Bash / Shell
    if any(f.endswith(".sh") for f in files):
        return LANG_BASH

    # C/C++ with build system
    if "Makefile" in files or "CMakeLists.txt" in files:
        return LANG_BINARY   # compile it

    # Pre-built binary or unknown
    return LANG_UNKNOWN


# ---------------------------------------------------------------------------
# Per-language build
# ---------------------------------------------------------------------------

def build(repo_dir: str, name: str, lang: str, progress: ProgressFn) -> list[str]:
    """
    Build/install the tool and return the *run_cmd* template list.
    Uses {entry} as a placeholder for the entry_path resolved at runtime.

    Returns a command list understood by Tool.resolved_run_cmd().
    """
    if lang == LANG_PYTHON:
        return _build_python(repo_dir, name, progress)

    elif lang == LANG_GO:
        return _build_go(repo_dir, name, progress)

    elif lang == LANG_RUST:
        return _build_rust(repo_dir, name, progress)

    elif lang == LANG_NODE:
        return _build_node(repo_dir, progress)

    elif lang == LANG_RUBY:
        return _build_ruby(repo_dir, progress)

    elif lang == LANG_JAVA:
        return _build_java(repo_dir, progress)

    elif lang == LANG_BASH:
        return _build_bash(repo_dir, name, progress)

    elif lang == LANG_POWERSHELL:
        return _build_powershell(repo_dir, name, progress)

    elif lang == LANG_BINARY:
        return _build_binary(repo_dir, name, progress)

    else:
        progress(f"[!] Unknown language — skipping build step.")
        return ["{entry}"]


# ---------------------------------------------------------------------------
# Language-specific builders
# ---------------------------------------------------------------------------

def _build_python(repo_dir: str, name: str, progress: ProgressFn) -> list[str]:
    python = sys.executable
    venv_dir = os.path.join(repo_dir, ".venv")

    # Prefer venv isolation
    try:
        _run([python, "-m", "venv", venv_dir], progress)
        venv_py = _venv_python(venv_dir)
        _run([venv_py, "-m", "pip", "install", "-q", "--upgrade", "pip"], progress)

        # Install in priority order
        for spec in (
            ("requirements.txt",  [venv_py, "-m", "pip", "install", "-q", "-r", os.path.join(repo_dir, "requirements.txt")]),
            ("pyproject.toml",    [venv_py, "-m", "pip", "install", "-q", "."]),
            ("setup.py",          [venv_py, "-m", "pip", "install", "-q", "."]),
        ):
            fname, cmd = spec
            if os.path.isfile(os.path.join(repo_dir, fname)):
                _run(cmd, progress)
                break

        progress(f"[+] Python venv ready: {venv_dir}")
        return [venv_py, "{entry}"]

    except RuntimeError:
        progress(f"[!] venv failed — falling back to --user install")
        req = os.path.join(repo_dir, "requirements.txt")
        if os.path.isfile(req):
            _run([python, "-m", "pip", "install", "-q", "--user", "-r", req], progress)
        return [python, "{entry}"]


def _build_go(repo_dir: str, name: str, progress: ProgressFn) -> list[str]:
    _require_or_warn("go", "Go is not installed — tool may not work")
    if shutil.which("go"):
        _run(["go", "build", "-v", "./..."], progress, cwd=repo_dir)
        progress(f"[+] Go build complete")
        # Look for the produced binary
        binary = _find_binary(repo_dir, name)
        if binary:
            os.chmod(binary, 0o755)
            return [binary]
    return ["{entry}"]


def _build_rust(repo_dir: str, name: str, progress: ProgressFn) -> list[str]:
    _require_or_warn("cargo", "Rust/cargo is not installed — tool may not work")
    if shutil.which("cargo"):
        _run(["cargo", "build", "--release"], progress, cwd=repo_dir)
        progress(f"[+] Rust build complete")
        binary = os.path.join(repo_dir, "target", "release", name)
        if sys.platform == "win32":
            binary += ".exe"
        if os.path.isfile(binary):
            return [binary]
    return ["{entry}"]


def _build_node(repo_dir: str, progress: ProgressFn) -> list[str]:
    _require_or_warn("npm", "Node.js/npm is not installed — tool may not work")
    if shutil.which("npm"):
        _run(["npm", "install", "--prefix", repo_dir, "--silent"], progress)
        progress(f"[+] npm install complete")
    # Prefer npx to run arbitrary scripts
    main_js = _detect_node_entry(repo_dir)
    node_bin = shutil.which("node") or "node"
    return [node_bin, "{entry}"]


def _build_ruby(repo_dir: str, progress: ProgressFn) -> list[str]:
    _require_or_warn("ruby", "Ruby is not installed — tool may not work")
    if shutil.which("gem") and os.path.isfile(os.path.join(repo_dir, "Gemfile")):
        if not shutil.which("bundle"):
            _run(["gem", "install", "bundler", "--quiet"], progress)
        _run(["bundle", "install", "--quiet"], progress, cwd=repo_dir)
        progress(f"[+] bundle install complete")
    ruby_bin = shutil.which("ruby") or "ruby"
    return [ruby_bin, "{entry}"]


def _build_java(repo_dir: str, progress: ProgressFn) -> list[str]:
    files = set(os.listdir(repo_dir))
    if "pom.xml" in files:
        _require_or_warn("mvn", "Maven is not installed — tool may not work")
        if shutil.which("mvn"):
            _run(["mvn", "package", "-q", "-DskipTests"], progress, cwd=repo_dir)
            progress(f"[+] Maven build complete")
    elif any(f.startswith("build.gradle") for f in files):
        gradle = "./gradlew" if os.path.isfile(os.path.join(repo_dir, "gradlew")) else "gradle"
        _require_or_warn("java", "Java is not installed — tool may not work")
        if shutil.which("java"):
            _run([gradle, "build", "-q"], progress, cwd=repo_dir)
            progress(f"[+] Gradle build complete")
    java_bin = shutil.which("java") or "java"
    # Find the first jar in target/ or build/libs/
    jar = _find_jar(repo_dir)
    if jar:
        return [java_bin, "-jar", jar]
    return [java_bin, "-jar", "{entry}"]


def _build_bash(repo_dir: str, name: str, progress: ProgressFn) -> list[str]:
    entry = _detect_shell_entry(repo_dir, name, ".sh")
    if entry:
        full = os.path.join(repo_dir, entry)
        os.chmod(full, 0o755)
        progress(f"[+] Marked {entry} executable")
    bash_bin = shutil.which("bash") or "bash"
    return [bash_bin, "{entry}"]


def _build_powershell(repo_dir: str, name: str, progress: ProgressFn) -> list[str]:
    ps = shutil.which("pwsh") or shutil.which("powershell")
    if not ps:
        progress(f"[!] PowerShell not found — tool may not work on this OS")
        ps = "pwsh"
    return [ps, "-ExecutionPolicy", "Bypass", "-File", "{entry}"]


def _build_binary(repo_dir: str, name: str, progress: ProgressFn) -> list[str]:
    """Try make/cmake, then fall back to chmod on any detected binary."""
    files = set(os.listdir(repo_dir))
    if "CMakeLists.txt" in files and shutil.which("cmake"):
        build_dir = os.path.join(repo_dir, "_build")
        os.makedirs(build_dir, exist_ok=True)
        _run(["cmake", ".."], progress, cwd=build_dir)
        _run(["make", "-j4"], progress, cwd=build_dir)
        progress(f"[+] CMake build complete")
    elif "Makefile" in files and shutil.which("make"):
        _run(["make"], progress, cwd=repo_dir)
        progress(f"[+] make complete")

    binary = _find_binary(repo_dir, name)
    if binary:
        os.chmod(binary, 0o755)
        return [binary]
    return ["{entry}"]


# ---------------------------------------------------------------------------
# Entry-point detection per language
# ---------------------------------------------------------------------------

def detect_entry(repo_dir: str, name: str, lang: str) -> str:
    """Return the relative path to the tool's main entry-point."""
    if lang == LANG_PYTHON:
        return _detect_python_entry(repo_dir, name)
    elif lang == LANG_GO:
        binary = _find_binary(repo_dir, name)
        if binary:
            return os.path.relpath(binary, repo_dir)
        return "main.go"
    elif lang == LANG_RUST:
        binary = os.path.join("target", "release", name + (".exe" if sys.platform == "win32" else ""))
        return binary if os.path.isfile(os.path.join(repo_dir, binary)) else "src/main.rs"
    elif lang == LANG_NODE:
        return _detect_node_entry(repo_dir)
    elif lang == LANG_RUBY:
        return _detect_any_entry(repo_dir, [name + ".rb", "main.rb", "app.rb", "cli.rb"], ".rb")
    elif lang == LANG_JAVA:
        jar = _find_jar(repo_dir)
        return os.path.relpath(jar, repo_dir) if jar else "pom.xml"
    elif lang in (LANG_BASH, LANG_UNKNOWN):
        return _detect_shell_entry(repo_dir, name, ".sh") or name + ".sh"
    elif lang == LANG_POWERSHELL:
        return _detect_shell_entry(repo_dir, name, ".ps1") or name + ".ps1"
    elif lang == LANG_BINARY:
        binary = _find_binary(repo_dir, name)
        return os.path.relpath(binary, repo_dir) if binary else name
    return name


def _detect_python_entry(repo_dir: str, name: str) -> str:
    candidates = [f"{name}.py", "main.py", "cli.py", "run.py", "__main__.py"]
    for c in candidates:
        if os.path.isfile(os.path.join(repo_dir, c)):
            return c
    for f in sorted(os.listdir(repo_dir)):
        if f.endswith(".py") and not f.startswith("_"):
            return f
    return "main.py"


def _detect_node_entry(repo_dir: str) -> str:
    pkg = os.path.join(repo_dir, "package.json")
    if os.path.isfile(pkg):
        try:
            import json
            with open(pkg) as f:
                data = json.load(f)
            main = data.get("main") or data.get("bin")
            if isinstance(main, str):
                return main
            if isinstance(main, dict):
                return next(iter(main.values()), "index.js")
        except Exception:
            pass
    for candidate in ("index.js", "cli.js", "main.js", "app.js"):
        if os.path.isfile(os.path.join(repo_dir, candidate)):
            return candidate
    return "index.js"


def _detect_any_entry(repo_dir: str, candidates: list[str], ext: str) -> str:
    for c in candidates:
        if os.path.isfile(os.path.join(repo_dir, c)):
            return c
    for f in sorted(os.listdir(repo_dir)):
        if f.endswith(ext) and not f.startswith("_"):
            return f
    return candidates[0] if candidates else f"main{ext}"


def _detect_shell_entry(repo_dir: str, name: str, ext: str) -> str:
    return _detect_any_entry(repo_dir, [name + ext, "main" + ext, "run" + ext], ext)


def _find_binary(repo_dir: str, name: str) -> str:
    """Return path to a native executable in the repo root or common build dirs."""
    suffix = ".exe" if sys.platform == "win32" else ""
    candidates = [
        os.path.join(repo_dir, name + suffix),
        os.path.join(repo_dir, "target", "release", name + suffix),
        os.path.join(repo_dir, "_build", name + suffix),
        os.path.join(repo_dir, "build", name + suffix),
        os.path.join(repo_dir, "bin", name + suffix),
        os.path.join(repo_dir, "dist", name + suffix),
    ]
    for c in candidates:
        if os.path.isfile(c):
            return c
    # Any executable in the root
    for f in sorted(os.listdir(repo_dir)):
        full = os.path.join(repo_dir, f)
        if os.path.isfile(full) and os.access(full, os.X_OK) and "." not in f:
            return full
    return ""


def _find_jar(repo_dir: str) -> str:
    for sub in ("target", os.path.join("build", "libs")):
        d = os.path.join(repo_dir, sub)
        if os.path.isdir(d):
            for f in sorted(os.listdir(d)):
                if f.endswith(".jar") and "sources" not in f and "javadoc" not in f:
                    return os.path.join(d, f)
    return ""


# ---------------------------------------------------------------------------
# Shared subprocess helper
# ---------------------------------------------------------------------------

def _git_clone(url: str, dest: str, progress: ProgressFn) -> None:
    _run(["git", "clone", "--depth=1", "--recurse-submodules", url, dest], progress)


def _run(cmd: list[str], progress: ProgressFn, cwd: Optional[str] = None) -> None:
    """Stream subprocess output to *progress*. Raises RuntimeError on non-zero exit."""
    proc = subprocess.Popen(
        cmd,
        cwd=cwd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    for line in proc.stdout:
        progress(line.rstrip())
    proc.wait()
    if proc.returncode != 0:
        raise RuntimeError(f"Command failed (exit {proc.returncode}): {' '.join(str(c) for c in cmd)}")


def _venv_python(venv_dir: str) -> str:
    if sys.platform == "win32":
        return os.path.join(venv_dir, "Scripts", "python.exe")
    return os.path.join(venv_dir, "bin", "python")


def _require(cmd: str) -> None:
    if shutil.which(cmd) is None:
        raise RuntimeError(
            f"'{cmd}' is not installed or not on PATH.\n"
            f"Install it and try again."
        )


def _require_or_warn(cmd: str, msg: str) -> None:
    """Emit a warning if *cmd* is missing; does NOT raise — build continues."""
    if shutil.which(cmd) is None:
        print(f"[!] {msg}", flush=True)


def _infer_description(repo_dir: str) -> str:
    for fname in ("README.md", "README.rst", "README.txt", "readme.md"):
        path = os.path.join(repo_dir, fname)
        if os.path.isfile(path):
            try:
                with open(path, "r", encoding="utf-8", errors="replace") as f:
                    for line in f:
                        line = line.strip()
                        # Skip headings, badges, HTML, dividers — but keep normal prose
                        if line and not line.startswith(("#", "!", "<", "=")):
                            # Strip leading Markdown link/image syntax like [![...](...)
                            if line.startswith("[!") or line.startswith("[!["):
                                continue
                            if len(line) > 10:
                                return line[:120]
            except OSError:
                pass
    return "(no description)"
