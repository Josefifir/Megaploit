# Plugin System

Drop a `.toml` (or `.json`) file into `plugins/` to add custom commands — no Python required.

> **v4.2.0 security note:** Remote plugin loading (`load_url`) is disabled by default. Pass `allow_remote=True` explicitly to permit it (see [Remote loading](#remote-loading) below).

## Example plugin

```toml
[plugin]
name    = "my-plugin"
version = "1.0.0"
author  = "you"

[[command]]
name    = "portscan"
kind    = "local"
shell   = "nmap -sV -p {arg0:-1-1000} {session_ip}"
timeout = 120
```

## Plugin commands

```
megaploit [0] » plugins                    # list loaded plugins
megaploit [0] » plugins reload             # hot-reload plugins/ directory
megaploit [0] » plugins info <name>        # show plugin details
megaploit [0] » plugins watcher on         # auto-reload on file change
megaploit [0] » plugins disable <name>     # disable a plugin
megaploit [0] » plugins enable <name>      # re-enable a plugin
```

## Command kinds

| Kind | Description |
|---|---|
| `local` | Run a shell command on the operator machine |
| `session` | Send a command to the active agent session |
| `python` | Call a Python function (dotted import path) |
| `native` | Compile and run a C/C++ source file |

## Placeholders

| Placeholder | Value |
|---|---|
| `{session_ip}` | IP of the current session |
| `{session_id}` | Numeric session ID |
| `{session_tag}` | Operator tag |
| `{session_os}` | OS name |
| `{lhost}` | Operator LHOST setting |
| `{port}` | Operator PORT setting |
| `{arg0}..{argN}` | Positional CLI args |
| `{joined_args}` | All args joined with spaces |

## C-remote-shell Plugin

Integrates the hardened Windows C agent (SChannel TLS, BCrypt AES-256-GCM):

```
megaploit [0] » crs_build       # compile Windows EXE
megaploit [0] » crs_probe       # run 46-check C2 compliance report
megaploit [0] » crs_verbs       # list all wire verbs

megaploit session(1) » forceOff     # force power-off via NtSetSystemPowerState ⚠
megaploit session(1) » blueScreen   # trigger BSOD via NtRaiseHardError ⚠
```

## Remote loading

Load a plugin directly from a URL:

```python
# Disabled by default — must opt in explicitly
plugin_loader.load_url("https://example.com/plugin.toml", allow_remote=True)
```

From the console there is no built-in remote-load command — remote loading is an API-level feature intentionally gated behind `allow_remote=True` to prevent implicit network fetches from untrusted sources.

## Path traversal protection

Native (`kind = "native"`) plugin `source_file` paths are resolved to an absolute path and must stay inside the `plugins/` directory. Any path that escapes `plugins/` (e.g. `../../etc/passwd`) raises `PluginTrustError` and is never compiled.
