# Post-Exploitation Pipeline Reference

> **NEW in v3.0** — `megaploit/core/pipeline.py`

## Overview

The **Post-Exploitation Pipeline** extends AutoRunScript with named **collection profiles**. When a new session opens, the pipeline runs the AutoRunScript baseline **plus** all active profiles, in one unified, deduplicated command list dispatched in a daemon thread.

This means operators can type `pipeline enable creds` once and have credential collection run automatically on every future session — without editing any config files.

---

## CLI Commands

```
pipeline status           Show active profiles + available profiles
pipeline list             List all profiles with ● active / ○ inactive indicators
pipeline enable <name>    Enable a profile (takes effect on next session)
pipeline disable <name>   Disable a profile
pipeline reload           Reload ~/.megaploit_autorun.json into the pipeline
```

**Example workflow:**

```
megaploit [0] » pipeline list
  ○ basic
  ○ creds
  ○ full
  ○ network
  ○ recon

megaploit [0] » pipeline enable creds
[+] Pipeline profile creds enabled — active on next session.

megaploit [0] » pipeline enable recon
[+] Pipeline profile recon enabled — active on next session.

megaploit [0] » pipeline status

  ╭─── Post-Exploitation Pipeline ───────────────╮
  │ Active profiles   creds, recon               │
  │ Available         basic  creds  full  …      │
  ╰───────────────────────────────────────────────╯

# When session opens → runs: sysinfo (autorun) + all creds cmds + all recon cmds

megaploit [0] » pipeline disable recon
[+] Pipeline profile recon disabled.
```

---

## Built-in Profiles

| Profile | Commands |
|---|---|
| `basic` | `sysinfo`, `whoami`, `pwd`, `env` |
| `creds` | `hashdump`, `wifi_passwords`, `browser_creds`, `ssh_harvest`, `cred_vault` |
| `recon` | `ps`, `installed_software`, `scheduled_tasks`, `users`, `os_info` |
| `network` | `arp`, `netstat`, `ifconfig`, `hosts_file` |
| `full` | Union of `basic + creds + recon + network` |

---

## Execution Flow

```
Console._on_new_session(session)
    │
    ├── _pipeline.commands_for(session)
    │   ├── _autorun.commands_for(session)   ← global + platform + tag rules
    │   └── for each active profile:
    │           add profile commands not already in the list
    │   → deduplicated, ordered list
    │
    └── threading.Thread(daemon=True):
            time.sleep(0.5)                  ← wait for session to stabilise
            for cmd in cmds:
                dispatch(session, cmd)       ← send via protocol
```

The 0.5 s delay prevents commands racing before the agent's main loop is ready.

---

## Python API

```python
from megaploit.core.pipeline import Pipeline, pipeline

# Use the global singleton:
pipeline.enable_profile("creds")
pipeline.disable_profile("recon")

# Check status:
pipeline.active_profiles()        # ["creds"]
pipeline.available_profiles()     # ["basic", "creds", "full", "network", "recon"]
pipeline.is_enabled("creds")      # True

# Get commands for a session:
from unittest.mock import MagicMock
sess = MagicMock()
sess.os_name = "linux"
sess.tag = "dc"
cmds = pipeline.commands_for(sess)

# Reload autorun config from disk:
pipeline.reload_autorun()

# Summary dict:
info = pipeline.summary()
# {
#   "active_profiles": ["creds"],
#   "available_profiles": ["basic", "creds", "full", "network", "recon"],
#   "autorun": {"path": "~/.megaploit_autorun.json", "global": [...], ...}
# }

# Create an isolated instance (e.g. for testing):
p = Pipeline()
p.enable_profile("basic")
```

---

## Extending with Custom Profiles

Profiles are defined in the `_PROFILES` dict in `megaploit/core/pipeline.py`. Add a new entry:

```python
# megaploit/core/pipeline.py  (after the built-in profiles)

_PROFILES["av_evasion"] = [
    "patch_amsi",
    "disable_defender",
    "clear_logs",
]
```

The new profile appears immediately in `pipeline list` and `pipeline enable av_evasion` after a reload.

---

## Relationship with AutoRunScript

The pipeline **wraps** AutoRunScript — it does not replace it. The baseline from `~/.megaploit_autorun.json` always runs first; profile commands are appended in sorted profile order, deduplicated.

```
Final command list = deduplicate(autorun_commands + profile_commands)
```

If `sysinfo` appears in both the autorun global list and the `basic` profile, it only runs once (first occurrence wins).

---

## Thread Safety

`Pipeline._active_profiles` is a `set[str]` protected by `Pipeline._lock` (`threading.Lock`). All read/write operations go through `enable_profile`, `disable_profile`, `active_profiles`, and `commands_for` which all acquire the lock.
