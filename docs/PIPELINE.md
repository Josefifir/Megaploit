# Post-Exploitation Pipeline & AutoRunScript

Two complementary systems that automate actions on every new session.

---

## Overview

| System | What it does | How to configure |
|---|---|---|
| **Pipeline** | Runs a named collection profile on every new session | `pipeline enable <profile>` |
| **AutoRunScript** | Runs per-OS and per-tag command lists | Edit `~/.megaploit_autorun.json` |

Both run automatically in a background thread when a new agent connects — the operator isn't blocked.

---

## Post-Exploitation Pipeline

The pipeline runs **named profiles** on every new session. Profiles are collections of session commands that gather common data automatically.

### Enable a profile

```
megaploit [0] » pipeline enable creds
[+] Profile 'creds' enabled — will run on every new session
```

### See what's active

```
megaploit [0] » pipeline status
  Active profiles:  creds, recon
  Available:        basic, creds, recon, network, full

megaploit [0] » pipeline list
  Profile   Status    Commands
  basic     inactive  sysinfo, whoami, pwd, env
  creds     ACTIVE    hashdump, wifi_passwords, browser_creds, ssh_harvest, cred_vault
  recon     ACTIVE    ps, installed_software, scheduled_tasks, users, os_info
  network   inactive  arp, netstat, ifconfig
  full      inactive  (all of the above)
```

### Disable a profile

```
megaploit [0] » pipeline disable creds
```

### Available profiles

| Profile | Commands run automatically |
|---|---|
| `basic` | `sysinfo`, `whoami`, `pwd`, `env` |
| `creds` | `hashdump`, `wifi_passwords`, `browser_creds`, `ssh_harvest`, `cred_vault` |
| `recon` | `ps`, `installed_software`, `scheduled_tasks`, `users`, `os_info` |
| `network` | `arp`, `netstat`, `ifconfig` |
| `full` | All of the above combined |

### Example: Full automated recon + cred harvest

```
megaploit [0] » pipeline enable full
[+] Profile 'full' enabled

# Now every new agent connection automatically runs:
# sysinfo, whoami, pwd, env,
# hashdump, wifi_passwords, browser_creds, ssh_harvest, cred_vault,
# ps, installed_software, scheduled_tasks, users, os_info,
# arp, netstat, ifconfig
```

All results are saved to the credential store and loot directory automatically.

### Reload pipeline config

If you edit the AutoRunScript config file while Megaploit is running:

```
megaploit [0] » pipeline reload
```

---

## AutoRunScript

AutoRunScript gives you finer control — run different commands based on the **OS** and **session tag**.

### Config file location

```
~/.megaploit_autorun.json
```

### Create the default template

```
megaploit [0] » autorun save-default
[+] Template written to ~/.megaploit_autorun.json
```

### View current config

```
megaploit [0] » autorun show
```

### Reload from disk

```
megaploit [0] » autorun reload
```

### Preview what would run for a session

```
megaploit [0] » autorun test 1
# Shows exactly which commands would fire for session 1
```

---

## Config File Reference

```json
{
  "global":  ["sysinfo", "whoami"],
  "windows": ["os_info", "installed_software", "ps"],
  "linux":   ["os_info", "find_suid", "env", "users"],
  "macos":   ["os_info", "env"],
  "tags": {
    "dc":          ["hashdump", "users", "scheduled_tasks", "net_view"],
    "workstation": ["browser_creds", "wifi_passwords", "ps", "keylog_start"],
    "server":      ["services", "netstat", "users", "os_info"],
    "web":         ["ps", "services", "find_files /var/www config"]
  }
}
```

### Key sections

| Section | When it runs |
|---|---|
| `"global"` | On **every** new session, regardless of OS |
| `"windows"` | Only on Windows agents |
| `"linux"` | Only on Linux/Unix agents |
| `"macos"` | Only on macOS agents |
| `"tags"` | Only when the session has a matching tag |

### Execution order

1. `global` commands run first
2. OS-specific commands run next
3. Tag-specific commands run last

---

## Session Tags

Tags let you categorize sessions and trigger different autorun commands.

### Set a tag on a session

Inside the session or from global:

```
megaploit session(1) » tag dc
megaploit session(1) » tag workstation
megaploit session(1) » tag web-server
```

Or from global context (once a session has connected):

```
megaploit [3] » sessions -s dc     # find sessions tagged dc
```

### Tag-based AutoRunScript example

Config:

```json
{
  "global": ["sysinfo", "whoami"],
  "tags": {
    "dc": [
      "hashdump",
      "users",
      "net_view",
      "kiwi logonpasswords",
      "scheduled_tasks"
    ],
    "workstation": [
      "browser_creds all",
      "wifi_passwords",
      "ps",
      "screenshot",
      "keylog_start"
    ]
  }
}
```

If a session is tagged `dc`, Megaploit automatically dumps hashes, users, and domain info.
If tagged `workstation`, it automatically grabs browser credentials and starts the keylogger.

---

## Practical Scenarios

### Scenario 1 — Internal Network Assessment

You're doing an internal pentest and expect many connections from workstations and servers.
Enable automatic recon and cred harvesting:

```
megaploit [0] » pipeline enable creds
megaploit [0] » pipeline enable recon
megaploit [0] » autorun save-default
# Edit ~/.megaploit_autorun.json, then:
megaploit [0] » autorun reload
```

Config:

```json
{
  "global":  ["sysinfo", "whoami", "screenshot"],
  "windows": ["installed_software", "startup_items", "scheduled_tasks"],
  "linux":   ["find_suid", "services", "users"],
  "tags": {
    "dc":  ["hashdump", "net_view", "kiwi logonpasswords"],
    "web": ["find_files /var/www password", "cat /etc/nginx/nginx.conf"]
  }
}
```

### Scenario 2 — Quick Credential Sweep

If your only goal is to harvest credentials from as many machines as possible:

```
megaploit [0] » pipeline enable creds
```

Every new agent that connects automatically runs: `hashdump`, `wifi_passwords`, `browser_creds`, `ssh_harvest`, `cred_vault`.
All creds are saved to the SQLite store. View them later:

```
megaploit [0] » creds show
megaploit [0] » creds export all_creds.json
```

### Scenario 3 — Silent Long-Term Monitoring

Set up monitoring without actively touching each session:

```json
{
  "global": ["whoami", "screenshot"],
  "windows": ["keylog_start"],
  "linux": []
}
```

Each new session automatically takes a screenshot and starts keylogging.

```
megaploit [0] » pipeline enable basic
```

---

## What Happens When a Session Connects

1. Agent connects and authenticates (HMAC-SHA256)
2. Session is assigned an ID and added to the session table
3. Console shows `★ NEW SESSION #N ★` notification
4. Background thread starts (0.5s delay for session to stabilise)
5. Pipeline commands run in order (one at a time)
6. AutoRunScript commands run in order (global → OS → tags)
7. All results saved to loot and credential store
8. Session is ready for operator interaction

The operator is never blocked — you can interact with other sessions while pipeline runs.
