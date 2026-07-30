# AutoRunScript

Automatically run commands on every new session. Commands are dispatched based on OS, hostname tag, or globally.

## Configuration file

Create `~/.megaploit_autorun.json`:

```json
{
  "global":  ["sysinfo", "whoami"],
  "windows": ["os_info", "installed_software", "ps"],
  "linux":   ["os_info", "find_suid", "env", "users"],
  "tags": {
    "dc":          ["hashdump", "users", "scheduled_tasks"],
    "workstation": ["browser_creds", "wifi_passwords", "ps"]
  }
}
```

## Commands

```
megaploit [0] » autorun show           # display current config
megaploit [0] » autorun reload         # reload from disk
megaploit [0] » autorun save-default   # write starter template
megaploit [0] » autorun test 1         # preview what would run for session 1
```
