# Malleable C2 Profile Reference

> **NEW in v3.0** — `megaploit/core/profile.py`

## Overview

A **C2 Profile** shapes the network appearance of Megaploit's C2 channel to evade IDS/IPS and blend into normal traffic. Operators create a YAML (or JSON) file describing HTTP headers, URI rotation, beacon timing, and metadata encoding. The profile is loaded at runtime and used by agents and the transport layer.

---

## Profile File Format (YAML)

```yaml
name: "WindowsUpdate"
description: "Mimic Windows Update traffic"

# Beacon timing
sleep:      60       # base interval in seconds
jitter_max: 15       # random jitter added to sleep (uniform 0..jitter_max)

# URI rotation — agents cycle through these paths
uri_paths:
  - "/windowsupdate/v9/selfupdate/AU/x86/XP/en/au.cab"
  - "/msdownload/update/v3/static/trustedr/en/authrootstl.cab"
  - "/windowsupdate/redir/v6/muv4wuredir.cab"

# HTTP headers injected into every agent→server request
request_headers:
  Host: "update.microsoft.com"
  User-Agent: "Windows-Update-Agent/10.0.10011.16384 Client-Protocol/1.21"
  Accept: "*/*"
  Connection: "Keep-Alive"
  Cache-Control: "no-cache"

# HTTP headers the server returns
response_headers:
  Content-Type: "application/octet-stream"
  Server: "Microsoft-IIS/10.0"
  X-Powered-By: "ASP.NET"

# Metadata encoding — where the agent identifier is hidden
metadata:
  prepend:  "Cookie: "
  append:   ""
  location: "header"   # "header" | "uri" | "body"
```

> **Note:** PyYAML is optional. If not installed, profiles can also be written as plain JSON — the loader falls back to `json.loads` automatically.

---

## CLI Usage

There is no dedicated CLI command for profiles yet. Load and apply them from Python or scripts:

```python
from megaploit.core.profile import load_profile

profile = load_profile("profiles/windows_update.yaml")
print(profile)
# <C2Profile 'WindowsUpdate'  sleep=60.0s jitter=15.0s  uri_paths=3>
```

---

## Python API

### Loading a profile

```python
from megaploit.core.profile import load_profile, default_profile

# Load from file:
profile = load_profile("profiles/dropbox.yaml")

# Use the built-in default (no traffic shaping):
from megaploit.core.profile import default_profile
```

### `C2Profile` methods

#### `next_uri() → str`
Returns a randomly chosen URI path from `uri_paths`.

```python
uri = profile.next_uri()   # e.g. "/windowsupdate/v9/selfupdate/..."
```

#### `uri_cycle() → Iterator[str]`
Endlessly cycles through URI paths in random shuffled order.

```python
for path in profile.uri_cycle():
    # make a request, then sleep
    time.sleep(profile.sleep_with_jitter())
```

#### `sleep_with_jitter() → float`
Returns `sleep + random.uniform(0, jitter_max)` seconds. Does **not** block.

```python
delay = profile.sleep_with_jitter()   # e.g. 67.3 (for sleep=60, jitter_max=15)
time.sleep(delay)
```

#### `wait() → None`
Blocks for `sleep_with_jitter()` seconds.

```python
profile.wait()   # equivalent to: time.sleep(profile.sleep_with_jitter())
```

#### `build_http_headers(extra=None) → dict`
Returns the full request header dict, with `User-Agent` auto-populated from `user_agent` if not already in `request_headers`. Merges with `extra` dict.

```python
headers = profile.build_http_headers(extra={"Authorization": "Bearer token123"})
```

#### `to_dict() → dict`
Returns a serialisable dict for export or inspection.

---

## `C2Profile` Fields

| Field | Type | Default | Description |
|---|---|---|---|
| `name` | str | `"default"` | Profile identifier |
| `description` | str | `""` | Human-readable description |
| `sleep` | float | `5.0` | Base beacon interval (seconds) |
| `jitter_max` | float | `2.0` | Maximum random jitter added to sleep |
| `uri_paths` | list[str] | `["/"]` | Rotating URI paths |
| `request_headers` | dict | `{}` | HTTP headers to inject in requests |
| `response_headers` | dict | `{}` | HTTP headers returned by server |
| `user_agent` | str | Chrome UA | User-Agent string |
| `metadata_prepend` | str | `""` | String prepended to encoded metadata |
| `metadata_append` | str | `""` | String appended to encoded metadata |
| `metadata_location` | str | `"header"` | Where metadata appears: `header`, `uri`, `body` |

---

## Example Profiles

### Dropbox API

```yaml
name: "DropboxAPI"
sleep: 30
jitter_max: 8

uri_paths:
  - "/2/files/list_folder"
  - "/2/files/download"
  - "/2/files/upload"

request_headers:
  Host: "api.dropboxapi.com"
  User-Agent: "OfficialDropboxPythonSDK/11.36.0"
  Content-Type: "application/json"
  Authorization: "Bearer sl.placeholder"

response_headers:
  Content-Type: "application/json"
  Server: "nginx"
```

### Office 365 / Microsoft Graph

```yaml
name: "MSGraph"
sleep: 45
jitter_max: 12

uri_paths:
  - "/v1.0/me/messages"
  - "/v1.0/me/mailFolders/inbox/messages"
  - "/v1.0/me/drive/root/children"

request_headers:
  Host: "graph.microsoft.com"
  User-Agent: "Microsoft Graph Client Library for Python/1.0.0"
  Accept: "application/json"
  Content-Type: "application/json"
```

### Minimal (bare TCP, no HTTP shaping)

```json
{
  "name": "bare",
  "sleep": 5,
  "jitter_max": 2,
  "uri_paths": ["/"]
}
```

---

## Implementation Notes

- Profiles are **advisory** — they describe the desired traffic appearance. The actual transport layer (TCP, TLS, WebSocket) must be separately configured. The profile provides metadata that agents and custom transport wrappers read.
- `load_profile` raises `FileNotFoundError` if the file is missing and `ValueError` if it cannot be parsed.
- `_from_dict(data)` is exported for programmatic profile construction without a file.
- The `_source_path` attribute stores the file path (set by `load_profile`; not part of `to_dict()`).
