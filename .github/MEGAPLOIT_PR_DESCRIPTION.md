# fix: C agent ↔ C2 server connection stack — four critical bugs fixed

## Summary

The C agent never established a session with the Megaploit C2 server.
This PR fixes four independent bugs that each caused every connection to
be rejected, updates the operator-facing documentation, and bumps the
C-remote-shell submodule to its own companion PR.

**Companion PR (C agent):**
https://github.com/Levon-Volodin/C-remote-shell/pull/10

---

## Bugs Fixed

### 1 — TLS never enabled by default (`megaploit/server/cli.py`)

The C agent performs a SChannel TLS handshake unconditionally before
any HMAC exchange. `_start_listener()` only enabled TLS when `--tls` or
`--cert`/`--key` flags were supplied. Without them, the raw socket received
the agent's TLS `ClientHello`, read those bytes as an HMAC response — they
never matched — and logged `REJECTED reason=auth_failed` on every attempt.
The agent retried every 60 seconds, always failing.

**Fix:** `_start_listener()` now always auto-generates a self-signed cert
at `loot/tls/megaploit.crt` on first run and reuses it on subsequent starts.
The `--tls` flag is still accepted but is no longer required.

---

### 2 — `crs_build` compiled the wrong source files (`plugins/c_remote_shell.py`)

`_client_srcs` listed the plain source files (`spoof.c`, `syscall.c`,
`evasion.c`, `handlers_system.c`, `handlers_lateral.c`) instead of the
`*_obf.c` variants that replace them in the current build layout. The
resulting binary had all DLL and API name strings in plaintext in `.rdata`.
Additionally, `sandbox.c` and `sleep_obf.c` were absent from the list,
so the build failed to link sandbox detection and obfuscated sleep.

**Fix:** `_client_srcs` updated to exactly mirror `CLIENT_SRCS` in the Makefile.

---

### 3 — `secret.key` key mismatch between server and submodule (`plugins/c_remote_shell.py`)

`crs_build` wrote the freshly generated key only to `./secret.key`
(Megaploit repo root). `C-remote-shell/secret.key` kept the stale key
from the previous session. Any agent built with `make` inside the submodule
used the old key; the server used the new one. Every connection produced
`REJECTED reason=auth_failed`.

**Fix:** Key is now written atomically to both `./secret.key` and
`C-remote-shell/secret.key` in a single `crs_build` call.

---

### 4 — MinGW link missing `-liphlpapi` (`plugins/c_remote_shell.py`)

The MinGW `libs` list in `crs_build` omitted `-liphlpapi` (IP Helper API),
required by `GetAdaptersInfo`, `GetIpNetTable2`, and related calls in
`handlers_system.c`. The link either failed or produced a binary that
crashed at runtime on any network-enumeration verb (`netstat`, `arp`,
`ifconfig`, `routes`).

**Fix:** Added `-liphlpapi` to the MinGW libs list to match `MINGW_LIBS`
in the Makefile exactly.

---

## Files Changed

| File | Change |
|---|---|
| `megaploit/server/cli.py` | `_start_listener()` always auto-generates TLS cert; `--tls` flag optional |
| `megaploit/server/listener.py` | `LISTEN`/`ACCEPTED`/`REJECTED`/`BLOCKED` audit log entries added |
| `plugins/c_remote_shell.py` | `_client_srcs` fixed to `*_obf.c` + `sandbox.c` + `sleep_obf.c`; dual key write; `-liphlpapi` |
| `docs/QUICKSTART.md` | Section 4 rewritten: correct `server.py` command, TLS-always-on, `--cert`/`--key`, `--allow-ip` |
| `docs/TROUBLESHOOTING.md` | Section 4 expanded to 10 steps with audit log table, key-mismatch fix, TLS failure guide, `DBG=1` bypass; Section 12 rewritten |
| `C-remote-shell` | Submodule bumped to `fix/c-agent-connect-and-hardening` |
| `tests/test_meterp.py` | GPU-safe pyautogui mock in screenshot stream test |

---

## Testing

- `python server.py -lh <ip> -p 4444` — TLS auto-cert generated, listener starts
- C agent (built with `mingw32-make C2_IP=<ip> SECRET_KEY=<hex>`) connects — `ACCEPTED` appears in `loot/audit.log`
- `crs_probe` compliance check: all 30 required signals pass
- `pytest tests/test_protocol.py tests/test_improvements.py tests/test_commands.py tests/test_jobs.py` — 128 tests pass

---

## Checklist

- [x] Audit log now records LISTEN / ACCEPTED / REJECTED for every connection attempt
- [x] TLS auto-cert reuses existing cert — no cert churn on server restart
- [x] `ALLOW_PLAINTEXT_FALLBACK=False` (default) still enforced; auto-cert does not weaken this
- [x] Both `secret.key` locations written in sync by `crs_build`
- [x] `crs_build` source list mirrors Makefile exactly — verified against `CLIENT_SRCS`
- [x] Docs updated: QUICKSTART, TROUBLESHOOTING, C-remote-shell README
- [x] 128 existing tests pass, no new failures
