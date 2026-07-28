/*
 * plugins/native_sdk/example_plugin.cpp
 * ========================================
 * Minimal native Megaploit plugin written in C++.
 *
 * What it does
 * -------------
 * This plugin is invoked by the operator as a regular CLI command.
 * It receives its arguments as argv[1..N], does its work, prints results
 * to stdout (which the runner captures and streams back), then exits.
 *
 * This particular example does a basic TCP port probe (argv[1]=host,
 * argv[2]=port) entirely without touching Python — useful for demonstrating
 * that C/C++ native code integrates cleanly with the rest of Megaploit.
 *
 * Compile manually (optional — the runner does this automatically):
 *   g++ -std=c++17 -O2 example_plugin.cpp -o example_plugin
 *   # Windows (MinGW):
 *   g++ -std=c++17 -O2 example_plugin.cpp -o example_plugin.exe -lws2_32
 *
 * Wire-protocol note
 * -------------------
 * When a native plugin is invoked by the runner it acts as a LOCAL tool —
 * it does NOT talk to the C2 server socket directly.  Its stdout is piped
 * back to the operator console.
 *
 * If you want a native *agent* (a client that connects to the C2 server and
 * runs the full command loop), see the section at the bottom of this file
 * and include megaploit_protocol.h.  The critical points to implement
 * correctly so the server accepts your client are:
 *
 *   1. HMAC-SHA256 challenge/response  (send 16-byte challenge → agent replies
 *      with HMAC-SHA256(key, challenge))
 *   2. Protocol-version byte: read 1 byte; echo it back.  'M' (0x4D) = v2
 *      encrypted.  0x00 = v1 plain.
 *   3. If v2: init AES-256-GCM with the shared 32-byte key.
 *   4. Frame format: [4-byte big-endian length][payload]
 *      Payload = [8-byte big-endian sequence number][JSON-encoded string]
 *      (or nonce+ciphertext+tag when encrypted — see megaploit_protocol.h)
 *   5. Sequence numbers are strictly monotonic.  The server REJECTS any
 *      message whose seq is ≤ the last accepted seq (replay protection).
 *      Start at seq=1 (increment before each send, start recv_seq at -1).
 *   6. JSON encoding: every command/response is a JSON *string* value, not
 *      a JSON object.  Use `json.dumps(string)` equivalent — the JSON payload
 *      is the quoted string itself, e.g. `"ls -la"` or `"[+] result here"`.
 *
 * These are the exact rules the Python protocol.py enforces, so anything
 * that follows them — C, C++, C#, Rust, Go — is fully compatible.
 */

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>

#ifdef _WIN32
#  include <winsock2.h>
#  include <ws2tcpip.h>
#  pragma comment(lib, "ws2_32.lib")
#  define CLOSE_SOCK closesocket
   typedef SOCKET sock_t;
#else
#  include <sys/socket.h>
#  include <netdb.h>
#  include <unistd.h>
#  include <fcntl.h>
#  include <sys/time.h>
#  define CLOSE_SOCK close
   typedef int sock_t;
   constexpr sock_t INVALID_SOCKET = -1;
#endif

/* ── Helper: set a socket timeout (seconds) ───────────────────────────── */
static void set_timeout(sock_t s, int secs) {
#ifdef _WIN32
    DWORD ms = (DWORD)(secs * 1000);
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char*)&ms, sizeof(ms));
    setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, (const char*)&ms, sizeof(ms));
#else
    struct timeval tv = { secs, 0 };
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
#endif
}

/* ── Probe a single TCP host:port ─────────────────────────────────────── */
static bool tcp_probe(const char *host, const char *port_str, int timeout_secs) {
    struct addrinfo hints{}, *res = nullptr;
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    if (getaddrinfo(host, port_str, &hints, &res) != 0 || !res)
        return false;

    sock_t s = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (s == INVALID_SOCKET) { freeaddrinfo(res); return false; }

    set_timeout(s, timeout_secs);
    bool connected = (connect(s, res->ai_addr, (int)res->ai_addrlen) == 0);

    CLOSE_SOCK(s);
    freeaddrinfo(res);
    return connected;
}

/* ── Entry point ─────────────────────────────────────────────────────── */
int main(int argc, char *argv[]) {
#ifdef _WIN32
    WSADATA wd;
    WSAStartup(MAKEWORD(2,2), &wd);
#endif

    if (argc < 3) {
        fprintf(stderr, "Usage: example_plugin <host> <port> [timeout_secs]\n");
        return 1;
    }

    const char *host      = argv[1];
    const char *port_str  = argv[2];
    int         timeout   = (argc >= 4) ? atoi(argv[3]) : 3;

    bool open = tcp_probe(host, port_str, timeout);
    printf("[%s] %s:%s is %s\n",
           open ? "+" : "-",
           host, port_str,
           open ? "OPEN" : "CLOSED/FILTERED");

#ifdef _WIN32
    WSACleanup();
#endif
    return open ? 0 : 1;
}

/* =========================================================================
 * APPENDIX — skeleton for a full native C2 agent (standalone client)
 * =========================================================================
 *
 * To write a native agent that connects to the Megaploit server and speaks
 * the full wire protocol, structure your code exactly like main.go does.
 * Here is a minimal pseudocode sketch using megaploit_protocol.h:
 *
 *   #define MEGAPLOIT_USE_OPENSSL   // if you have OpenSSL for AES-GCM
 *   #include "megaploit_protocol.h"
 *   #include <openssl/hmac.h>
 *
 *   // 1. Connect
 *   int fd = tcp_connect(LHOST, PORT);
 *
 *   // 2. HMAC-SHA256 challenge/response
 *   uint8_t challenge[16];
 *   recv_exactly(fd, challenge, 16);
 *   uint8_t response[32];
 *   HMAC(EVP_sha256(), key, 32, challenge, 16, response, NULL);
 *   send(fd, response, 32, 0);
 *
 *   // 3. Protocol version handshake
 *   uint8_t ver;
 *   recv_exactly(fd, &ver, 1);
 *   send(fd, &ver, 1, 0);   // echo back
 *   int use_v2 = (ver == MP_V2_MAGIC);
 *
 *   // 4. Init connection state
 *   mp_conn_t conn;
 *   mp_init(&conn, fd, use_v2, key);
 *
 *   // 5. Command loop
 *   while (1) {
 *       char *cmd = NULL;
 *       if (mp_recv_msg(&conn, &cmd) != MP_OK) break;
 *
 *       char *result = handle_command(cmd);   // your logic here
 *       free(cmd);
 *
 *       // Response must be a JSON string: wrap in double-quotes and
 *       // escape any internal quotes.
 *       char json_result[4096];
 *       snprintf(json_result, sizeof(json_result), "\"%s\"", result);
 *       mp_send_msg(&conn, json_result);
 *       free(result);
 *   }
 *
 * Key pitfalls that will cause the Python server to reject your client:
 *
 *   ✗  Sending raw text without the 8-byte sequence header.
 *   ✗  Sending a JSON object/array instead of a JSON *string*.
 *   ✗  Reusing a sequence number (replay protection will drop the message).
 *   ✗  Wrong byte-order for the 4-byte length or 8-byte seq (must be
 *      big-endian, matching Python's struct.pack("!I") / struct.pack("!Q")).
 *   ✗  AES-GCM nonce placed AFTER the ciphertext instead of before it.
 *   ✗  Forgetting the 16-byte GCM authentication tag in the ciphertext blob.
 */
