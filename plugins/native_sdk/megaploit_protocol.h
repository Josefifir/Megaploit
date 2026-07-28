/*
 * megaploit_protocol.h  —  Megaploit C2 wire-protocol for native (C/C++) plugins
 * ================================================================================
 *
 * Drop this single header into your project; no other dependency is needed for
 * the plain-TCP framing layer.  AES-256-GCM encryption is optional and requires
 * OpenSSL (see MEGAPLOIT_USE_OPENSSL below).
 *
 * Wire layout (matches megaploit/core/protocol.py exactly)
 * ---------------------------------------------------------
 *
 *  Every message:
 *
 *    ┌─────────────────────────────────────────────────────────┐
 *    │  4 bytes  │  big-endian uint32  │  total payload length │
 *    ├─────────────────────────────────────────────────────────┤
 *    │  payload  │  see below          │  <length> bytes       │
 *    └─────────────────────────────────────────────────────────┘
 *
 *  Encrypted payload (v2, AES-256-GCM):
 *
 *    ┌──────────────────────────────────────────────────────────────────────┐
 *    │  12 bytes nonce  │  N bytes AES-GCM ciphertext  │  16 bytes auth tag │
 *    └──────────────────────────────────────────────────────────────────────┘
 *
 *  Plaintext (inside encryption, or raw when unencrypted):
 *
 *    ┌───────────────────────────────────────────────────────────┐
 *    │  8 bytes uint64 big-endian seq  │  JSON-encoded content   │
 *    └───────────────────────────────────────────────────────────┘
 *
 *  File-transfer messages use the same outer frame but carry raw bytes after
 *  the 8-byte sequence prefix (no JSON encoding).
 *
 * Protocol handshake (v1 / v2 negotiation)
 * -----------------------------------------
 *  1. TCP connect → HMAC-SHA256 challenge/response (server sends 16 random bytes,
 *     client replies with HMAC-SHA256(key, challenge)).
 *  2. Server sends one byte: 0x4D ('M') = v2 encrypted, 0x00 = v1 plaintext.
 *     Client echoes it back.
 *  3. If v2: both sides derive the AES-256-GCM cipher from the shared key.
 *
 * Typical session loop
 * ---------------------
 *  loop:
 *    recv_msg(conn)          → string command from operator
 *    … process command …
 *    send_msg(conn, result)  → JSON string reply
 *
 * Usage
 * ------
 *  Plain TCP (no encryption):
 *    #include "megaploit_protocol.h"
 *    mp_conn_t c = {.fd = sock_fd, .encrypted = 0};
 *
 *  With AES-256-GCM (requires OpenSSL):
 *    #define MEGAPLOIT_USE_OPENSSL
 *    #include "megaploit_protocol.h"
 *    mp_conn_t c = {.fd = sock_fd, .encrypted = 1};
 *    mp_init_gcm(&c, key_32_bytes);
 *
 * License: same as Megaploit (see project root).
 */

#pragma once

#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#ifdef _WIN32
#  include <winsock2.h>
#  pragma comment(lib, "ws2_32.lib")
   typedef SOCKET mp_fd_t;
#  define MP_SEND(fd,b,n)  send((fd),(const char*)(b),(int)(n),0)
#  define MP_RECV(fd,b,n)  recv((fd),(char*)(b),(int)(n),0)
#  define MP_CLOSE(fd)     closesocket(fd)
#else
#  include <unistd.h>
#  include <sys/socket.h>
#  include <arpa/inet.h>
   typedef int mp_fd_t;
#  define MP_SEND(fd,b,n)  send((fd),(b),(n),0)
#  define MP_RECV(fd,b,n)  recv((fd),(b),(n),0)
#  define MP_CLOSE(fd)     close(fd)
#endif

/* ── Optional OpenSSL AES-256-GCM ──────────────────────────────────────── */
#ifdef MEGAPLOIT_USE_OPENSSL
#  include <openssl/evp.h>
#  include <openssl/rand.h>
#endif

/* ── Protocol constants ─────────────────────────────────────────────────── */
#define MP_HDR_LEN    4          /* outer 4-byte big-endian length prefix    */
#define MP_SEQ_LEN    8          /* 8-byte big-endian uint64 sequence stamp  */
#define MP_NONCE_LEN  12         /* AES-GCM nonce                            */
#define MP_TAG_LEN    16         /* AES-GCM authentication tag               */
#define MP_KEY_LEN    32         /* AES-256 key length                       */
#define MP_V2_MAGIC   0x4D       /* 'M' — encrypted v2 handshake byte       */

/*
 * MP_MAX_MSG — hard cap on a single framed payload (must match
 * MAX_PLUGIN_MSG_SIZE in megaploit/core/config.py).
 *
 * 256 MiB accommodates:
 *   - large C/C++ plugin output blobs
 *   - screenshot JPEG frames  (~200–400 KB at quality 85)
 *   - zip / timelapse archives transferred in one shot
 * Any frame header advertising more than this is rejected immediately
 * to prevent memory exhaustion from a malformed or hostile peer.
 */
#define MP_MAX_MSG    (256*1024*1024)   /* 256 MiB — matches config.py      */

/* ── TLS buffer sizing (C agent, raw OpenSSL or manual record parsing) ──── */
/*
 * Use these when allocating recv/send buffers around SSL_read / SSL_write,
 * or when parsing TLS records directly on the raw socket.
 *
 * The server's cipher suite (ECDHE+AESGCM / ECDHE+CHACHA20) forces an
 * ephemeral ECDH key exchange on every connection, which means the server
 * sends a coalesced flight of:
 *   ServerHello       ~  80 B
 *   Certificate       ~1900 B  (RSA-4096 self-signed DER)
 *   ServerKeyExchange ~ 400 B  (ECDHE public key + RSA-4096 signature)
 *   ServerHelloDone      4 B
 *                   ────────
 *   Total           ~2400 B   → TLS_BUF_SERVER_FLIGHT (8 KiB) is safe
 *
 * RFC 5246 §6.2.1 caps any single TLS record at 2^14 = 16 384 bytes.
 * Use TLS_BUF_RECORD for any recv() that may read a full record at once.
 */
#define TLS_BUF_RECORD        16384   /* RFC 5246 §6.2.1 hard cap per record */
#define TLS_BUF_SERVER_FLIGHT  8192   /* largest inbound handshake burst      */
#define TLS_BUF_CLIENT_HELLO   1024   /* ClientHello with all extensions      */
#define C2_APP_BUF            65536   /* post-handshake C2 frames (= BUFFER_SIZE in config.py) */

/* ── Connection state ──────────────────────────────────────────────────── */
typedef struct {
    mp_fd_t  fd;
    int      encrypted;          /* 1 = AES-GCM active, 0 = plaintext        */
    uint8_t  key[MP_KEY_LEN];    /* AES-256 key (zero when plaintext)        */
    uint64_t send_seq;           /* monotonic outgoing sequence counter      */
    int64_t  recv_seq;           /* last accepted incoming seq (-1 = none)   */
} mp_conn_t;

/* ── Error codes ───────────────────────────────────────────────────────── */
#define MP_OK          0
#define MP_ERR_IO     -1
#define MP_ERR_OOM    -2
#define MP_ERR_REPLAY -3
#define MP_ERR_CRYPTO -4
#define MP_ERR_TOOBIG -5

/* ======================================================================== */
/* Low-level I/O helpers                                                     */
/* ======================================================================== */

static inline int mp_recv_exactly(mp_fd_t fd, uint8_t *buf, size_t n) {
    size_t got = 0;
    while (got < n) {
        int r = (int)MP_RECV(fd, buf + got, (int)(n - got));
        if (r <= 0) return MP_ERR_IO;
        got += (size_t)r;
    }
    return MP_OK;
}

static inline int mp_send_all(mp_fd_t fd, const uint8_t *buf, size_t n) {
    size_t sent = 0;
    while (sent < n) {
        int r = (int)MP_SEND(fd, buf + sent, (int)(n - sent));
        if (r <= 0) return MP_ERR_IO;
        sent += (size_t)r;
    }
    return MP_OK;
}

/* Big-endian helpers (avoid relying on ntohl for 64-bit) */
static inline uint32_t mp_be32(const uint8_t *b) {
    return ((uint32_t)b[0]<<24)|((uint32_t)b[1]<<16)|
           ((uint32_t)b[2]<<8)|(uint32_t)b[3];
}
static inline void mp_put_be32(uint8_t *b, uint32_t v) {
    b[0]=(uint8_t)(v>>24); b[1]=(uint8_t)(v>>16);
    b[2]=(uint8_t)(v>>8);  b[3]=(uint8_t)v;
}
static inline uint64_t mp_be64(const uint8_t *b) {
    uint64_t v = 0;
    for (int i = 0; i < 8; i++) v = (v<<8)|b[i];
    return v;
}
static inline void mp_put_be64(uint8_t *b, uint64_t v) {
    for (int i = 7; i >= 0; i--) { b[i]=(uint8_t)(v&0xFF); v>>=8; }
}

/* ======================================================================== */
/* AES-256-GCM (only compiled when MEGAPLOIT_USE_OPENSSL is defined)         */
/* ======================================================================== */

#ifdef MEGAPLOIT_USE_OPENSSL

static inline int mp_gcm_encrypt(
    const uint8_t *key, const uint8_t *nonce,
    const uint8_t *plain, size_t plain_len,
    uint8_t *out,   /* must be plain_len + MP_TAG_LEN bytes */
    size_t  *out_len)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return MP_ERR_CRYPTO;
    int ok = 1;
    int len = 0;
    ok &= EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
    ok &= EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, MP_NONCE_LEN, NULL);
    ok &= EVP_EncryptInit_ex(ctx, NULL, NULL, key, nonce);
    ok &= EVP_EncryptUpdate(ctx, out, &len, plain, (int)plain_len);
    int total = len;
    ok &= EVP_EncryptFinal_ex(ctx, out + total, &len);
    total += len;
    ok &= EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, MP_TAG_LEN, out + total);
    EVP_CIPHER_CTX_free(ctx);
    if (!ok) return MP_ERR_CRYPTO;
    *out_len = (size_t)total + MP_TAG_LEN;
    return MP_OK;
}

static inline int mp_gcm_decrypt(
    const uint8_t *key, const uint8_t *nonce,
    const uint8_t *ct_tag, size_t ct_tag_len,
    uint8_t *out, size_t *out_len)
{
    if (ct_tag_len < MP_TAG_LEN) return MP_ERR_CRYPTO;
    size_t ct_len = ct_tag_len - MP_TAG_LEN;
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return MP_ERR_CRYPTO;
    int ok = 1, len = 0;
    ok &= EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
    ok &= EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, MP_NONCE_LEN, NULL);
    ok &= EVP_DecryptInit_ex(ctx, NULL, NULL, key, nonce);
    ok &= EVP_DecryptUpdate(ctx, out, &len, ct_tag, (int)ct_len);
    int total = len;
    /* set expected tag */
    ok &= EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, MP_TAG_LEN,
                               (void*)(ct_tag + ct_len));
    ok &= EVP_DecryptFinal_ex(ctx, out + total, &len);
    EVP_CIPHER_CTX_free(ctx);
    if (!ok) return MP_ERR_CRYPTO;
    *out_len = (size_t)total + len;
    return MP_OK;
}

#endif /* MEGAPLOIT_USE_OPENSSL */

/* ======================================================================== */
/* Framed send / recv                                                         */
/* ======================================================================== */

/*
 * mp_send_frame — send <payload_len> bytes from <payload> as a single
 * framed message (4-byte length header + body).
 */
static inline int mp_send_frame(mp_conn_t *c,
                                 const uint8_t *payload, size_t payload_len)
{
    uint8_t hdr[MP_HDR_LEN];
    mp_put_be32(hdr, (uint32_t)payload_len);
    int r = mp_send_all(c->fd, hdr, MP_HDR_LEN);
    if (r != MP_OK) return r;
    return mp_send_all(c->fd, payload, payload_len);
}

/*
 * mp_recv_frame — read one framed message.
 *
 * Allocates *out (caller must free()).  Sets *out_len on success.
 * Returns MP_OK or a negative error code.
 */
static inline int mp_recv_frame(mp_conn_t *c, uint8_t **out, size_t *out_len) {
    uint8_t hdr[MP_HDR_LEN];
    int r = mp_recv_exactly(c->fd, hdr, MP_HDR_LEN);
    if (r != MP_OK) return r;
    uint32_t length = mp_be32(hdr);
    if (length == 0) { *out = NULL; *out_len = 0; return MP_OK; }
    if (length > MP_MAX_MSG) return MP_ERR_TOOBIG;
    uint8_t *buf = (uint8_t*)malloc(length);
    if (!buf) return MP_ERR_OOM;
    r = mp_recv_exactly(c->fd, buf, length);
    if (r != MP_OK) { free(buf); return r; }
    *out = buf; *out_len = length;
    return MP_OK;
}

/* ======================================================================== */
/* High-level send / recv (JSON strings)                                      */
/* ======================================================================== */

/*
 * mp_send_msg — JSON-encode <json_str> (a nul-terminated C string), prepend
 * an 8-byte sequence stamp, optionally encrypt, and send as a frame.
 *
 * This mirrors Python's send_msg() exactly.
 */
static inline int mp_send_msg(mp_conn_t *c, const char *json_str) {
    size_t json_len = strlen(json_str);
    size_t plain_len = MP_SEQ_LEN + json_len;

    uint8_t *plain = (uint8_t*)malloc(plain_len);
    if (!plain) return MP_ERR_OOM;

    c->send_seq += 1;
    mp_put_be64(plain, c->send_seq);
    memcpy(plain + MP_SEQ_LEN, json_str, json_len);

    int ret = MP_OK;

#ifdef MEGAPLOIT_USE_OPENSSL
    if (c->encrypted) {
        uint8_t nonce[MP_NONCE_LEN];
        RAND_bytes(nonce, MP_NONCE_LEN);
        size_t ct_len = plain_len + MP_TAG_LEN;
        uint8_t *frame = (uint8_t*)malloc(MP_NONCE_LEN + ct_len);
        if (!frame) { free(plain); return MP_ERR_OOM; }
        memcpy(frame, nonce, MP_NONCE_LEN);
        size_t actual = 0;
        ret = mp_gcm_encrypt(c->key, nonce, plain, plain_len,
                              frame + MP_NONCE_LEN, &actual);
        if (ret == MP_OK)
            ret = mp_send_frame(c, frame, MP_NONCE_LEN + actual);
        free(frame);
        free(plain);
        return ret;
    }
#endif

    ret = mp_send_frame(c, plain, plain_len);
    free(plain);
    return ret;
}

/*
 * mp_recv_msg — read one framed message, decrypt if needed, verify the
 * sequence number, and return a heap-allocated nul-terminated JSON string.
 *
 * Caller must free() *out.
 * Returns MP_OK on success or a negative error code.
 */
static inline int mp_recv_msg(mp_conn_t *c, char **out) {
    uint8_t *raw = NULL;
    size_t   raw_len = 0;
    int r = mp_recv_frame(c, &raw, &raw_len);
    if (r != MP_OK) return r;

    uint8_t *plain = raw;
    size_t   plain_len = raw_len;

#ifdef MEGAPLOIT_USE_OPENSSL
    if (c->encrypted) {
        if (raw_len < MP_NONCE_LEN + MP_TAG_LEN) { free(raw); return MP_ERR_CRYPTO; }
        uint8_t *dec = (uint8_t*)malloc(raw_len);
        if (!dec) { free(raw); return MP_ERR_OOM; }
        size_t dec_len = 0;
        r = mp_gcm_decrypt(c->key, raw,              /* nonce = first 12 bytes */
                            raw + MP_NONCE_LEN,
                            raw_len - MP_NONCE_LEN,
                            dec, &dec_len);
        free(raw); raw = NULL;
        if (r != MP_OK) { free(dec); return r; }
        plain = dec; plain_len = dec_len;
    }
#endif

    if (plain_len < MP_SEQ_LEN) { free(plain); return MP_ERR_IO; }

    uint64_t seq = mp_be64(plain);

    /* Replay protection: seq must be strictly greater than last accepted */
    if (c->recv_seq >= 0 && (int64_t)seq <= c->recv_seq) {
        free(plain);
        return MP_ERR_REPLAY;
    }
    c->recv_seq = (int64_t)seq;

    size_t   json_len = plain_len - MP_SEQ_LEN;
    char    *str      = (char*)malloc(json_len + 1);
    if (!str) { free(plain); return MP_ERR_OOM; }
    memcpy(str, plain + MP_SEQ_LEN, json_len);
    str[json_len] = '\0';
    free(plain);

    *out = str;
    return MP_OK;
}

/*
 * mp_init — initialise a connection state struct.
 * Call before the first send/recv.  key may be NULL for plaintext.
 */
static inline void mp_init(mp_conn_t *c, mp_fd_t fd,
                            int encrypted, const uint8_t *key)
{
    memset(c, 0, sizeof(*c));
    c->fd        = fd;
    c->encrypted = encrypted;
    c->send_seq  = 0;
    c->recv_seq  = -1;
    if (encrypted && key)
        memcpy(c->key, key, MP_KEY_LEN);
}
