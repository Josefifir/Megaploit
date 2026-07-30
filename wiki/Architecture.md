# Architecture

```
server.py                    ← Operator entry point
agent.py                     ← Python agent (deploy to target)
secret.key                   ← Shared HMAC secret
megaploit/
  server/
    cli.py                   ← Interactive console
    commands.py              ← 135 session command dispatchers
    meterp_session.py        ← Meterpreter-class console
    listener.py              ← TCP/TLS accept loop
    session.py               ← Session dataclass
  agent/
    handlers.py              ← 90+ victim-side handlers
    meterp.py                ← Advanced post-exploitation handlers
    shell.py                 ← recv → handle → respond loop
    connection.py            ← Connect-back loop
    go_agent/                ← Go agent source
  modules/
    exploits/                ← 20+ exploit modules
    auxiliary/               ← 12+ scanner modules
    post/                    ← Post-exploitation modules
  payload/
    builder.py               ← 14-format payload builder
    encoders.py              ← 10-encoder pipeline
  core/
    framing.py               ← Wire framing + AES-256-GCM
    transport.py             ← Handshake, send/recv, file transfer
    websocket.py             ← WsTransport (RFC 6455)
    messages.py              ← Typed msgpack/JSON envelopes
    protocol.py              ← Re-export shim
    exceptions.py            ← Common exception hierarchy
    crypto.py                ← HMAC-SHA256 authentication
    pipeline.py              ← Post-exploitation pipeline
    autorun.py               ← AutoRunScript engine
    jobs.py                  ← Background job manager
  plugins/                   ← TOML plugin system
  toolbox/                   ← 200+ tool installer
  db/                        ← SQLite credential/loot store
  reporting/                 ← HTML/JSON report generator
  web/                       ← Flask dashboard
loot/                        ← All collected data + audit.log
plugins/                     ← TOML plugin files
tools/                       ← Installed toolbox tools
```
