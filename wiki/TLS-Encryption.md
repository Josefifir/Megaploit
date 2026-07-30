# TLS Encryption

All C2 traffic is protected by AES-256-GCM with HMAC-SHA256 authentication. TLS adds an additional transport layer.

## Startup

```bash
python3 server.py -lh 10.0.0.1 -p 4444 --tls
```

## Console commands

```
megaploit [0] » tls auto           # generate self-signed cert and enable now
megaploit [0] » tls status         # show cert path and SHA-256 fingerprint
megaploit [0] » tls regen          # force-regenerate (rotate cert)

megaploit [0] » set cert /path/to/cert.pem
megaploit [0] » set key  /path/to/key.pem
```

## Agent payloads

```
megaploit [0] » generate --tls
megaploit [0] » payload ps1 --tls --out agent.ps1
megaploit [0] » payload exe --tls --out agent.exe
```

## Key exchange

The shared `secret.key` is used for HMAC-SHA256 authentication before the session is established. Generate a unique key per engagement:

```bash
python3 -c "import os,binascii; open('secret.key','wb').write(binascii.hexlify(os.urandom(32)))"
```
