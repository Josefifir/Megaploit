# Web Dashboard & RPC

## Web Dashboard

A live Flask dashboard with SSE streaming.

```bash
megaploit [0] » web start               # http://127.0.0.1:8080
megaploit [0] » web start --port 9090   # custom port
megaploit [0] » web stop
megaploit [0] » web status
```

## Multi-operator JSON-RPC

Share a session with multiple operators.

```bash
megaploit [0] » rpc start               # 127.0.0.1:7777
megaploit [0] » rpc start --port 8888
megaploit [0] » rpc operators           # show connected operators
megaploit [0] » rpc stop
```
