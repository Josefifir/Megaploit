"""
megaploit.web.rpc
~~~~~~~~~~~~~~~~~
Multi-operator JSON-RPC 2.0 server over TCP (line-delimited JSON).

Allows multiple Megaploit operators to connect to the same C2 server,
share session data, exchange chat messages, and collaborate on notes
in real time.

Protocol
--------
Each message is a JSON line terminated with ``\\n``.

Requests  (client → server)::

    {"jsonrpc": "2.0", "id": 1, "method": "sessions.list", "params": {}}
    {"jsonrpc": "2.0", "id": 2, "method": "chat.send",
     "params": {"message": "hello"}}
    {"jsonrpc": "2.0", "id": 3, "method": "notes.add",
     "params": {"session_id": 1, "text": "found creds"}}
    {"jsonrpc": "2.0", "id": 4, "method": "session.cmd",
     "params": {"session_id": 1, "cmd": "sysinfo"}}

Notifications  (server → all clients)::

    {"jsonrpc": "2.0", "method": "event",
     "params": {"type": "new_session", "session_id": 2, "ip": "10.0.0.5"}}
    {"jsonrpc": "2.0", "method": "event",
     "params": {"type": "chat", "operator": "alice", "message": "hello"}}
    {"jsonrpc": "2.0", "method": "event",
     "params": {"type": "note_added", "session_id": 1, "text": "found creds"}}

Available methods
-----------------
  auth                  — authenticate with API key, set display name
  sessions.list         — list active sessions
  sessions.get          — get one session detail
  session.cmd           — send command to session, get output
  chat.send             — broadcast chat message to all operators
  chat.history          — last N chat messages
  notes.add             — add a note to a session
  notes.list            — list notes for a session
  creds.list            — list credential store
  jobs.list             — list background jobs
  operators.list        — list connected operators
  ping                  — keep-alive
"""

from __future__ import annotations

import datetime
import json
import socket
import threading
import uuid
from collections import deque
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

__all__ = ["RpcServer", "rpc_server"]


# ---------------------------------------------------------------------------
# Chat history
# ---------------------------------------------------------------------------

_CHAT_HISTORY: deque[dict] = deque(maxlen=500)


# ---------------------------------------------------------------------------
# Operator connection
# ---------------------------------------------------------------------------

@dataclass
class Operator:
    """Represents one connected operator."""
    conn_id:  str
    sock:     socket.socket
    addr:     tuple
    name:     str                = "anonymous"
    auth_ok:  bool               = False
    _lock:    threading.Lock     = field(default_factory=threading.Lock, repr=False)

    def send(self, obj: dict) -> None:
        """Thread-safe JSON line send."""
        try:
            line = json.dumps(obj, default=str) + "\n"
            with self._lock:
                self.sock.sendall(line.encode())
        except Exception:
            pass

    def send_error(self, req_id: Any, code: int, message: str) -> None:
        self.send({
            "jsonrpc": "2.0",
            "id":      req_id,
            "error":   {"code": code, "message": message},
        })

    def send_result(self, req_id: Any, result: Any) -> None:
        self.send({"jsonrpc": "2.0", "id": req_id, "result": result})

    def send_notification(self, method: str, params: dict) -> None:
        self.send({"jsonrpc": "2.0", "method": method, "params": params})

    def __repr__(self) -> str:
        return f"<Operator {self.name}@{self.addr}>"


# ---------------------------------------------------------------------------
# RPC Server
# ---------------------------------------------------------------------------

class RpcServer:
    """
    Multi-operator JSON-RPC 2.0 server.

    Parameters
    ----------
    sessions_ref  : dict[int, Session]  — shared sessions dict
    sessions_lock : threading.Lock
    host          : str                 — bind address
    port          : int                 — default 7777
    api_key       : str                 — required for auth
    """

    def __init__(
        self,
        sessions_ref:  dict,
        sessions_lock: threading.Lock,
        host:    str = "127.0.0.1",
        port:    int = 7777,
        api_key: str = "",
    ) -> None:
        self._sessions  = sessions_ref
        self._sess_lock = sessions_lock
        self._host      = host
        self._port      = port
        self._api_key   = api_key
        self._operators: dict[str, Operator] = {}
        self._op_lock   = threading.Lock()
        self._server_sock: Optional[socket.socket] = None
        self._running   = False

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def start(self) -> None:
        """Start the RPC listener in a daemon thread."""
        self._running = True
        t = threading.Thread(target=self._accept_loop, daemon=True, name="rpc-server")
        t.start()

    def stop(self) -> None:
        self._running = False
        if self._server_sock:
            try:
                self._server_sock.close()
            except Exception:
                pass

    # ------------------------------------------------------------------
    # Accept loop
    # ------------------------------------------------------------------

    def _accept_loop(self) -> None:
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((self._host, self._port))
        srv.listen(20)
        srv.settimeout(1.0)
        self._server_sock = srv

        while self._running:
            try:
                conn, addr = srv.accept()
            except socket.timeout:
                continue
            except Exception:
                break

            op = Operator(
                conn_id=str(uuid.uuid4())[:8],
                sock=conn,
                addr=addr,
            )
            with self._op_lock:
                self._operators[op.conn_id] = op

            t = threading.Thread(
                target=self._handle_operator,
                args=(op,),
                daemon=True,
                name=f"rpc-op-{op.conn_id}",
            )
            t.start()

    # ------------------------------------------------------------------
    # Per-operator handler
    # ------------------------------------------------------------------

    def _handle_operator(self, op: Operator) -> None:
        buf = b""
        op.sock.settimeout(120)
        try:
            while self._running:
                try:
                    chunk = op.sock.recv(4096)
                except socket.timeout:
                    continue
                if not chunk:
                    break
                buf += chunk
                while b"\n" in buf:
                    line, buf = buf.split(b"\n", 1)
                    self._dispatch(op, line.strip())
        finally:
            with self._op_lock:
                self._operators.pop(op.conn_id, None)
            try:
                op.sock.close()
            except Exception:
                pass
            # Notify others
            self._broadcast_notification("event", {
                "type":     "operator_left",
                "operator": op.name,
                "ts":       _now(),
            }, exclude=op.conn_id)

    # ------------------------------------------------------------------
    # Dispatcher
    # ------------------------------------------------------------------

    def _dispatch(self, op: Operator, raw: bytes) -> None:
        try:
            req = json.loads(raw.decode())
        except Exception:
            op.send_error(None, -32700, "Parse error")
            return

        req_id = req.get("id")
        method = req.get("method", "")
        params = req.get("params") or {}

        # Auth gate
        if method != "auth" and not op.auth_ok:
            op.send_error(req_id, -32001, "Not authenticated — call auth first")
            return

        handler = self._methods.get(method)
        if handler is None:
            op.send_error(req_id, -32601, f"Method not found: {method}")
            return

        try:
            result = handler(self, op, params)
            op.send_result(req_id, result)
        except RpcError as exc:
            op.send_error(req_id, exc.code, exc.message)
        except Exception as exc:
            op.send_error(req_id, -32603, str(exc))

    # ------------------------------------------------------------------
    # Broadcast helpers
    # ------------------------------------------------------------------

    def _broadcast_notification(
        self, method: str, params: dict, exclude: str = ""
    ) -> None:
        with self._op_lock:
            ops = list(self._operators.values())
        for op in ops:
            if op.conn_id != exclude and op.auth_ok:
                op.send_notification(method, params)

    # ------------------------------------------------------------------
    # RPC method implementations
    # ------------------------------------------------------------------

    def _m_auth(self, op: Operator, params: dict) -> dict:
        key  = params.get("api_key", "")
        name = params.get("name", "anonymous")[:32]
        if self._api_key and key != self._api_key:
            raise RpcError(-32001, "Invalid API key")
        op.auth_ok = True
        op.name    = name
        self._broadcast_notification("event", {
            "type":     "operator_joined",
            "operator": name,
            "ts":       _now(),
        }, exclude=op.conn_id)
        with self._op_lock:
            n_ops = len(self._operators)
        return {"authenticated": True, "operator_count": n_ops}

    def _m_ping(self, op: Operator, params: dict) -> str:
        return "pong"

    def _m_sessions_list(self, op: Operator, params: dict) -> list:
        with self._sess_lock:
            slist = list(self._sessions.values())
        return [_sess_dict(s) for s in slist]

    def _m_sessions_get(self, op: Operator, params: dict) -> dict:
        sid = int(params.get("session_id", -1))
        with self._sess_lock:
            s = self._sessions.get(sid)
        if s is None:
            raise RpcError(-32002, f"Session {sid} not found")
        return _sess_dict(s)

    def _m_session_cmd(self, op: Operator, params: dict) -> dict:
        sid = int(params.get("session_id", -1))
        cmd = str(params.get("cmd", ""))
        if not cmd:
            raise RpcError(-32602, "cmd parameter required")
        with self._sess_lock:
            s = self._sessions.get(sid)
        if s is None:
            raise RpcError(-32002, f"Session {sid} not found")
        try:
            from megaploit.server.commands import dispatch
            result = dispatch(s, cmd)
            return {"ok": result.ok, "output": result.output}
        except Exception as exc:
            raise RpcError(-32603, str(exc))

    def _m_chat_send(self, op: Operator, params: dict) -> dict:
        msg = str(params.get("message", ""))[:500]
        if not msg:
            raise RpcError(-32602, "message required")
        entry = {"operator": op.name, "message": msg, "ts": _now()}
        _CHAT_HISTORY.append(entry)
        self._broadcast_notification("event", {"type": "chat", **entry})
        return {"sent": True}

    def _m_chat_history(self, op: Operator, params: dict) -> list:
        n = min(int(params.get("n", 50)), 500)
        return list(_CHAT_HISTORY)[-n:]

    def _m_notes_add(self, op: Operator, params: dict) -> dict:
        sid  = int(params.get("session_id", -1))
        text = str(params.get("text", ""))[:2000]
        if not text:
            raise RpcError(-32602, "text required")
        with self._sess_lock:
            s = self._sessions.get(sid)
        if s is None:
            raise RpcError(-32002, f"Session {sid} not found")
        if hasattr(s, "notes"):
            s.notes.append(f"[{op.name}] {text}")
        self._broadcast_notification("event", {
            "type":       "note_added",
            "session_id": sid,
            "operator":   op.name,
            "text":       text,
            "ts":         _now(),
        })
        return {"added": True}

    def _m_notes_list(self, op: Operator, params: dict) -> list:
        sid = int(params.get("session_id", -1))
        with self._sess_lock:
            s = self._sessions.get(sid)
        if s is None:
            raise RpcError(-32002, f"Session {sid} not found")
        return list(getattr(s, "notes", []))

    def _m_creds_list(self, op: Operator, params: dict) -> list:
        try:
            from megaploit.db.database import db
            rows = db.get_credentials()
            for r in rows:
                if r.get("secret"):
                    r["secret"] = r["secret"][:4] + "…"
            return rows
        except Exception:
            return []

    def _m_jobs_list(self, op: Operator, params: dict) -> list:
        try:
            from megaploit.core.jobs import job_manager
            return job_manager.list_jobs()
        except Exception:
            return []

    def _m_operators_list(self, op: Operator, params: dict) -> list:
        with self._op_lock:
            ops = list(self._operators.values())
        return [
            {"id": o.conn_id, "name": o.name, "addr": f"{o.addr[0]}:{o.addr[1]}"}
            for o in ops if o.auth_ok
        ]

    # Method dispatch table
    _methods: dict[str, Callable] = {
        "auth":            _m_auth,
        "ping":            _m_ping,
        "sessions.list":   _m_sessions_list,
        "sessions.get":    _m_sessions_get,
        "session.cmd":     _m_session_cmd,
        "chat.send":       _m_chat_send,
        "chat.history":    _m_chat_history,
        "notes.add":       _m_notes_add,
        "notes.list":      _m_notes_list,
        "creds.list":      _m_creds_list,
        "jobs.list":       _m_jobs_list,
        "operators.list":  _m_operators_list,
    }

    # ------------------------------------------------------------------

    def broadcast_event(self, event_type: str, **data: Any) -> None:
        """Push an event to all authenticated operators."""
        self._broadcast_notification("event", {
            "type": event_type,
            "ts":   _now(),
            **data,
        })

    def __repr__(self) -> str:
        n = len(self._operators)
        return f"<RpcServer  {self._host}:{self._port}  {n} operator(s)>"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

class RpcError(Exception):
    def __init__(self, code: int, message: str) -> None:
        super().__init__(message)
        self.code    = code
        self.message = message


def _now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).strftime("%H:%M:%S")


def _sess_dict(s: Any) -> dict:
    try:
        return s.to_dict()
    except AttributeError:
        return {
            "id":       getattr(s, "id", "?"),
            "ip":       getattr(s, "ip", "?"),
            "port":     getattr(s, "port", 0),
            "os_name":  getattr(s, "os_name", ""),
            "hostname": getattr(s, "hostname", ""),
            "username": getattr(s, "username", ""),
            "tag":      getattr(s, "tag", ""),
            "uptime":   getattr(s, "uptime", ""),
        }


# ---------------------------------------------------------------------------
# Singleton (configured lazily)
# ---------------------------------------------------------------------------

rpc_server: Optional[RpcServer] = None
