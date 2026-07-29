"""
megaploit.web.app
~~~~~~~~~~~~~~~~~
Lightweight Flask web dashboard for Megaploit.

Provides
--------
  GET  /                     — Dashboard overview (HTML)
  GET  /api/sessions         — JSON list of active sessions
  GET  /api/sessions/<id>    — JSON details of one session
  GET  /api/loot             — JSON loot file listing
  GET  /api/creds            — JSON credential store dump
  GET  /api/jobs             — JSON background job list
  GET  /api/modules          — JSON loaded module catalogue
  POST /api/sessions/<id>/cmd — Send a command to a session
  GET  /events               — Server-Sent Events stream  (live feed)

Run
---
    from megaploit.web.app import create_app, WebServer
    server = WebServer(sessions_ref, jobs_ref, port=8080)
    server.start()       # starts Flask in a daemon thread

Auth
----
A simple bearer token is required (set via ``X-API-Key`` header or
``?apikey=`` query parameter).  The token defaults to the HMAC key
fingerprint; set ``api_key`` on WebServer to override.

Dependencies
------------
  Flask ≥ 2.3   (optional — falls back gracefully if absent)
  flask-cors    (optional — for cross-origin requests)
"""

from __future__ import annotations

import json
import os
import queue
import threading
import time
from typing import Any, Optional

__all__ = ["WebServer", "create_app"]

# ---------------------------------------------------------------------------
# Flask dependency check
# ---------------------------------------------------------------------------

try:
    from flask import Flask, Response, abort, jsonify, request, stream_with_context
    _HAS_FLASK = True
except ImportError:
    _HAS_FLASK = False


# ---------------------------------------------------------------------------
# Embedded dashboard HTML  (single-page, no external assets)
# ---------------------------------------------------------------------------

_DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Megaploit Dashboard</title>
<style>
  *,*::before,*::after{box-sizing:border-box;}
  body{margin:0;font-family:-apple-system,"Segoe UI",system-ui,sans-serif;
       font-size:14px;background:#0d1117;color:#c9d1d9;line-height:1.6;}
  header{background:#161b22;padding:12px 24px;border-bottom:1px solid #30363d;
         display:flex;align-items:center;gap:16px;}
  header h1{margin:0;font-size:18px;color:#58a6ff;font-weight:700;}
  header span{color:#8b949e;font-size:12px;}
  .live-dot{width:8px;height:8px;border-radius:50%;background:#3fb950;
            box-shadow:0 0 6px #3fb950;animation:pulse 1.5s infinite;}
  @keyframes pulse{0%,100%{opacity:1;}50%{opacity:.3;}}
  main{max-width:1100px;margin:24px auto;padding:0 20px;}
  .stat-grid{display:grid;grid-template-columns:repeat(4,1fr);gap:14px;margin-bottom:28px;}
  .stat{background:#161b22;border:1px solid #30363d;border-radius:8px;
        padding:14px 18px;text-align:center;}
  .stat .n{font-size:32px;font-weight:700;color:#58a6ff;}
  .stat .l{font-size:11px;color:#8b949e;text-transform:uppercase;letter-spacing:.05em;}
  h2{color:#c9d1d9;font-size:15px;margin:0 0 10px;font-weight:600;}
  .card{background:#161b22;border:1px solid #30363d;border-radius:8px;
        padding:16px;margin-bottom:20px;}
  table{width:100%;border-collapse:collapse;font-size:13px;}
  th{background:#21262d;padding:6px 10px;text-align:left;color:#8b949e;
     font-weight:600;border-bottom:1px solid #30363d;}
  td{padding:6px 10px;border-bottom:1px solid #21262d;word-break:break-word;}
  tr:last-child td{border-bottom:none;}
  tr:hover td{background:#1c2128;}
  .badge{display:inline-block;padding:1px 7px;border-radius:12px;
         font-size:11px;font-weight:600;}
  .green{background:#033a16;color:#3fb950;}
  .red{background:#3d1c1c;color:#f85149;}
  .blue{background:#031d2d;color:#58a6ff;}
  .yellow{background:#3d3400;color:#d29922;}
  .grey{background:#21262d;color:#8b949e;}
  #events-log{max-height:200px;overflow-y:auto;font-size:12px;
              font-family:monospace;color:#8b949e;}
  #events-log p{margin:1px 0;border-bottom:1px solid #21262d;padding:2px 0;}
  footer{text-align:center;color:#484f58;font-size:11px;
         margin-top:40px;padding:12px;border-top:1px solid #21262d;}
  /* Terminal widget */
  .terminal-wrap{display:flex;gap:8px;margin-top:10px;}
  #term-input{flex:1;background:#0d1117;border:1px solid #30363d;color:#c9d1d9;
              padding:6px 10px;font-family:monospace;font-size:13px;border-radius:4px;}
  #term-btn{background:#1f6feb;color:#fff;border:none;padding:6px 14px;
            border-radius:4px;cursor:pointer;font-size:13px;}
  #term-btn:hover{background:#388bfd;}
  #term-output{background:#0d1117;border:1px solid #30363d;border-radius:4px;
               padding:10px;font-family:monospace;font-size:12px;color:#c9d1d9;
               min-height:80px;max-height:300px;overflow-y:auto;white-space:pre-wrap;
               margin-top:8px;}
  #term-sid-wrap{display:flex;align-items:center;gap:8px;margin-bottom:8px;}
  #term-sid{width:80px;background:#161b22;border:1px solid #30363d;color:#c9d1d9;
            padding:4px 8px;font-size:13px;border-radius:4px;}
</style>
</head>
<body>
<header>
  <h1>&#x1F4A3; Megaploit</h1>
  <div class="live-dot" title="Live feed active"></div>
  <span id="status-text">Connecting…</span>
</header>
<main>
  <div class="stat-grid">
    <div class="stat"><div class="n" id="n-sessions">—</div><div class="l">Sessions</div></div>
    <div class="stat"><div class="n" id="n-jobs">—</div><div class="l">Jobs</div></div>
    <div class="stat"><div class="n" id="n-creds">—</div><div class="l">Credentials</div></div>
    <div class="stat"><div class="n" id="n-loot">—</div><div class="l">Loot files</div></div>
  </div>

  <div class="card">
    <h2>Active Sessions</h2>
    <table id="sessions-table">
      <thead><tr>
        <th>#</th><th>IP:Port</th><th>OS</th><th>Hostname</th><th>User</th><th>Tag</th><th>Uptime</th>
      </tr></thead>
      <tbody id="sessions-tbody"><tr><td colspan="7" style="color:#484f58">Loading…</td></tr></tbody>
    </table>
  </div>

  <div class="card">
    <h2>&#x1F4BB; Session Terminal</h2>
    <div id="term-sid-wrap">
      <label style="color:#8b949e;font-size:12px;">Session ID:</label>
      <input id="term-sid" type="number" min="1" placeholder="1">
    </div>
    <div class="terminal-wrap">
      <input id="term-input" type="text" placeholder="Type a command and press Enter or Send…">
      <button id="term-btn">Send</button>
    </div>
    <div id="term-output" style="display:none"></div>
  </div>

  <div class="card">
    <h2>Background Jobs</h2>
    <table id="jobs-table">
      <thead><tr><th>ID</th><th>Name</th><th>Status</th><th>Started</th></tr></thead>
      <tbody id="jobs-tbody"><tr><td colspan="4" style="color:#484f58">Loading…</td></tr></tbody>
    </table>
  </div>

  <div class="card">
    <h2>Live Event Feed</h2>
    <div id="events-log"><p style="color:#484f58">Waiting for events…</p></div>
  </div>

</main>
<footer>Megaploit Web Dashboard</footer>

<script>
const API = "";  // same origin
let apiKey = new URLSearchParams(location.search).get("apikey") || "";

function hdr(){return {"X-API-Key": apiKey};}

function badge(text, color){
  return `<span class="badge ${color}">${text}</span>`;
}

function refreshSessions(){
  fetch(API+"/api/sessions",{headers:hdr()})
    .then(r=>r.json()).then(data=>{
      document.getElementById("n-sessions").textContent = data.length;
      const tbody = document.getElementById("sessions-tbody");
      if(!data.length){
        tbody.innerHTML='<tr><td colspan="7" style="color:#484f58">No active sessions</td></tr>';
        return;
      }
      tbody.innerHTML = data.map(s=>`
        <tr>
          <td>${s.id}</td>
          <td>${s.ip}:${s.port}</td>
          <td>${badge(s.os_name||"unknown","blue")}</td>
          <td>${s.hostname||"—"}</td>
          <td>${s.username||"—"}</td>
          <td>${s.tag?badge(s.tag,"yellow"):"—"}</td>
          <td>${s.uptime||"—"}</td>
        </tr>`).join("");
    }).catch(()=>{});
}

function refreshJobs(){
  fetch(API+"/api/jobs",{headers:hdr()})
    .then(r=>r.json()).then(data=>{
      document.getElementById("n-jobs").textContent = data.length;
      const tbody = document.getElementById("jobs-tbody");
      if(!data.length){
        tbody.innerHTML='<tr><td colspan="4" style="color:#484f58">No jobs</td></tr>';
        return;
      }
      tbody.innerHTML = data.map(j=>{
        const sc = j.status==="running"?"green":j.status==="completed"?"grey":"red";
        return `<tr>
          <td>${j.id}</td>
          <td>${j.name}</td>
          <td>${badge(j.status,sc)}</td>
          <td>${j.started||"—"}</td>
        </tr>`;
      }).join("");
    }).catch(()=>{});
}

function refreshCreds(){
  fetch(API+"/api/creds",{headers:hdr()})
    .then(r=>r.json())
    .then(data=>document.getElementById("n-creds").textContent=data.length)
    .catch(()=>{});
}

function refreshLoot(){
  fetch(API+"/api/loot",{headers:hdr()})
    .then(r=>r.json())
    .then(data=>document.getElementById("n-loot").textContent=data.length)
    .catch(()=>{});
}

function connectSSE(){
  const src = new EventSource(API+"/events?apikey="+encodeURIComponent(apiKey));
  src.onopen = ()=>{
    document.getElementById("status-text").textContent = "Live";
  };
  src.onerror = ()=>{
    document.getElementById("status-text").textContent = "Reconnecting…";
    setTimeout(connectSSE, 5000);
    src.close();
  };
  src.addEventListener("update", e=>{
    try{
      const d = JSON.parse(e.data);
      const log = document.getElementById("events-log");
      const p = document.createElement("p");
      p.textContent = `[${d.ts||""}] ${d.type||""}: ${d.message||""}`;
      log.prepend(p);
      if(log.children.length > 100) log.lastChild.remove();
      if(d.type==="new_session"||d.type==="session_closed") refreshSessions();
      if(d.type==="new_job"||d.type==="job_done") refreshJobs();
      if(d.type==="new_cred") refreshCreds();
      if(d.type==="new_loot") refreshLoot();
    }catch(e){}
  });
}

// Terminal widget
function sendTermCmd(){
  const sid = parseInt(document.getElementById("term-sid").value||"0");
  const cmd = document.getElementById("term-input").value.trim();
  if(!sid||!cmd) return;
  const out = document.getElementById("term-output");
  out.style.display="block";
  out.textContent += "\n$ " + cmd + "\n";
  fetch(API+"/api/sessions/"+sid+"/cmd",{
    method:"POST",
    headers:{...hdr(),"Content-Type":"application/json"},
    body:JSON.stringify({cmd:cmd})
  }).then(r=>r.json()).then(d=>{
    out.textContent += (d.output||"(no output)")+"\n";
    out.scrollTop=out.scrollHeight;
  }).catch(e=>{out.textContent+="[error] "+e+"\n";});
  document.getElementById("term-input").value="";
}
document.getElementById("term-btn").addEventListener("click",sendTermCmd);
document.getElementById("term-input").addEventListener("keydown",function(e){
  if(e.key==="Enter") sendTermCmd();
});

// Initial load + periodic refresh
refreshSessions(); refreshJobs(); refreshCreds(); refreshLoot();
setInterval(()=>{refreshSessions();refreshJobs();}, 10000);
connectSSE();
</script>
</body>
</html>
"""


# ---------------------------------------------------------------------------
# Flask application factory
# ---------------------------------------------------------------------------

def create_app(
    sessions_ref: dict,
    sessions_lock: "threading.Lock",
    api_key: str = "",
) -> "Flask":
    """
    Create and configure the Flask application.

    Parameters
    ----------
    sessions_ref   : dict[int, Session] — live sessions dict (shared reference)
    sessions_lock  : threading.Lock     — guards sessions_ref
    api_key        : str                — bearer token for API auth
    """
    if not _HAS_FLASK:
        raise ImportError("Flask is required:  pip install flask")

    app = Flask(__name__)
    app.config["SECRET_KEY"] = api_key or os.urandom(16).hex()

    # SSE event queue
    _event_queue: queue.Queue = queue.Queue(maxsize=500)

    # ------------------------------------------------------------------
    # Auth middleware
    # ------------------------------------------------------------------

    def _check_auth() -> bool:
        if not api_key:
            return True
        token = (
            request.headers.get("X-API-Key")
            or request.args.get("apikey")
            or ""
        )
        return token == api_key

    # ------------------------------------------------------------------
    # Routes
    # ------------------------------------------------------------------

    @app.route("/")
    def index():
        if not _check_auth():
            abort(401)
        return Response(_DASHBOARD_HTML, mimetype="text/html")

    @app.route("/api/sessions")
    def api_sessions():
        if not _check_auth():
            abort(401)
        with sessions_lock:
            slist = list(sessions_ref.values())
        data = []
        for s in slist:
            try:
                data.append(s.to_dict())
            except AttributeError:
                data.append({
                    "id":       getattr(s, "id", "?"),
                    "ip":       getattr(s, "ip", "?"),
                    "port":     getattr(s, "port", 0),
                    "os_name":  getattr(s, "os_name", ""),
                    "hostname": getattr(s, "hostname", ""),
                    "username": getattr(s, "username", ""),
                    "tag":      getattr(s, "tag", ""),
                    "uptime":   getattr(s, "uptime", ""),
                })
        return jsonify(data)

    @app.route("/api/sessions/<int:sid>")
    def api_session_detail(sid: int):
        if not _check_auth():
            abort(401)
        with sessions_lock:
            sess = sessions_ref.get(sid)
        if sess is None:
            abort(404)
        try:
            return jsonify(sess.to_dict())
        except AttributeError:
            return jsonify({"id": sid})

    @app.route("/api/sessions/<int:sid>/cmd", methods=["POST"])
    def api_send_cmd(sid: int):
        if not _check_auth():
            abort(401)
        with sessions_lock:
            sess = sessions_ref.get(sid)
        if sess is None:
            abort(404)
        body = request.get_json(force=True, silent=True) or {}
        cmd  = body.get("cmd", "")
        if not cmd:
            return jsonify({"error": "cmd field required"}), 400
        try:
            from megaploit.server.commands import dispatch
            result = dispatch(sess, cmd)
            return jsonify({"ok": result.ok, "output": result.output})
        except Exception as exc:
            return jsonify({"error": str(exc)}), 500

    @app.route("/api/loot")
    def api_loot():
        if not _check_auth():
            abort(401)
        loot_root = "loot"
        files = []
        if os.path.isdir(loot_root):
            for root, _dirs, fnames in os.walk(loot_root):
                for fname in fnames:
                    fpath = os.path.join(root, fname)
                    try:
                        size = os.path.getsize(fpath)
                    except OSError:
                        size = 0
                    files.append({
                        "path": os.path.relpath(fpath, loot_root),
                        "size": size,
                    })
        return jsonify(files)

    @app.route("/api/creds")
    def api_creds():
        if not _check_auth():
            abort(401)
        try:
            from megaploit.db.database import db
            rows = db.get_credentials()
            # Redact secrets for web API
            for row in rows:
                if row.get("secret"):
                    row["secret"] = row["secret"][:4] + "…"
            return jsonify(rows)
        except Exception:
            return jsonify([])

    @app.route("/api/jobs")
    def api_jobs():
        if not _check_auth():
            abort(401)
        try:
            from megaploit.core.jobs import job_manager
            return jsonify(job_manager.list_jobs())
        except Exception:
            return jsonify([])

    @app.route("/api/modules")
    def api_modules():
        if not _check_auth():
            abort(401)
        try:
            from megaploit.modules.registry import module_registry
            return jsonify([
                {
                    "name":        e.name,
                    "type":        e.module_type.value,
                    "description": e.description,
                    "rank":        e.rank,
                }
                for e in module_registry.all()
            ])
        except Exception:
            return jsonify([])

    # ------------------------------------------------------------------
    # SSE stream
    # ------------------------------------------------------------------

    @app.route("/events")
    def sse_stream():
        if not _check_auth():
            abort(401)

        def _generate():
            # Register a subscriber queue
            sub_q: queue.Queue = queue.Queue(maxsize=200)
            _subscribers.append(sub_q)
            try:
                yield "retry: 3000\n\n"
                while True:
                    try:
                        event = sub_q.get(timeout=20)
                        yield f"event: update\ndata: {json.dumps(event)}\n\n"
                    except queue.Empty:
                        yield ": ping\n\n"
            finally:
                try:
                    _subscribers.remove(sub_q)
                except ValueError:
                    pass

        return Response(
            stream_with_context(_generate()),
            mimetype="text/event-stream",
            headers={
                "Cache-Control": "no-cache",
                "X-Accel-Buffering": "no",
            },
        )

    # Store subscriber list and broadcast function on app
    _subscribers: list[queue.Queue] = []
    app._subscribers = _subscribers  # type: ignore[attr-defined]

    def _broadcast(event_type: str, message: str, **data: Any) -> None:
        payload = {
            "ts":      time.strftime("%H:%M:%S", time.gmtime()),
            "type":    event_type,
            "message": message,
            **data,
        }
        for sub_q in list(_subscribers):
            try:
                sub_q.put_nowait(payload)
            except queue.Full:
                pass

    app._broadcast = _broadcast  # type: ignore[attr-defined]

    return app


# ---------------------------------------------------------------------------
# Web server wrapper
# ---------------------------------------------------------------------------

class WebServer:
    """
    Wraps Flask in a daemon thread.  Call start() to launch.

    Parameters
    ----------
    sessions_ref   : dict[int, Session]   — shared sessions dict
    sessions_lock  : threading.Lock
    port           : int                   — default 8080
    host           : str                   — bind address, default 127.0.0.1
    api_key        : str                   — auth token
    debug          : bool
    """

    def __init__(
        self,
        sessions_ref: dict,
        sessions_lock: threading.Lock,
        port:    int  = 8080,
        host:    str  = "127.0.0.1",
        api_key: str  = "",
        debug:   bool = False,
    ) -> None:
        if not _HAS_FLASK:
            raise ImportError("Flask is required:  pip install flask")

        self._port    = port
        self._host    = host
        self._debug   = debug
        self._app     = create_app(sessions_ref, sessions_lock, api_key)
        self._thread: Optional[threading.Thread] = None

    # ------------------------------------------------------------------

    def start(self) -> None:
        """Start Flask in a background daemon thread."""
        if self._thread and self._thread.is_alive():
            return

        def _run() -> None:
            import logging
            log = logging.getLogger("werkzeug")
            log.setLevel(logging.ERROR)
            self._app.run(
                host=self._host,
                port=self._port,
                debug=self._debug,
                use_reloader=False,
                threaded=True,
            )

        self._thread = threading.Thread(target=_run, daemon=True, name="web-dashboard")
        self._thread.start()

    def broadcast(self, event_type: str, message: str, **data: Any) -> None:
        """Push an SSE event to all connected browser clients."""
        fn = getattr(self._app, "_broadcast", None)
        if fn:
            fn(event_type, message, **data)

    def url(self) -> str:
        return f"http://{self._host}:{self._port}/"

    def is_running(self) -> bool:
        return bool(self._thread and self._thread.is_alive())

    def __repr__(self) -> str:
        status = "running" if self.is_running() else "stopped"
        return f"<WebServer  {self.url()}  {status}>"
