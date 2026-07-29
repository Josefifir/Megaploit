"""
megaploit.db.database
~~~~~~~~~~~~~~~~~~~~~
SQLite-backed persistence layer.

Tables
------
  hosts        — every discovered / active host
  services     — open ports / running services on hosts
  credentials  — harvested credentials (username, secret, type, source)
  notes        — operator free-text notes (can be linked to a host or session)
  loot         — metadata for every file pulled from a session

The module-level singleton  ``db``  is created automatically on import and
backed by  ``loot/megaploit.db``  (created on first use).

Usage
-----
    from megaploit.db import db

    # hosts
    hid = db.add_host("192.168.1.10", hostname="DC01", os_name="Windows Server 2019")
    db.update_host(hid, os_name="Windows Server 2019 (patched)")
    hosts = db.get_hosts()

    # services
    db.add_service(hid, port=445, proto="tcp", name="smb", banner="Windows 10 SMB")

    # creds
    cid = db.add_credential(hid, username="Administrator", secret="P@ssw0rd",
                             cred_type="plaintext", source="cred_vault")
    creds = db.get_credentials()

    # notes
    db.add_note(text="Found creds in web.config", host_id=hid)

    # loot
    db.add_loot(session_id=1, host="192.168.1.10", path="loot/downloads/passwd",
                description="Linux /etc/passwd", file_type="text")

    # nmap XML import
    db.import_nmap_xml("scan.xml")
"""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import threading
import time
import xml.etree.ElementTree as ET
from contextlib import contextmanager
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Generator, Optional

_DB_PATH = os.path.join("loot", "megaploit.db")

_DDL = """
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS hosts (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ip          TEXT NOT NULL UNIQUE,
    hostname    TEXT DEFAULT '',
    os_name     TEXT DEFAULT '',
    os_version  TEXT DEFAULT '',
    mac         TEXT DEFAULT '',
    domain      TEXT DEFAULT '',
    info        TEXT DEFAULT '',
    state       TEXT DEFAULT 'up',   -- up | down | unknown
    first_seen  REAL NOT NULL,
    last_seen   REAL NOT NULL,
    tags        TEXT DEFAULT '[]'    -- JSON list of strings
);

CREATE TABLE IF NOT EXISTS services (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id     INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    port        INTEGER NOT NULL,
    proto       TEXT NOT NULL DEFAULT 'tcp',  -- tcp | udp
    name        TEXT DEFAULT '',
    product     TEXT DEFAULT '',
    version     TEXT DEFAULT '',
    banner      TEXT DEFAULT '',
    state       TEXT DEFAULT 'open',  -- open | closed | filtered
    extra       TEXT DEFAULT '{}',    -- JSON blob for extra fields
    updated_at  REAL NOT NULL,
    UNIQUE(host_id, port, proto)
);

CREATE TABLE IF NOT EXISTS credentials (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id     INTEGER REFERENCES hosts(id) ON DELETE SET NULL,
    session_id  INTEGER DEFAULT 0,
    username    TEXT NOT NULL DEFAULT '',
    secret      TEXT NOT NULL DEFAULT '',
    cred_type   TEXT NOT NULL DEFAULT 'plaintext', -- plaintext | hash | key | token | cookie
    hash_type   TEXT DEFAULT '',   -- e.g. ntlm, sha512crypt
    realm       TEXT DEFAULT '',   -- domain / service
    source      TEXT DEFAULT '',   -- command that produced this (hashdump, wifi_passwords, …)
    note        TEXT DEFAULT '',
    captured_at REAL NOT NULL,
    used        INTEGER DEFAULT 0  -- 1 = successfully used
);

CREATE INDEX IF NOT EXISTS idx_creds_username ON credentials(username);
CREATE INDEX IF NOT EXISTS idx_creds_host     ON credentials(host_id);

CREATE TABLE IF NOT EXISTS notes (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id     INTEGER REFERENCES hosts(id) ON DELETE SET NULL,
    session_id  INTEGER DEFAULT 0,
    text        TEXT NOT NULL,
    category    TEXT DEFAULT 'general',
    created_at  REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS loot (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id  INTEGER DEFAULT 0,
    host        TEXT DEFAULT '',
    path        TEXT NOT NULL,       -- local loot file path
    description TEXT DEFAULT '',
    file_type   TEXT DEFAULT '',     -- screenshot | recording | download | archive | text
    size_bytes  INTEGER DEFAULT 0,
    sha256      TEXT DEFAULT '',
    created_at  REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS engagements (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT NOT NULL DEFAULT 'Unnamed',
    description TEXT DEFAULT '',
    started_at  REAL NOT NULL,
    ended_at    REAL DEFAULT NULL,
    extra       TEXT DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS jobs (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id  INTEGER DEFAULT 0,
    name        TEXT NOT NULL,
    status      TEXT DEFAULT 'running',  -- running | done | error
    started_at  REAL NOT NULL,
    ended_at    REAL DEFAULT NULL,
    result      TEXT DEFAULT ''
);
"""

# ---------------------------------------------------------------------------
# Dataclasses (returned by query methods)
# ---------------------------------------------------------------------------

@dataclass
class Host:
    id:         int
    ip:         str
    hostname:   str = ""
    os_name:    str = ""
    os_version: str = ""
    mac:        str = ""
    domain:     str = ""
    info:       str = ""
    state:      str = "up"
    first_seen: float = 0.0
    last_seen:  float = 0.0
    tags:       list[str] = field(default_factory=list)

    @property
    def first_seen_str(self) -> str:
        return datetime.fromtimestamp(self.first_seen, tz=timezone.utc).strftime("%Y-%m-%d %H:%M")

    @property
    def last_seen_str(self) -> str:
        return datetime.fromtimestamp(self.last_seen, tz=timezone.utc).strftime("%Y-%m-%d %H:%M")


@dataclass
class Service:
    id:        int
    host_id:   int
    port:      int
    proto:     str = "tcp"
    name:      str = ""
    product:   str = ""
    version:   str = ""
    banner:    str = ""
    state:     str = "open"
    extra:     dict = field(default_factory=dict)
    updated_at: float = 0.0


@dataclass
class Credential:
    id:         int
    host_id:    Optional[int]
    session_id: int
    username:   str
    secret:     str
    cred_type:  str = "plaintext"
    hash_type:  str = ""
    realm:      str = ""
    source:     str = ""
    note:       str = ""
    captured_at: float = 0.0
    used:       bool = False

    @property
    def captured_str(self) -> str:
        return datetime.fromtimestamp(self.captured_at, tz=timezone.utc).strftime("%Y-%m-%d %H:%M")


@dataclass
class Note:
    id:         int
    host_id:    Optional[int]
    session_id: int
    text:       str
    category:   str = "general"
    created_at: float = 0.0


@dataclass
class Loot:
    id:          int
    session_id:  int
    host:        str
    path:        str
    description: str = ""
    file_type:   str = ""
    size_bytes:  int = 0
    sha256:      str = ""
    created_at:  float = 0.0


# ---------------------------------------------------------------------------
# Database class
# ---------------------------------------------------------------------------

class Database:
    """
    Thread-safe SQLite wrapper.  Uses a per-thread connection to avoid
    cross-thread sharing issues, protected by a write lock for mutations.
    """

    def __init__(self, path: str = _DB_PATH) -> None:
        self._path    = path
        self._lock    = threading.Lock()
        self._local   = threading.local()
        self._init()

    # ── Internal helpers ──────────────────────────────────────────────

    def _conn(self) -> sqlite3.Connection:
        conn = getattr(self._local, "conn", None)
        if conn is None:
            os.makedirs(os.path.dirname(self._path) or ".", exist_ok=True)
            conn = sqlite3.connect(self._path, check_same_thread=False)
            conn.row_factory = sqlite3.Row
            self._local.conn = conn
        return conn

    def _init(self) -> None:
        with self._lock:
            c = self._conn()
            c.executescript(_DDL)
            c.commit()

    @contextmanager
    def _write(self) -> Generator[sqlite3.Cursor, None, None]:
        with self._lock:
            c = self._conn()
            cur = c.cursor()
            try:
                yield cur
                c.commit()
            except Exception:
                c.rollback()
                raise

    def _read(self, sql: str, params: tuple = ()) -> list[sqlite3.Row]:
        return self._conn().execute(sql, params).fetchall()

    # ── Hosts ─────────────────────────────────────────────────────────

    def add_host(
        self,
        ip: str,
        hostname: str = "",
        os_name: str = "",
        os_version: str = "",
        mac: str = "",
        domain: str = "",
        info: str = "",
        state: str = "up",
        tags: list[str] | None = None,
    ) -> int:
        """Insert or update a host by IP.  Returns the host id."""
        now = time.time()
        with self._write() as cur:
            cur.execute(
                """INSERT INTO hosts
                   (ip,hostname,os_name,os_version,mac,domain,info,state,first_seen,last_seen,tags)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?)
                   ON CONFLICT(ip) DO UPDATE SET
                     hostname   = excluded.hostname,
                     os_name    = excluded.os_name,
                     os_version = excluded.os_version,
                     mac        = excluded.mac,
                     domain     = excluded.domain,
                     info       = excluded.info,
                     state      = excluded.state,
                     last_seen  = excluded.last_seen,
                     tags       = excluded.tags
                """,
                (ip, hostname, os_name, os_version, mac, domain, info, state,
                 now, now, json.dumps(tags or [])),
            )
            # BUG (was): called self._conn() INSIDE the _write() context manager,
            # which tries to acquire self._lock again → deadlock on non-reentrant
            # Lock.  Use the cursor's connection directly via cur.connection
            # to stay inside the same transaction without re-acquiring the lock.
            row = cur.execute("SELECT id FROM hosts WHERE ip=?", (ip,)).fetchone()
        return row["id"]

    def update_host(self, host_id: int, **kwargs) -> None:
        allowed = {"hostname","os_name","os_version","mac","domain","info","state","tags"}
        sets = []
        vals = []
        for k, v in kwargs.items():
            if k in allowed:
                sets.append(f"{k}=?")
                vals.append(json.dumps(v) if k == "tags" else v)
        if not sets:
            return
        vals.append(time.time())
        vals.append(host_id)
        with self._write() as cur:
            cur.execute(f"UPDATE hosts SET {','.join(sets)},last_seen=? WHERE id=?", vals)

    def get_hosts(self, state: str | None = None) -> list[dict]:
        sql = "SELECT * FROM hosts"
        params: tuple = ()
        if state:
            sql += " WHERE state=?"
            params = (state,)
        sql += " ORDER BY ip"
        rows = self._read(sql, params)
        result = []
        for r in rows:
            d = dict(r)
            d["tags"] = json.loads(d.get("tags") or "[]")
            result.append(d)
        return result

    def get_host_by_ip(self, ip: str) -> Host | None:
        rows = self._read("SELECT * FROM hosts WHERE ip=?", (ip,))
        return self._row_to_host(rows[0]) if rows else None

    def get_host(self, host_id: int) -> Host | None:
        rows = self._read("SELECT * FROM hosts WHERE id=?", (host_id,))
        return self._row_to_host(rows[0]) if rows else None

    @staticmethod
    def _row_to_host(row: sqlite3.Row) -> Host:
        d = dict(row)
        d["tags"] = json.loads(d.get("tags") or "[]")
        return Host(**d)

    # ── Services ──────────────────────────────────────────────────────

    def add_service(
        self,
        host_id: int,
        port: int,
        proto: str = "tcp",
        name: str = "",
        product: str = "",
        version: str = "",
        banner: str = "",
        state: str = "open",
        extra: dict | None = None,
    ) -> int:
        now = time.time()
        with self._write() as cur:
            cur.execute(
                """INSERT INTO services
                   (host_id,port,proto,name,product,version,banner,state,extra,updated_at)
                   VALUES (?,?,?,?,?,?,?,?,?,?)
                   ON CONFLICT(host_id,port,proto) DO UPDATE SET
                     name=excluded.name, product=excluded.product,
                     version=excluded.version, banner=excluded.banner,
                     state=excluded.state, extra=excluded.extra,
                     updated_at=excluded.updated_at
                """,
                (host_id, port, proto, name, product, version, banner, state,
                 json.dumps(extra or {}), now),
            )
            # BUG (was): same _conn()-inside-_write() deadlock as add_host.
            row = cur.execute(
                "SELECT id FROM services WHERE host_id=? AND port=? AND proto=?",
                (host_id, port, proto)
            ).fetchone()
        return row["id"]

    def get_services(self, host_id: int | None = None) -> list[Service]:
        if host_id is not None:
            rows = self._read("SELECT * FROM services WHERE host_id=? ORDER BY port", (host_id,))
        else:
            rows = self._read("SELECT * FROM services ORDER BY host_id, port")
        return [self._row_to_service(r) for r in rows]

    @staticmethod
    def _row_to_service(row: sqlite3.Row) -> Service:
        d = dict(row)
        d["extra"] = json.loads(d.get("extra") or "{}")
        return Service(**d)

    # ── Credentials ───────────────────────────────────────────────────

    def add_credential(
        self,
        username: str = "",
        secret: str = "",
        cred_type: str = "plaintext",
        host_id: int | None = None,
        host: str | None = None,
        session_id: int = 0,
        hash_type: str = "",
        realm: str = "",
        source: str = "",
        note: str = "",
    ) -> int:
        """Insert a credential.  ``host`` may be a string IP (looked up or
        created automatically); ``host_id`` may be an integer FK.  If both
        are given, ``host_id`` wins."""
        if host_id is None and host is not None:
            h = self.get_host_by_ip(host)
            if h is None:
                host_id = self.add_host(host)
            else:
                host_id = h.id
        with self._write() as cur:
            cur.execute(
                """INSERT INTO credentials
                   (host_id,session_id,username,secret,cred_type,hash_type,realm,source,note,captured_at)
                   VALUES (?,?,?,?,?,?,?,?,?,?)""",
                (host_id, session_id, username, secret, cred_type, hash_type,
                 realm, source, note, time.time()),
            )
            return cur.lastrowid

    def get_credentials(
        self,
        host_id: int | None = None,
        username: str | None = None,
        cred_type: str | None = None,
        search: str | None = None,
    ) -> list[dict]:
        clauses, params = [], []
        if host_id is not None:
            clauses.append("c.host_id=?"); params.append(host_id)
        if username is not None:
            clauses.append("c.username LIKE ?"); params.append(f"%{username}%")
        if cred_type is not None:
            clauses.append("c.cred_type=?"); params.append(cred_type)
        if search is not None:
            clauses.append(
                "(c.username LIKE ? OR c.secret LIKE ? OR c.realm LIKE ? OR c.source LIKE ?)"
            )
            params.extend([f"%{search}%"] * 4)
        sql = "SELECT c.*, COALESCE(h.ip, '') AS host FROM credentials c LEFT JOIN hosts h ON h.id = c.host_id"
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        sql += " ORDER BY c.captured_at DESC"
        rows = self._read(sql, tuple(params))
        return [self._cred_to_dict(r) for r in rows]

    def search_credentials(self, query: str) -> list[dict]:
        """Search credentials by username, host IP, secret, realm or source."""
        sql = """
            SELECT c.*, h.ip AS host
            FROM credentials c
            LEFT JOIN hosts h ON h.id = c.host_id
            WHERE c.username LIKE ?
               OR c.secret   LIKE ?
               OR c.realm    LIKE ?
               OR c.source   LIKE ?
               OR h.ip       LIKE ?
            ORDER BY c.captured_at DESC
        """
        q = f"%{query}%"
        rows = self._read(sql, (q, q, q, q, q))
        return [self._cred_to_dict(r) for r in rows]

    def clear_credentials(self) -> None:
        """Delete all stored credentials."""
        with self._write() as cur:
            cur.execute("DELETE FROM credentials")

    def mark_credential_used(self, cred_id: int) -> None:
        with self._write() as cur:
            cur.execute("UPDATE credentials SET used=1 WHERE id=?", (cred_id,))

    @staticmethod
    def _row_to_cred(row: sqlite3.Row) -> Credential:
        d = dict(row)
        d["used"] = bool(d.get("used", 0))
        return Credential(**d)

    @staticmethod
    def _cred_to_dict(row: sqlite3.Row) -> dict:
        d = dict(row)
        d["used"] = bool(d.get("used", 0))
        # surface host IP when joined in
        if "host" not in d:
            d["host"] = ""
        return d

    # ── Notes ─────────────────────────────────────────────────────────

    def add_note(
        self,
        text: str = "",
        host_id: int | None = None,
        session_id: int = 0,
        category: str = "general",
    ) -> int:
        with self._write() as cur:
            cur.execute(
                "INSERT INTO notes (host_id,session_id,text,category,created_at) VALUES (?,?,?,?,?)",
                (host_id, session_id, text, category, time.time()),
            )
            return cur.lastrowid

    def get_notes(self, host_id: int | None = None, session_id: int | None = None) -> list[dict]:
        clauses, params = [], []
        if host_id is not None:
            clauses.append("host_id=?"); params.append(host_id)
        if session_id is not None:
            clauses.append("session_id=?"); params.append(session_id)
        sql = "SELECT * FROM notes"
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        sql += " ORDER BY created_at"
        return [dict(r) for r in self._read(sql, tuple(params))]

    # ── Loot ──────────────────────────────────────────────────────────

    def add_loot(
        self,
        path: str = "",
        session_id: int = 0,
        host: str = "",
        description: str = "",
        file_type: str = "",
        file_path: str | None = None,
        size: int | None = None,
    ) -> int:
        """Add a loot entry.  ``file_path`` is an alias for ``path``;
        ``size`` overrides the auto-detected file size."""
        if file_path is not None:
            path = file_path
        size_bytes = 0
        sha = ""
        if size is not None:
            size_bytes = size
        elif os.path.isfile(path):
            size_bytes = os.path.getsize(path)
            h = hashlib.sha256()
            with open(path, "rb") as f:
                for chunk in iter(lambda: f.read(65536), b""):
                    h.update(chunk)
            sha = h.hexdigest()
        with self._write() as cur:
            cur.execute(
                """INSERT INTO loot
                   (session_id,host,path,description,file_type,size_bytes,sha256,created_at)
                   VALUES (?,?,?,?,?,?,?,?)""",
                (session_id, host, path, description, file_type, size_bytes, sha, time.time()),
            )
            return cur.lastrowid

    def get_loot(self, session_id: int | None = None, host: str | None = None) -> list[dict]:
        clauses, params = [], []
        if session_id is not None:
            clauses.append("session_id=?"); params.append(session_id)
        if host is not None:
            clauses.append("host=?"); params.append(host)
        sql = "SELECT * FROM loot"
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        sql += " ORDER BY created_at DESC"
        results = []
        for r in self._read(sql, tuple(params)):
            d = dict(r)
            # expose file_path as an alias for path
            d["file_path"] = d.get("path", "")
            results.append(d)
        return results

    # ── Jobs ──────────────────────────────────────────────────────────

    def add_job(self, name: str, session_id: int = 0) -> int:
        with self._write() as cur:
            cur.execute(
                "INSERT INTO jobs (session_id,name,status,started_at) VALUES (?,?,?,?)",
                (session_id, name, "running", time.time()),
            )
            return cur.lastrowid

    def finish_job(self, job_id: int, result: str = "", error: bool = False) -> None:
        status = "error" if error else "done"
        with self._write() as cur:
            cur.execute(
                "UPDATE jobs SET status=?,ended_at=?,result=? WHERE id=?",
                (status, time.time(), result[:4000], job_id),
            )

    def get_jobs(self, session_id: int | None = None, status: str | None = None) -> list[dict]:
        clauses, params = [], []
        if session_id is not None:
            clauses.append("session_id=?"); params.append(session_id)
        if status is not None:
            clauses.append("status=?"); params.append(status)
        sql = "SELECT * FROM jobs"
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        sql += " ORDER BY started_at DESC"
        return [dict(r) for r in self._read(sql, tuple(params))]

    # ── Engagements ───────────────────────────────────────────────────

    def start_engagement(self, name: str, description: str = "") -> int:
        with self._write() as cur:
            cur.execute(
                "INSERT INTO engagements (name,description,started_at) VALUES (?,?,?)",
                (name, description, time.time()),
            )
            return cur.lastrowid

    def end_engagement(self, eng_id: int) -> None:
        with self._write() as cur:
            cur.execute("UPDATE engagements SET ended_at=? WHERE id=?", (time.time(), eng_id))

    def get_engagements(self) -> list[dict]:
        return [dict(r) for r in self._read("SELECT * FROM engagements ORDER BY started_at DESC")]

    def set_engagement(self, name: str, description: str = "") -> int:
        """Create (or replace) the current engagement record.  Returns its id."""
        return self.start_engagement(name=name, description=description)

    def get_engagement(self) -> dict | None:
        """Return the most-recently created engagement, or None."""
        rows = self.get_engagements()
        return rows[0] if rows else None

    # ── Nmap XML import ───────────────────────────────────────────────

    def import_nmap_xml(self, xml_path: str) -> tuple[int, int]:
        """
        Parse an nmap XML output file and populate hosts + services.
        Returns (hosts_added, services_added).
        """
        try:
            tree = ET.parse(xml_path)
        except ET.ParseError as e:
            raise ValueError(f"Invalid nmap XML: {e}") from e

        hosts_added = services_added = 0
        for host_el in tree.findall(".//host"):
            state_el = host_el.find("status")
            state = state_el.get("state", "unknown") if state_el is not None else "unknown"
            addr_el = host_el.find("address[@addrtype='ipv4']")
            if addr_el is None:
                addr_el = host_el.find("address[@addrtype='ipv6']")
            if addr_el is None:
                continue
            ip = addr_el.get("addr", "")
            if not ip:
                continue

            mac = ""
            mac_el = host_el.find("address[@addrtype='mac']")
            if mac_el is not None:
                mac = mac_el.get("addr", "")

            hostname = ""
            hn_el = host_el.find(".//hostname[@type='PTR']")
            if hn_el is None:
                hn_el = host_el.find(".//hostname")
            if hn_el is not None:
                hostname = hn_el.get("name", "")

            os_name = ""
            osm = host_el.find(".//osmatch")
            if osm is not None:
                os_name = osm.get("name", "")

            hid = self.add_host(ip, hostname=hostname, os_name=os_name, mac=mac, state=state)
            hosts_added += 1

            for port_el in host_el.findall(".//port"):
                pstate = port_el.find("state")
                if pstate is None or pstate.get("state") not in ("open", "filtered"):
                    continue
                portnum  = int(port_el.get("portid", 0))
                proto    = port_el.get("protocol", "tcp")
                svc_el   = port_el.find("service")
                svc_name = product = version = banner = ""
                if svc_el is not None:
                    svc_name = svc_el.get("name", "")
                    product  = svc_el.get("product", "")
                    version  = svc_el.get("version", "")
                    extra_info = svc_el.get("extrainfo", "")
                    banner   = " ".join(filter(None, [product, version, extra_info]))
                self.add_service(hid, portnum, proto, svc_name, product, version, banner,
                                 state=pstate.get("state", "open"))
                services_added += 1

        return hosts_added, services_added

    # ── Statistics ────────────────────────────────────────────────────

    def stats(self) -> dict:
        rows = self._conn().execute("""
            SELECT
              (SELECT COUNT(*) FROM hosts)       AS hosts,
              (SELECT COUNT(*) FROM services)    AS services,
              (SELECT COUNT(*) FROM credentials) AS credentials,
              (SELECT COUNT(*) FROM notes)        AS notes,
              (SELECT COUNT(*) FROM loot)         AS loot,
              (SELECT COUNT(*) FROM jobs WHERE status='running') AS running_jobs
        """).fetchone()
        return dict(rows)

    # ── Export ────────────────────────────────────────────────────────

    def export_json(self, path: str) -> None:
        """Dump the entire DB to a structured JSON file."""
        data = {
            "hosts":       self.get_hosts(),
            "services":    [asdict(s) for s in self.get_services()],
            "credentials": self.get_credentials(),
            "notes":       self.get_notes(),
            "loot":        self.get_loot(),
            "stats":       self.stats(),
            "exported_at": datetime.now(timezone.utc).isoformat(),
        }
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

db = Database()
