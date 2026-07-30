"""
megaploit.db.workspace
~~~~~~~~~~~~~~~~~~~~~~
Per-engagement workspace isolation.

Every row in every data table (hosts, services, credentials, notes, loot, jobs)
now carries a ``workspace_id`` foreign key.  All queries are scoped to the
**active workspace** automatically via a ``WorkspaceDatabase`` subclass that
wraps the base ``Database`` class.

Workspaces
----------
* Workspace **1** ("default") is created automatically on first use.
* Operators create, switch, rename, or delete workspaces via the CLI:

    workspace new  pentest-corp
    workspace switch  pentest-corp
    workspace list
    workspace delete  old-engagement
    workspace rename  old-name  new-name

* All subsequent database calls (add_host, add_credential, …) operate within
  the active workspace.

Migration
---------
Running ``WorkspaceDatabase._migrate()`` adds a ``workspace_id`` column to
all existing tables in a live database and backfills them with ``1`` (default
workspace).  This is called automatically on first open.
"""

from __future__ import annotations

import json
import os
import sqlite3
import threading
import time

from megaploit.db.database import Database, _DB_PATH

__all__ = ["WorkspaceDatabase", "workspace_db"]

# ---------------------------------------------------------------------------
# DDL additions
# ---------------------------------------------------------------------------

_WORKSPACE_DDL = """
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS workspaces (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT NOT NULL UNIQUE,
    description TEXT DEFAULT '',
    created_at  REAL NOT NULL,
    active      INTEGER DEFAULT 0
);

-- Seed the default workspace (id=1)
INSERT OR IGNORE INTO workspaces (id, name, description, created_at, active)
VALUES (1, 'default', 'Default workspace', {now}, 1);
"""

# Columns to add to existing tables for workspace scoping
_WORKSPACE_COLS = {
    "hosts":       "ALTER TABLE hosts       ADD COLUMN workspace_id INTEGER NOT NULL DEFAULT 1",
    "services":    "ALTER TABLE services    ADD COLUMN workspace_id INTEGER NOT NULL DEFAULT 1",
    "credentials": "ALTER TABLE credentials ADD COLUMN workspace_id INTEGER NOT NULL DEFAULT 1",
    "notes":       "ALTER TABLE notes       ADD COLUMN workspace_id INTEGER NOT NULL DEFAULT 1",
    "loot":        "ALTER TABLE loot        ADD COLUMN workspace_id INTEGER NOT NULL DEFAULT 1",
    "jobs":        "ALTER TABLE jobs        ADD COLUMN workspace_id INTEGER NOT NULL DEFAULT 1",
}


# ---------------------------------------------------------------------------
# WorkspaceDatabase
# ---------------------------------------------------------------------------

class WorkspaceDatabase(Database):
    """
    Extends ``Database`` with workspace-scoped queries.

    All write operations inject the current workspace_id automatically.
    All read operations filter by the current workspace_id.
    """

    def __init__(self, path: str = _DB_PATH) -> None:
        super().__init__(path)
        self._workspace_id: int = 1
        self._ws_lock = threading.Lock()
        self._migrate()
        self._ensure_default_workspace()

    # ------------------------------------------------------------------
    # Migration — adds workspace_id to all tables if not present
    # ------------------------------------------------------------------

    def _migrate(self) -> None:
        """Add workspace_id column to legacy tables (idempotent)."""
        with self._lock:
            conn = self._conn()
            # Create workspaces table first
            conn.executescript(_WORKSPACE_DDL.format(now=time.time()))
            conn.commit()

            for table, alter_sql in _WORKSPACE_COLS.items():
                try:
                    conn.execute(alter_sql)
                    conn.commit()
                except sqlite3.OperationalError:
                    pass  # Column already exists

            # Create indexes for workspace queries
            for table in _WORKSPACE_COLS:
                try:
                    conn.execute(
                        f"CREATE INDEX IF NOT EXISTS idx_{table}_ws "
                        f"ON {table}(workspace_id)"
                    )
                    conn.commit()
                except sqlite3.OperationalError:
                    pass

    def _ensure_default_workspace(self) -> None:
        rows = self._read("SELECT id FROM workspaces WHERE id=1")
        if not rows:
            with self._write() as cur:
                cur.execute(
                    "INSERT OR IGNORE INTO workspaces (id,name,description,created_at,active)"
                    " VALUES (1,'default','Default workspace',?,1)",
                    (time.time(),)
                )

    # ------------------------------------------------------------------
    # Workspace management
    # ------------------------------------------------------------------

    @property
    def workspace_id(self) -> int:
        with self._ws_lock:
            return self._workspace_id

    def create_workspace(self, name: str, description: str = "") -> int:
        """Create a new workspace.  Returns its id."""
        with self._write() as cur:
            cur.execute(
                "INSERT INTO workspaces (name,description,created_at) VALUES (?,?,?)",
                (name, description, time.time()),
            )
            return cur.lastrowid

    def switch_workspace(self, name: str) -> int:
        """Switch the active workspace by name.  Returns the new workspace_id."""
        rows = self._read("SELECT id FROM workspaces WHERE name=?", (name,))
        if not rows:
            raise KeyError(f"Workspace {name!r} does not exist")
        wid = rows[0]["id"]
        with self._ws_lock:
            self._workspace_id = wid
        with self._write() as cur:
            cur.execute("UPDATE workspaces SET active=0")
            cur.execute("UPDATE workspaces SET active=1 WHERE id=?", (wid,))
        return wid

    def list_workspaces(self) -> list[dict]:
        rows = self._read("SELECT id,name,description,active,created_at FROM workspaces ORDER BY id")
        return [dict(r) for r in rows]

    def get_workspace(self, name: str) -> dict | None:
        rows = self._read(
            "SELECT id,name,description,active,created_at FROM workspaces WHERE name=?", (name,)
        )
        return dict(rows[0]) if rows else None

    def rename_workspace(self, old_name: str, new_name: str) -> None:
        with self._write() as cur:
            cur.execute("UPDATE workspaces SET name=? WHERE name=?", (new_name, old_name))

    def delete_workspace(self, name: str) -> None:
        """Delete a workspace and ALL its data (cascades).  Cannot delete 'default'."""
        if name.lower() == "default":
            raise ValueError("Cannot delete the default workspace")
        rows = self._read("SELECT id FROM workspaces WHERE name=?", (name,))
        if not rows:
            raise KeyError(f"Workspace {name!r} does not exist")
        wid = rows[0]["id"]
        with self._write() as cur:
            # Delete all workspace data
            for table in _WORKSPACE_COLS:
                cur.execute(f"DELETE FROM {table} WHERE workspace_id=?", (wid,))
            cur.execute("DELETE FROM workspaces WHERE id=?", (wid,))
        # If we deleted the active workspace, revert to default
        with self._ws_lock:
            if self._workspace_id == wid:
                self._workspace_id = 1

    def workspace_stats(self) -> dict:
        """Return row counts per table for the current workspace."""
        wid    = self.workspace_id
        counts = {}
        for table in _WORKSPACE_COLS:
            rows = self._read(
                f"SELECT COUNT(*) AS n FROM {table} WHERE workspace_id=?", (wid,)
            )
            counts[table] = rows[0]["n"] if rows else 0
        return {"workspace_id": wid, **counts}

    # ------------------------------------------------------------------
    # Override write methods to inject workspace_id
    # ------------------------------------------------------------------

    def add_host(self, ip: str, **kwargs) -> int:
        """Insert or update a host, scoped to the current workspace."""
        hostname   = kwargs.get("hostname", "")
        os_name    = kwargs.get("os_name", "")
        os_version = kwargs.get("os_version", "")
        mac        = kwargs.get("mac", "")
        domain     = kwargs.get("domain", "")
        info       = kwargs.get("info", "")
        state      = kwargs.get("state", "up")
        tags       = kwargs.get("tags") or []
        now        = time.time()
        wid        = self.workspace_id
        with self._write() as cur:
            cur.execute(
                """INSERT INTO hosts
                   (ip,hostname,os_name,os_version,mac,domain,info,state,
                    first_seen,last_seen,tags,workspace_id)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
                   ON CONFLICT(ip) DO UPDATE SET
                     hostname=excluded.hostname, os_name=excluded.os_name,
                     os_version=excluded.os_version, mac=excluded.mac,
                     domain=excluded.domain, info=excluded.info,
                     state=excluded.state, last_seen=excluded.last_seen,
                     tags=excluded.tags
                   WHERE workspace_id=?
                """,
                (ip, hostname, os_name, os_version, mac, domain, info, state,
                 now, now, json.dumps(tags), wid, wid),
            )
            row = self._conn().execute(
                "SELECT id FROM hosts WHERE ip=? AND workspace_id=?", (ip, wid)
            ).fetchone()
        return row["id"]

    def get_hosts(self, state: str | None = None) -> list[dict]:
        wid = self.workspace_id
        sql = "SELECT * FROM hosts WHERE workspace_id=?"
        params: list = [wid]
        if state:
            sql += " AND state=?"
            params.append(state)
        sql += " ORDER BY ip"
        rows = self._read(sql, tuple(params))
        result = []
        for r in rows:
            d = dict(r)
            d["tags"] = json.loads(d.get("tags") or "[]")
            result.append(d)
        return result

    def add_credential(self, username: str = "", secret: str = "",
                       cred_type: str = "plaintext", host_id: int | None = None,
                       host: str | None = None, session_id: int = 0,
                       hash_type: str = "", realm: str = "",
                       source: str = "", note: str = "") -> int:
        if host_id is None and host:
            h = self.get_host_by_ip(host)
            host_id = h.id if h else self.add_host(host)
        wid = self.workspace_id
        with self._write() as cur:
            cur.execute(
                """INSERT INTO credentials
                   (host_id,session_id,username,secret,cred_type,hash_type,
                    realm,source,note,captured_at,workspace_id)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
                (host_id, session_id, username, secret, cred_type, hash_type,
                 realm, source, note, time.time(), wid),
            )
            return cur.lastrowid

    def get_credentials(self, host_id: int | None = None,
                        username: str | None = None, cred_type: str | None = None,
                        search: str | None = None) -> list[dict]:
        wid = self.workspace_id
        clauses = ["c.workspace_id=?"]
        params  = [wid]
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
        sql = ("SELECT c.*, COALESCE(h.ip,'') AS host FROM credentials c "
               "LEFT JOIN hosts h ON h.id=c.host_id "
               "WHERE " + " AND ".join(clauses) + " ORDER BY c.captured_at DESC")
        rows = self._read(sql, tuple(params))
        return [self._cred_to_dict(r) for r in rows]

    def add_loot(self, path: str = "", session_id: int = 0, host: str = "",
                 description: str = "", file_type: str = "",
                 file_path: str | None = None, size: int | None = None) -> int:
        import hashlib
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
        wid = self.workspace_id
        with self._write() as cur:
            cur.execute(
                """INSERT INTO loot
                   (session_id,host,path,description,file_type,
                    size_bytes,sha256,created_at,workspace_id)
                   VALUES (?,?,?,?,?,?,?,?,?)""",
                (session_id, host, path, description, file_type,
                 size_bytes, sha, time.time(), wid),
            )
            return cur.lastrowid

    def get_loot(self, session_id: int | None = None, host: str | None = None) -> list[dict]:
        wid = self.workspace_id
        clauses = ["workspace_id=?"]
        params: list = [wid]
        if session_id is not None:
            clauses.append("session_id=?"); params.append(session_id)
        if host is not None:
            clauses.append("host=?"); params.append(host)
        sql = ("SELECT * FROM loot WHERE " + " AND ".join(clauses) +
               " ORDER BY created_at DESC")
        results = []
        for r in self._read(sql, tuple(params)):
            d = dict(r)
            d["file_path"] = d.get("path", "")
            results.append(d)
        return results

    def add_note(self, text: str = "", host_id: int | None = None,
                 session_id: int = 0, category: str = "general") -> int:
        wid = self.workspace_id
        with self._write() as cur:
            cur.execute(
                "INSERT INTO notes (host_id,session_id,text,category,created_at,workspace_id)"
                " VALUES (?,?,?,?,?,?)",
                (host_id, session_id, text, category, time.time(), wid),
            )
            return cur.lastrowid


# ---------------------------------------------------------------------------
# Singleton
# ---------------------------------------------------------------------------

workspace_db = WorkspaceDatabase()
