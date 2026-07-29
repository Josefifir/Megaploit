"""
megaploit.reporting.report
~~~~~~~~~~~~~~~~~~~~~~~~~~
Generate engagement reports in HTML or JSON format.

No external dependencies required for HTML — the template is embedded.
Jinja2 and weasyprint are used only if available (for richer HTML and
optional PDF output).

Usage::

    from megaploit.reporting.report import generate_report

    generate_report(
        output_path="report.html",
        fmt="html",
        engagement_name="Acme Corp Pentest",
        engagement_desc="Q1 2025 internal network assessment",
        engagement_start=1710000000.0,
        sessions=[...],
    )
"""

from __future__ import annotations

import datetime
import json
import os
import time
from typing import Any

__all__ = ["generate_report"]


# ---------------------------------------------------------------------------
# Embedded HTML template  (single self-contained file, no external deps)
# ---------------------------------------------------------------------------

_HTML_TEMPLATE = """\
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Megaploit Engagement Report — {engagement_name}</title>
<style>
  *, *::before, *::after {{ box-sizing: border-box; }}
  body {{
    margin: 0; padding: 0;
    font-family: -apple-system, "Segoe UI", system-ui, sans-serif;
    font-size: 14px; line-height: 1.6;
    background: #f7f8fa; color: #1f2328;
  }}
  .page {{
    max-width: 960px; margin: 32px auto; padding: 0 24px 48px;
  }}
  h1, h2, h3 {{
    font-weight: 600; color: #1f2328;
    border-bottom: 1px solid #e5e7eb; padding-bottom: 4px;
  }}
  h1 {{ font-size: 24px; margin-bottom: 4px; border: none; }}
  h2 {{ font-size: 17px; margin-top: 32px; }}
  h3 {{ font-size: 14px; margin-top: 20px; border: none; }}
  .meta {{ color: #57606a; font-size: 12px; margin-bottom: 24px; }}
  .badge {{
    display: inline-block; padding: 2px 8px; border-radius: 12px;
    font-size: 11px; font-weight: 600; text-transform: uppercase;
  }}
  .badge-green  {{ background: #d1fae5; color: #065f46; }}
  .badge-red    {{ background: #fee2e2; color: #991b1b; }}
  .badge-yellow {{ background: #fef9c3; color: #854d0e; }}
  .badge-blue   {{ background: #dbeafe; color: #1e40af; }}
  .badge-grey   {{ background: #f1f5f9; color: #64748b; }}
  table {{
    width: 100%; border-collapse: collapse; margin-top: 12px;
    font-size: 13px;
  }}
  th {{
    background: #f1f5f9; text-align: left; padding: 6px 10px;
    font-weight: 600; color: #374151;
    border-bottom: 1px solid #e5e7eb;
  }}
  td {{
    padding: 6px 10px; border-bottom: 1px solid #f0f0f0;
    word-break: break-word;
  }}
  tr:last-child td {{ border-bottom: none; }}
  tr:hover td {{ background: #f9fafb; }}
  .card {{
    background: #fff; border: 1px solid #e5e7eb;
    border-radius: 8px; padding: 16px 20px; margin-bottom: 16px;
  }}
  .stat-grid {{
    display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px;
    margin-bottom: 24px;
  }}
  .stat-card {{
    background: #fff; border: 1px solid #e5e7eb;
    border-radius: 8px; padding: 14px 16px; text-align: center;
  }}
  .stat-card .val {{
    font-size: 28px; font-weight: 700; color: #3b82d4;
    display: block;
  }}
  .stat-card .lbl {{
    font-size: 11px; color: #57606a; text-transform: uppercase;
    letter-spacing: 0.04em;
  }}
  pre {{
    background: #f1f5f9; border: 1px solid #e5e7eb;
    border-radius: 4px; padding: 10px 12px;
    font-size: 12px; overflow-x: auto; white-space: pre-wrap;
  }}
  .footer {{
    text-align: center; font-size: 11px; color: #9ca3af;
    margin-top: 48px; padding-top: 12px;
    border-top: 1px solid #e5e7eb;
  }}
  @media print {{
    body {{ background: #fff; }}
    .page {{ margin: 0; padding: 0 16px; }}
  }}
</style>
</head>
<body>
<div class="page">

  <!-- Header -->
  <h1>&#x1F4CB; Megaploit Engagement Report</h1>
  <div class="meta">
    <strong>Engagement:</strong> {engagement_name_esc} &nbsp;|&nbsp;
    <strong>Started:</strong> {engagement_start_str} &nbsp;|&nbsp;
    <strong>Generated:</strong> {generated_at}
  </div>
  {engagement_desc_html}

  <!-- Summary stats -->
  <div class="stat-grid">
    <div class="stat-card">
      <span class="val">{n_sessions}</span>
      <span class="lbl">Sessions</span>
    </div>
    <div class="stat-card">
      <span class="val">{n_creds}</span>
      <span class="lbl">Credentials</span>
    </div>
    <div class="stat-card">
      <span class="val">{n_loot}</span>
      <span class="lbl">Loot files</span>
    </div>
    <div class="stat-card">
      <span class="val">{n_hosts}</span>
      <span class="lbl">Unique hosts</span>
    </div>
  </div>

  <!-- Sessions table -->
  <h2>&#x1F4BB; Sessions</h2>
  {sessions_table}

  <!-- Credentials table -->
  <h2>&#x1F511; Credentials</h2>
  {creds_table}

  <!-- Loot table -->
  <h2>&#x1F4E6; Loot</h2>
  {loot_table}

  <!-- Notes -->
  <h2>&#x1F4DD; Session Notes</h2>
  {notes_section}

  <div class="footer">
    Generated by <strong>Megaploit</strong> &mdash; {generated_at}
  </div>
</div>
</body>
</html>
"""

_SESSIONS_TABLE_TEMPLATE = """\
<table>
  <thead>
    <tr>
      <th>#</th><th>IP : Port</th><th>OS</th><th>Hostname</th>
      <th>User</th><th>Tag</th><th>Uptime</th>
    </tr>
  </thead>
  <tbody>
    {rows}
  </tbody>
</table>
"""

_CREDS_TABLE_TEMPLATE = """\
<table>
  <thead>
    <tr>
      <th>Host</th><th>Username</th><th>Type</th><th>Secret (redacted)</th>
    </tr>
  </thead>
  <tbody>
    {rows}
  </tbody>
</table>
"""

_LOOT_TABLE_TEMPLATE = """\
<table>
  <thead>
    <tr>
      <th>Session</th><th>File</th><th>Size</th>
    </tr>
  </thead>
  <tbody>
    {rows}
  </tbody>
</table>
"""


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _esc(s: str) -> str:
    """HTML-escape a string."""
    return (s
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;"))


def _badge(text: str, color: str = "grey") -> str:
    return f'<span class="badge badge-{color}">{_esc(text)}</span>'


def _fmt_size(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.0f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"


def _loot_files_for_session(sess_id: int) -> list[tuple[str, int]]:
    """Walk loot/<id>/ and return (filename, size) pairs."""
    loot_dir = os.path.join("loot", str(sess_id))
    if not os.path.isdir(loot_dir):
        return []
    results = []
    for root, _dirs, files in os.walk(loot_dir):
        for fname in files:
            fpath = os.path.join(root, fname)
            try:
                size = os.path.getsize(fpath)
            except OSError:
                size = 0
            rel = os.path.relpath(fpath, "loot")
            results.append((rel, size))
    return results


# ---------------------------------------------------------------------------
# Report builder
# ---------------------------------------------------------------------------

def _build_sessions_table(sessions: list) -> tuple[str, list[str]]:
    """Return (html_table, unique_host_list)."""
    if not sessions:
        return "<p>No sessions recorded.</p>", []

    rows = []
    unique_hosts: set[str] = set()
    for sess in sessions:
        unique_hosts.add(sess.ip)
        os_badge   = _badge(sess.os_name or "unknown", "blue")
        tag_badge  = _badge(sess.tag, "yellow") if sess.tag else "—"
        rows.append(
            f"<tr>"
            f"<td>{_esc(str(sess.id))}</td>"
            f"<td>{_esc(sess.ip)}:{_esc(str(sess.port))}</td>"
            f"<td>{os_badge}</td>"
            f"<td>{_esc(sess.hostname or '—')}</td>"
            f"<td>{_esc(sess.username or '—')}</td>"
            f"<td>{tag_badge}</td>"
            f"<td>{_esc(sess.uptime)}</td>"
            f"</tr>"
        )
    table_html = _SESSIONS_TABLE_TEMPLATE.format(rows="\n    ".join(rows))
    return table_html, list(unique_hosts)


def _build_creds_table(sessions: list) -> tuple[str, int]:
    """Try to pull creds from db; fall back to empty."""
    try:
        from megaploit.db.database import db
        creds = db.get_credentials()
    except Exception:
        creds = []

    if not creds:
        return "<p>No credentials captured.</p>", 0

    rows = []
    for c in creds:
        sec = (c.get("secret") or "")
        redacted = sec[:4] + "•" * min(len(sec) - 4, 20) if len(sec) > 4 else "•" * len(sec)
        rows.append(
            f"<tr>"
            f"<td>{_esc(c.get('host') or '—')}</td>"
            f"<td>{_esc(c.get('username') or '—')}</td>"
            f"<td>{_badge(c.get('cred_type') or '?', 'green')}</td>"
            f"<td><code>{_esc(redacted)}</code></td>"
            f"</tr>"
        )
    table_html = _CREDS_TABLE_TEMPLATE.format(rows="\n    ".join(rows))
    return table_html, len(creds)


def _build_loot_table(sessions: list) -> tuple[str, int]:
    all_loot: list[tuple[str, str, int]] = []
    for sess in sessions:
        for fpath, size in _loot_files_for_session(sess.id):
            all_loot.append((str(sess.id), fpath, size))

    if not all_loot:
        return "<p>No loot files found.</p>", 0

    rows = [
        f"<tr>"
        f"<td>{_esc(sid)}</td>"
        f"<td><code>{_esc(fpath)}</code></td>"
        f"<td>{_esc(_fmt_size(size))}</td>"
        f"</tr>"
        for sid, fpath, size in all_loot
    ]
    return _LOOT_TABLE_TEMPLATE.format(rows="\n    ".join(rows)), len(all_loot)


def _build_notes_section(sessions: list) -> str:
    blocks = []
    for sess in sessions:
        notes = getattr(sess, "notes", [])
        if not notes:
            continue
        notes_html = "<br>".join(_esc(str(n)) for n in notes)
        blocks.append(
            f'<div class="card">'
            f'<h3>Session #{_esc(str(sess.id))}  {_esc(sess.ip)}</h3>'
            f'{notes_html}'
            f'</div>'
        )
    return "\n".join(blocks) if blocks else "<p>No notes recorded.</p>"


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def generate_report(
    output_path: str,
    fmt: str = "html",
    engagement_name: str = "",
    engagement_desc: str = "",
    engagement_start: float = 0.0,
    sessions: list = None,
    command_history: list = None,
    **_kwargs: Any,
) -> None:
    """
    Generate a report and write it to *output_path*.

    Parameters
    ----------
    output_path : str
        Destination file path.
    fmt : str
        ``"html"``, ``"json"``, or ``"pdf"``
    engagement_name : str
    engagement_desc : str
    engagement_start : float
        Unix timestamp.
    sessions : list[Session]
        Active or previously active sessions.
    command_history : list[dict]
        Operator command history entries from ``_CommandHistory.tail()``.
    """
    sessions        = sessions or []
    command_history = command_history or []
    fmt             = fmt.lower()

    if fmt == "json":
        _write_json(output_path, engagement_name, engagement_desc,
                    engagement_start, sessions, command_history)
        return

    if fmt == "pdf":
        _write_pdf(output_path, engagement_name, engagement_desc,
                   engagement_start, sessions, command_history)
        return

    # HTML
    _write_html(output_path, engagement_name, engagement_desc,
                engagement_start, sessions, command_history)


def _write_json(path: str, name: str, desc: str, start: float, sessions: list,
                command_history: list) -> None:
    data: dict[str, Any] = {
        "engagement": {
            "name":  name,
            "desc":  desc,
            "start": datetime.datetime.utcfromtimestamp(start).isoformat() if start else "",
        },
        "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
        "sessions": [],
        "command_timeline": command_history,
    }
    for sess in sessions:
        try:
            data["sessions"].append(sess.to_dict())
        except AttributeError:
            data["sessions"].append({
                "id": getattr(sess, "id", "?"),
                "ip": getattr(sess, "ip", "?"),
            })
    try:
        from megaploit.db.database import db
        data["credentials"] = db.get_credentials()
    except Exception:
        data["credentials"] = []

    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, default=str)


def _build_timeline_section(command_history: list) -> str:
    """Build an HTML table of the command timeline from history entries."""
    if not command_history:
        return "<p>No command history available.</p>"
    rows = []
    for entry in command_history:
        ts      = _esc(str(entry.get("ts", "")))
        ctx     = _esc(str(entry.get("context", "")))
        sid     = _esc(str(entry.get("session_id", "")))
        cmd     = _esc(str(entry.get("cmd", ""))[:120])
        rows.append(
            f"<tr><td>{ts}</td><td>{ctx}</td><td>{sid}</td>"
            f"<td><code>{cmd}</code></td></tr>"
        )
    return (
        "<table><thead><tr>"
        "<th>Timestamp</th><th>Context</th><th>Session</th><th>Command</th>"
        "</tr></thead><tbody>"
        + "\n".join(rows)
        + "</tbody></table>"
    )


def _write_pdf(path: str, name: str, desc: str, start: float, sessions: list,
               command_history: list) -> None:
    """Generate a PDF report via weasyprint (optional dep).  Falls back to HTML."""
    try:
        from weasyprint import HTML as _WH  # type: ignore[import]
    except ImportError:
        # weasyprint not installed — write HTML and rename to .pdf so the caller
        # at least gets something useful
        html_path = path + ".html"
        _write_html(html_path, name, desc, start, sessions, command_history)
        import os as _os
        _os.rename(html_path, path)
        return

    # Build the HTML in memory then convert to PDF
    import io as _io
    buf = _io.StringIO()
    _write_html_to_stream(buf, name, desc, start, sessions, command_history)
    html_str = buf.getvalue()
    _WH(string=html_str).write_pdf(path)


def _write_html(path: str, name: str, desc: str, start: float, sessions: list,
                command_history: list) -> None:
    start_str = (
        datetime.datetime.utcfromtimestamp(start).strftime("%Y-%m-%d %H:%M UTC")
        if start else "unknown"
    )
    generated_at = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    sessions_table, unique_hosts = _build_sessions_table(sessions)
    creds_table, n_creds         = _build_creds_table(sessions)
    loot_table, n_loot           = _build_loot_table(sessions)
    notes_section                = _build_notes_section(sessions)
    timeline_section             = _build_timeline_section(command_history)

    desc_html = (
        f'<div class="card"><p>{_esc(desc)}</p></div>'
        if desc else ""
    )

    # Append timeline section to the template (injected before the footer)
    template = _HTML_TEMPLATE.replace(
        '<div class="footer">',
        '<h2>&#x23F1; Command Timeline</h2>\n  {timeline_section}\n\n  <div class="footer">',
    ).replace('{timeline_section}', timeline_section)

    html = template.format(
        engagement_name     = _esc(name or "Untitled Engagement"),
        engagement_name_esc = _esc(name or "Untitled Engagement"),
        engagement_start_str= start_str,
        generated_at        = generated_at,
        engagement_desc_html= desc_html,
        n_sessions          = len(sessions),
        n_creds             = n_creds,
        n_loot              = n_loot,
        n_hosts             = len(unique_hosts),
        sessions_table      = sessions_table,
        creds_table         = creds_table,
        loot_table          = loot_table,
        notes_section       = notes_section,
    )

    with open(path, "w", encoding="utf-8") as f:
        f.write(html)


def _write_html_to_stream(stream, name: str, desc: str, start: float, sessions: list,
                          command_history: list) -> None:
    """Write the HTML report to an in-memory stream (used by PDF generation)."""
    import io as _io
    tmp_path = "__megaploit_tmp_report__.html"
    _write_html(tmp_path, name, desc, start, sessions, command_history)
    import os as _os
    try:
        with open(tmp_path, "r", encoding="utf-8") as f:
            stream.write(f.read())
    finally:
        try:
            _os.remove(tmp_path)
        except OSError:
            pass
