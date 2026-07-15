"""IMAP mail checker for iCloud Hide My Email accounts."""
from __future__ import annotations

import email
import email.header
import email.utils
import imaplib
import os
import re
import time
import traceback
from email.message import Message
from pathlib import Path
from typing import Any

from admin_panel.core import Database, now_iso


def decode_header_value(raw: str) -> str:
    """Decode RFC 2047 encoded header value."""
    if not raw:
        return ""
    parts = email.header.decode_header(raw)
    decoded = []
    for data, charset in parts:
        if isinstance(data, bytes):
            decoded.append(data.decode(charset or "utf-8", errors="replace"))
        else:
            decoded.append(data)
    return " ".join(decoded)


def extract_text_body(msg: Message) -> str:
    """Extract plain text body from email message."""
    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            disposition = str(part.get("Content-Disposition", ""))
            if content_type == "text/plain" and "attachment" not in disposition:
                payload = part.get_payload(decode=True)
                if payload:
                    charset = part.get_content_charset() or "utf-8"
                    return payload.decode(charset, errors="replace")
        # Fallback to text/html if no plain text
        for part in msg.walk():
            content_type = part.get_content_type()
            disposition = str(part.get("Content-Disposition", ""))
            if content_type == "text/html" and "attachment" not in disposition:
                payload = part.get_payload(decode=True)
                if payload:
                    charset = part.get_content_charset() or "utf-8"
                    html = payload.decode(charset, errors="replace")
                    return _strip_html(html)
    else:
        payload = msg.get_payload(decode=True)
        if payload:
            charset = msg.get_content_charset() or "utf-8"
            text = payload.decode(charset, errors="replace")
            if msg.get_content_type() == "text/html":
                return _strip_html(text)
            return text
    return ""


def _strip_html(html: str) -> str:
    """HTML to text conversion."""
    # Remove style/script blocks entirely
    text = re.sub(r"<style[^>]*>.*?</style>", "", html, flags=re.IGNORECASE | re.DOTALL)
    text = re.sub(r"<script[^>]*>.*?</script>", "", text, flags=re.IGNORECASE | re.DOTALL)
    # Remove HTML comments
    text = re.sub(r"<!--.*?-->", "", text, flags=re.DOTALL)
    # Line breaks
    text = re.sub(r"<br\s*/?>", "\n", text, flags=re.IGNORECASE)
    text = re.sub(r"</?(?:p|div|tr|li|h[1-6])[^>]*>", "\n", text, flags=re.IGNORECASE)
    # Remove remaining tags
    text = re.sub(r"<[^>]+>", "", text)
    # Decode entities
    text = re.sub(r"&nbsp;", " ", text)
    text = re.sub(r"&amp;", "&", text)
    text = re.sub(r"&lt;", "<", text)
    text = re.sub(r"&gt;", ">", text)
    text = re.sub(r"&[a-zA-Z]+;", "", text)
    text = re.sub(r"&#\d+;", "", text)
    # Clean whitespace
    text = re.sub(r"[ \t]+", " ", text)
    text = re.sub(r"\n[ \t]+", "\n", text)
    text = re.sub(r"\n{3,}", "\n\n", text)
    return text.strip()


def extract_verification_code(subject: str, body: str) -> str:
    """Try to extract a verification/OTP code from email subject or body."""
    text = subject + "\n" + body
    # Priority 1: code/verification keyword followed by a number
    patterns = [
        r'(?:verification|security|confirm)\s*code[:\s]+(\d{4,8})',
        r'(?:code|код|pin|otp|пароль)[:\s]+(\d{4,8})',
        r'(?:code|код|pin|otp)[:\s]+([A-Z0-9]{4,8})',
        r'(?:is|:)\s*(\d{6})\b',  # "is 123456" or ": 123456"
    ]
    for pattern in patterns:
        match = re.search(pattern, text, re.IGNORECASE)
        if match:
            return match.group(1).replace(" ", "").replace("-", "")
    # Priority 2: standalone 6-digit number on its own line (common for OTP)
    match = re.search(r'^\s*(\d{6})\s*$', text, re.MULTILINE)
    if match:
        return match.group(1)
    return ""


def extract_recipients(msg: Message) -> list[str]:
    """Extract all To/Delivered-To/X-Original-To addresses."""
    addresses: list[str] = []
    for header in ("To", "Delivered-To", "X-Original-To", "Cc"):
        raw = msg.get(header, "")
        if raw:
            decoded = decode_header_value(raw)
            for _name, addr in email.utils.getaddresses([decoded]):
                if addr:
                    addresses.append(addr.lower())
    return addresses


class MailChecker:
    """Periodically checks iCloud IMAP for new emails and stores them in DB."""

    def __init__(self, db: Database, imap_host: str, imap_user: str, imap_pass: str, interval: int = 60):
        self.db = db
        self.imap_host = imap_host
        self.imap_user = imap_user
        self.imap_pass = imap_pass
        self.interval = interval

    def check_once(self) -> int:
        """Check IMAP inbox for new emails. Returns count of new emails stored."""
        account_map = self.db.all_account_emails_by_address()
        if not account_map:
            return 0

        stored = 0
        conn = imaplib.IMAP4_SSL(self.imap_host, 993)
        try:
            conn.login(self.imap_user, self.imap_pass)
            conn.select("INBOX", readonly=True)

            # Search for emails from last 24 hours
            since = time.strftime("%d-%b-%Y", time.gmtime(time.time() - 86400))
            status, data = conn.search(None, f'(SINCE {since})')
            if status != "OK" or not data[0]:
                return 0

            msg_ids = data[0].split()
            # Process last 100 at most
            for msg_id in msg_ids[-100:]:
                try:
                    status, msg_data = conn.fetch(msg_id, "(BODY.PEEK[])")
                    if status != "OK" or not msg_data:
                        continue
                    # Find the tuple part containing raw email bytes
                    raw_email = None
                    for part in msg_data:
                        if isinstance(part, tuple) and len(part) == 2 and isinstance(part[1], bytes):
                            raw_email = part[1]
                            break
                    if raw_email is None:
                        continue
                    msg = email.message_from_bytes(raw_email)

                    message_id = msg.get("Message-ID", "").strip()
                    sender = decode_header_value(msg.get("From", ""))
                    subject = decode_header_value(msg.get("Subject", ""))
                    body = extract_text_body(msg)
                    # Truncate body to 5000 chars
                    if len(body) > 5000:
                        body = body[:5000] + "..."

                    date_str = msg.get("Date", "")
                    parsed_date = email.utils.parsedate_to_datetime(date_str) if date_str else None
                    received_at = parsed_date.isoformat(timespec="seconds") if parsed_date else now_iso()

                    recipients = extract_recipients(msg)

                    for recipient in recipients:
                        account_id = account_map.get(recipient)
                        if account_id is not None:
                            code = extract_verification_code(subject, body)
                            result = self.db.store_email(
                                account_id=account_id,
                                message_id=message_id,
                                sender=sender,
                                subject=subject,
                                body_text=body,
                                extracted_code=code,
                                received_at=received_at,
                            )
                            if result is not None:
                                stored += 1
                            break
                except Exception:
                    traceback.print_exc()
                    continue
        finally:
            try:
                conn.logout()
            except Exception:
                pass
        return stored

    def run_forever(self) -> None:
        """Run mail checking loop."""
        print(f"Mail checker started: {self.imap_user}@{self.imap_host}, interval={self.interval}s", flush=True)
        while True:
            try:
                count = self.check_once()
                if count:
                    print(f"Mail checker: stored {count} new email(s)", flush=True)
            except Exception as exc:
                print(f"Mail checker error: {exc.__class__.__name__}: {exc}", flush=True)
            time.sleep(self.interval)


def main() -> None:
    """Entry point for mail checker service."""
    db_path = Path(os.environ.get("ADMIN_DB_PATH", "profiles.sqlite3"))
    imap_host = os.environ.get("IMAP_HOST", "imap.mail.me.com")
    imap_user = os.environ.get("IMAP_USER", "")
    imap_pass = os.environ.get("IMAP_PASS", "")
    interval = int(os.environ.get("MAIL_CHECK_INTERVAL", "60"))

    if not imap_user or not imap_pass:
        print("IMAP_USER and IMAP_PASS must be set", flush=True)
        return

    db = Database(db_path)
    checker = MailChecker(db, imap_host, imap_user, imap_pass, interval)
    checker.run_forever()


if __name__ == "__main__":
    main()
