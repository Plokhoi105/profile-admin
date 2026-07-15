from __future__ import annotations

import csv
import base64
import hashlib
import hmac
import json
import re
import secrets
import sqlite3
import string
import struct
import time
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Iterator
from urllib.parse import parse_qs, urlparse


EMAIL_RE = re.compile(r"^[^\s@,:]+@[^\s@,:]+\.[^\s@,:]+$")
LABEL_RE = re.compile(r"^(newTry\[(\d+)\])\s+", re.IGNORECASE)
PROFILE_NAME_RE = re.compile(r"newTry\[(\d+)]", re.IGNORECASE)
PREFIX_INDEX_RE = re.compile(r"^(.+?)\[(\d+)]$")
AUTO_CODE_START_INDEX = 51
AUTO_CODE_LENGTH = 10

COUNTRY_ALIASES = {
    "mozambique": "mz",
    "mozambik": "mz",
    "\u043c\u043e\u0437\u0430\u043c\u0431\u0438\u043a": "mz",
    "ukraine": "ua",
    "\u0443\u043a\u0440\u0430\u0438\u043d\u0430": "ua",
    "poland": "pl",
    "\u043f\u043e\u043b\u044c\u0448\u0430": "pl",
    "germany": "de",
    "\u0433\u0435\u0440\u043c\u0430\u043d\u0438\u044f": "de",
    "france": "fr",
    "\u0444\u0440\u0430\u043d\u0446\u0438\u044f": "fr",
    "spain": "es",
    "\u0438\u0441\u043f\u0430\u043d\u0438\u044f": "es",
    "italy": "it",
    "\u0438\u0442\u0430\u043b\u0438\u044f": "it",
    "portugal": "pt",
    "\u043f\u043e\u0440\u0442\u0443\u0433\u0430\u043b\u0438\u044f": "pt",
    "united states": "us",
    "usa": "us",
    "\u0441\u0448\u0430": "us",
    "united kingdom": "gb",
    "uk": "gb",
    "\u0432\u0435\u043b\u0438\u043a\u043e\u0431\u0440\u0438\u0442\u0430\u043d\u0438\u044f": "gb",
    "canada": "ca",
    "\u043a\u0430\u043d\u0430\u0434\u0430": "ca",
    "brazil": "br",
    "\u0431\u0440\u0430\u0437\u0438\u043b\u0438\u044f": "br",
    "mexico": "mx",
    "\u043c\u0435\u043a\u0441\u0438\u043a\u0430": "mx",
    "turkey": "tr",
    "\u0442\u0443\u0440\u0446\u0438\u044f": "tr",
    "india": "in",
    "\u0438\u043d\u0434\u0438\u044f": "in",
    "indonesia": "id",
    "\u0438\u043d\u0434\u043e\u043d\u0435\u0437\u0438\u044f": "id",
    "vietnam": "vn",
    "\u0432\u044c\u0435\u0442\u043d\u0430\u043c": "vn",
    "japan": "jp",
    "\u044f\u043f\u043e\u043d\u0438\u044f": "jp",
    "australia": "au",
    "\u0430\u0432\u0441\u0442\u0440\u0430\u043b\u0438\u044f": "au",
    "south africa": "za",
    "\u044e\u0430\u0440": "za",
}


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def normalize_totp_secret(value: str) -> str:
    secret = value.strip()
    if secret.casefold().startswith("otpauth://"):
        secret = parse_qs(urlparse(secret).query).get("secret", [""])[0]
    secret = re.sub(r"[\s-]+", "", secret).upper().rstrip("=")
    if not re.fullmatch(r"[A-Z2-7]{16,256}", secret):
        raise ValueError("Invalid authenticator key")
    try:
        decoded = base64.b32decode(secret + "=" * (-len(secret) % 8), casefold=True)
    except (ValueError, base64.binascii.Error) as exc:
        raise ValueError("Invalid authenticator key") from exc
    if len(decoded) < 10:
        raise ValueError("Authenticator key is too short")
    return secret


def totp_code(secret: str, timestamp: float | None = None, digits: int = 6, period: int = 30) -> str:
    normalized = normalize_totp_secret(secret)
    key = base64.b32decode(normalized + "=" * (-len(normalized) % 8), casefold=True)
    counter = int(time.time() if timestamp is None else timestamp) // period
    digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    value = (struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF) % (10**digits)
    return str(value).zfill(digits)


def normalize_country(value: str) -> str:
    value = value.strip().casefold()
    if not value:
        return ""
    if value in COUNTRY_ALIASES:
        return COUNTRY_ALIASES[value]
    if re.fullmatch(r"[a-z]{2}", value):
        return value
    raise ValueError(f"Unknown country {value!r}; use a two-letter ISO code")


def normalize_os(value: str) -> str:
    value = value.strip().casefold()
    if value in {"win", "windows"}:
        return "win"
    if value in {"mac", "macos", "osx"}:
        return "mac"
    raise ValueError("OS must be win or mac")


def profile_index(profile_name: str) -> int | None:
    match = PROFILE_NAME_RE.fullmatch(profile_name.strip())
    return int(match.group(1)) if match else None


def generate_code(length: int = AUTO_CODE_LENGTH) -> str:
    if length < 3:
        raise ValueError("Generated code length must be at least 3")
    characters = [
        secrets.choice(string.ascii_lowercase),
        secrets.choice(string.ascii_uppercase),
        secrets.choice(string.digits),
    ]
    alphabet = string.ascii_letters + string.digits
    characters.extend(secrets.choice(alphabet) for _ in range(length - len(characters)))
    secrets.SystemRandom().shuffle(characters)
    return "".join(characters)


def ensure_account_code(profile_name: str, code: str) -> str:
    code = code.strip().strip("*")
    if not code:
        return generate_code()
    return code


@dataclass(frozen=True)
class ImportedAccount:
    email: str
    code: str
    country: str
    fingerprint_os: str
    profile_name: str = ""
    requested_index: int | None = None


def parse_import(text: str, default_country: str, default_os: str) -> tuple[list[ImportedAccount], list[dict]]:
    country = normalize_country(default_country) if default_country.strip() else ""
    fingerprint_os = normalize_os(default_os)
    accounts: list[ImportedAccount] = []
    errors: list[dict] = []

    for line_number, raw_line in enumerate(text.splitlines(), start=1):
        line = raw_line.strip()
        if not line:
            continue

        profile_name = ""
        requested_index = None
        label_match = LABEL_RE.match(line)
        if label_match:
            profile_name = label_match.group(1)
            requested_index = int(label_match.group(2))
            line = line[label_match.end():].strip()

        parts = [part.strip() for part in line.split(",")]
        identity = parts[0]
        line_country = country
        if len(parts) > 1 and parts[1]:
            try:
                line_country = normalize_country(parts[1])
            except ValueError as exc:
                errors.append({"line": line_number, "value": raw_line, "error": str(exc)})
                continue
        if len(parts) > 2:
            errors.append({"line": line_number, "value": raw_line, "error": "Too many comma-separated fields"})
            continue

        email, separator, code = identity.partition(":")
        email = email.strip().casefold()
        code = code.strip().strip("*") if separator else ""
        if not EMAIL_RE.fullmatch(email):
            errors.append({"line": line_number, "value": raw_line, "error": "Invalid email"})
            continue
        accounts.append(
            ImportedAccount(
                email=email,
                code=code,
                country=line_country,
                fingerprint_os=fingerprint_os,
                profile_name=profile_name,
                requested_index=requested_index,
            )
        )
    return accounts, errors


class Database:
    def __init__(self, path: Path):
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.initialize()

    @contextmanager
    def connect(self) -> Iterator[sqlite3.Connection]:
        connection = sqlite3.connect(self.path, timeout=30, isolation_level="DEFERRED")
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA journal_mode = WAL")
        try:
            yield connection
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def initialize(self) -> None:
        with self.connect() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS accounts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    profile_name TEXT NOT NULL UNIQUE,
                    email TEXT NOT NULL UNIQUE COLLATE NOCASE,
                    code TEXT NOT NULL DEFAULT '',
                    country TEXT NOT NULL DEFAULT '',
                    fingerprint_os TEXT NOT NULL DEFAULT 'win',
                    status TEXT NOT NULL DEFAULT 'ready',
                    vision_profile_id TEXT NOT NULL DEFAULT '',
                    vision_proxy_id TEXT NOT NULL DEFAULT '',
                    proxy_endpoint TEXT NOT NULL DEFAULT '',
                    last_synced_at TEXT NOT NULL DEFAULT '',
                    fraud_score INTEGER NOT NULL DEFAULT -1,
                    fraud_ip TEXT NOT NULL DEFAULT '',
                    fraud_risk TEXT NOT NULL DEFAULT '',
                    fraud_checked_at TEXT NOT NULL DEFAULT '',
                    auth_secret TEXT NOT NULL DEFAULT '',
                    error TEXT NOT NULL DEFAULT '',
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS jobs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    status TEXT NOT NULL DEFAULT 'queued',
                    total INTEGER NOT NULL,
                    completed INTEGER NOT NULL DEFAULT 0,
                    failed INTEGER NOT NULL DEFAULT 0,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS job_accounts (
                    job_id INTEGER NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
                    account_id INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
                    PRIMARY KEY (job_id, account_id)
                );
                CREATE TABLE IF NOT EXISTS account_trash (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    original_id INTEGER NOT NULL,
                    snapshot TEXT NOT NULL,
                    deleted_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS ip_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    account_id INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
                    ip TEXT NOT NULL,
                    fraud_score INTEGER NOT NULL,
                    fraud_risk TEXT NOT NULL DEFAULT '',
                    checked_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS emails (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    account_id INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
                    message_id TEXT NOT NULL DEFAULT '',
                    sender TEXT NOT NULL DEFAULT '',
                    subject TEXT NOT NULL DEFAULT '',
                    body_text TEXT NOT NULL DEFAULT '',
                    extracted_code TEXT NOT NULL DEFAULT '',
                    received_at TEXT NOT NULL,
                    is_read INTEGER NOT NULL DEFAULT 0
                );
                CREATE UNIQUE INDEX IF NOT EXISTS idx_emails_msgid
                    ON emails(message_id) WHERE message_id != '';
                """
            )
            columns = {row["name"] for row in connection.execute("PRAGMA table_info(accounts)")}
            if "proxy_endpoint" not in columns:
                connection.execute("ALTER TABLE accounts ADD COLUMN proxy_endpoint TEXT NOT NULL DEFAULT ''")
            if "last_synced_at" not in columns:
                connection.execute("ALTER TABLE accounts ADD COLUMN last_synced_at TEXT NOT NULL DEFAULT ''")
            if "fraud_score" not in columns:
                connection.execute("ALTER TABLE accounts ADD COLUMN fraud_score INTEGER NOT NULL DEFAULT -1")
            if "fraud_ip" not in columns:
                connection.execute("ALTER TABLE accounts ADD COLUMN fraud_ip TEXT NOT NULL DEFAULT ''")
            if "fraud_risk" not in columns:
                connection.execute("ALTER TABLE accounts ADD COLUMN fraud_risk TEXT NOT NULL DEFAULT ''")
            if "fraud_checked_at" not in columns:
                connection.execute("ALTER TABLE accounts ADD COLUMN fraud_checked_at TEXT NOT NULL DEFAULT ''")
            if "auth_secret" not in columns:
                connection.execute("ALTER TABLE accounts ADD COLUMN auth_secret TEXT NOT NULL DEFAULT ''")
            if "bybit_cookies" not in columns:
                connection.execute("ALTER TABLE accounts ADD COLUMN bybit_cookies TEXT NOT NULL DEFAULT ''")
            if "deposit_address" not in columns:
                connection.execute("ALTER TABLE accounts ADD COLUMN deposit_address TEXT NOT NULL DEFAULT ''")
            if "deposit_chain" not in columns:
                connection.execute("ALTER TABLE accounts ADD COLUMN deposit_chain TEXT NOT NULL DEFAULT ''")
            email_columns = {row["name"] for row in connection.execute("PRAGMA table_info(emails)")}
            if email_columns and "extracted_code" not in email_columns:
                connection.execute("ALTER TABLE emails ADD COLUMN extracted_code TEXT NOT NULL DEFAULT ''")
            if {"deleted_at", "deleted_status"}.issubset(columns):
                legacy_rows = connection.execute(
                    "SELECT * FROM accounts WHERE deleted_at != ''"
                ).fetchall()
                for row in legacy_rows:
                    snapshot = dict(row)
                    snapshot["status"] = snapshot.get("deleted_status") or "not_created"
                    deleted_at = str(snapshot.get("deleted_at") or now_iso())
                    snapshot.pop("deleted_at", None)
                    snapshot.pop("deleted_status", None)
                    connection.execute(
                        "INSERT INTO account_trash (original_id, snapshot, deleted_at) VALUES (?, ?, ?)",
                        (snapshot["id"], json.dumps(snapshot, ensure_ascii=False), deleted_at),
                    )
                    connection.execute("DELETE FROM accounts WHERE id = ?", (snapshot["id"],))

    def next_profile_index(self, connection: sqlite3.Connection, prefix: str = "newTry") -> int:
        rows = connection.execute("SELECT profile_name FROM accounts").fetchall()
        values = []
        for row in rows:
            match = PREFIX_INDEX_RE.match(row["profile_name"])
            if match and match.group(1).casefold() == prefix.casefold():
                values.append(int(match.group(2)))
        return max(values, default=0) + 1

    def import_accounts(self, accounts: Iterable[ImportedAccount], prefix: str = "") -> dict:
        added = 0
        duplicates: list[str] = []
        name_prefix = prefix if prefix else "newTry"
        with self.connect() as connection:
            next_index = self.next_profile_index(connection, name_prefix)
            for account in accounts:
                existing = connection.execute("SELECT id FROM accounts WHERE email = ?", (account.email,)).fetchone()
                if existing:
                    duplicates.append(account.email)
                    continue
                profile_name = account.profile_name
                if profile_name and connection.execute(
                    "SELECT id FROM accounts WHERE profile_name = ?", (profile_name,)
                ).fetchone():
                    profile_name = ""
                if not profile_name:
                    while connection.execute(
                        "SELECT id FROM accounts WHERE profile_name = ?", (f"{name_prefix}[{next_index}]",)
                    ).fetchone():
                        next_index += 1
                    profile_name = f"{name_prefix}[{next_index}]"
                    next_index += 1
                code = ensure_account_code(profile_name, account.code)
                timestamp = now_iso()
                connection.execute(
                    """
                    INSERT INTO accounts (
                        profile_name, email, code, country, fingerprint_os, created_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        profile_name,
                        account.email,
                        code,
                        account.country,
                        account.fingerprint_os,
                        timestamp,
                        timestamp,
                    ),
                )
                added += 1
        return {"added": added, "duplicates": duplicates}

    def bootstrap(self, source: Path) -> int:
        with self.connect() as connection:
            if connection.execute("SELECT COUNT(*) FROM accounts").fetchone()[0]:
                return 0
        if not source.exists():
            return 0
        accounts, _ = parse_import(source.read_text(encoding="utf-8-sig"), "", "win")
        return self.import_accounts(accounts)["added"]

    def enrich_from_proxy_csv(self, source: Path) -> int:
        if not source.exists():
            return 0
        updated = 0
        with source.open("r", encoding="utf-8-sig", newline="") as handle:
            rows = list(csv.DictReader(handle))
        with self.connect() as connection:
            for row in rows:
                profile_name = (row.get("title") or "").strip()
                if not profile_name:
                    continue
                existing = connection.execute(
                    "SELECT id, country FROM accounts WHERE profile_name = ?", (profile_name,)
                ).fetchone()
                if not existing or existing["country"]:
                    continue
                password = row.get("proxy_password") or ""
                country_match = re.search(r"_country-([a-z]{2})(?:_|$)", password, re.IGNORECASE)
                country = country_match.group(1).lower() if country_match else ""
                fingerprint_os = (row.get("fingerprint_os") or "").strip().lower()
                if fingerprint_os not in {"win", "mac"}:
                    fingerprint_os = "win"
                connection.execute(
                    "UPDATE accounts SET country = ?, fingerprint_os = ?, updated_at = ? WHERE id = ?",
                    (country, fingerprint_os, now_iso(), existing["id"]),
                )
                updated += 1
        return updated

    def list_accounts(self) -> list[dict]:
        with self.connect() as connection:
            rows = connection.execute("SELECT * FROM accounts ORDER BY id").fetchall()
            unread = dict(connection.execute(
                "SELECT account_id, COUNT(*) FROM emails WHERE is_read = 0 GROUP BY account_id"
            ).fetchall())
            # Latest extracted code per account
            latest_codes = dict(connection.execute(
                "SELECT account_id, extracted_code FROM emails WHERE extracted_code != '' "
                "AND id IN (SELECT MAX(id) FROM emails WHERE extracted_code != '' GROUP BY account_id)"
            ).fetchall())
        result = []
        for row in rows:
            acc = self.public_account(row)
            acc["unread_emails"] = unread.get(acc["id"], 0)
            acc["last_email_code"] = latest_codes.get(acc["id"], "")
            result.append(acc)
        return result

    def account(self, account_id: int) -> dict | None:
        with self.connect() as connection:
            row = connection.execute("SELECT * FROM accounts WHERE id = ?", (account_id,)).fetchone()
        return self.public_account(row) if row else None

    @staticmethod
    def public_account(row: sqlite3.Row | dict) -> dict:
        account = dict(row)
        account["has_authenticator"] = bool(account.pop("auth_secret", ""))
        account["has_bybit_cookies"] = bool(account.pop("bybit_cookies", ""))
        return account

    def set_authenticator(self, account_id: int, secret: str) -> dict | None:
        normalized = normalize_totp_secret(secret)
        with self.connect() as connection:
            cursor = connection.execute(
                "UPDATE accounts SET auth_secret = ?, updated_at = ? WHERE id = ?",
                (normalized, now_iso(), account_id),
            )
            if not cursor.rowcount:
                return None
            row = connection.execute("SELECT * FROM accounts WHERE id = ?", (account_id,)).fetchone()
        return self.public_account(row)

    def set_bybit_cookies(self, account_id: int, cookies_json: str) -> dict | None:
        with self.connect() as connection:
            cursor = connection.execute(
                "UPDATE accounts SET bybit_cookies = ?, updated_at = ? WHERE id = ?",
                (cookies_json, now_iso(), account_id),
            )
            if not cursor.rowcount:
                return None
            row = connection.execute("SELECT * FROM accounts WHERE id = ?", (account_id,)).fetchone()
        return self.public_account(row)

    def get_bybit_cookies(self, account_id: int) -> str:
        with self.connect() as connection:
            row = connection.execute("SELECT bybit_cookies FROM accounts WHERE id = ?", (account_id,)).fetchone()
        return row["bybit_cookies"] if row else ""

    def set_deposit_address(self, account_id: int, address: str, chain: str = "") -> None:
        with self.connect() as connection:
            connection.execute(
                "UPDATE accounts SET deposit_address = ?, deposit_chain = ?, updated_at = ? WHERE id = ?",
                (address, chain, now_iso(), account_id),
            )

    def authenticator_codes(self, timestamp: float | None = None) -> list[dict]:
        now = time.time() if timestamp is None else timestamp
        with self.connect() as connection:
            rows = connection.execute(
                "SELECT id, auth_secret FROM accounts WHERE auth_secret != '' ORDER BY id"
            ).fetchall()
        remaining = 30 - (int(now) % 30)
        return [
            {"id": int(row["id"]), "code": totp_code(row["auth_secret"], now), "remaining": remaining}
            for row in rows
        ]

    def trashed_accounts(self) -> list[dict]:
        with self.connect() as connection:
            rows = connection.execute(
                "SELECT * FROM account_trash ORDER BY deleted_at DESC, id DESC"
            ).fetchall()
        accounts = []
        for row in rows:
            snapshot = json.loads(row["snapshot"])
            snapshot.pop("auth_secret", None)
            snapshot.pop("has_authenticator", None)
            snapshot.update(
                {
                    "trash_id": row["id"],
                    "original_id": row["original_id"],
                    "deleted_at": row["deleted_at"],
                }
            )
            accounts.append(snapshot)
        return accounts

    def update_account(self, account_id: int, changes: dict) -> dict | None:
        allowed = {"profile_name", "email", "country", "fingerprint_os", "code"}
        fields = {key: value for key, value in changes.items() if key in allowed}
        if "profile_name" in fields:
            profile_name = str(fields["profile_name"]).strip()
            if not profile_name or len(profile_name) > 120 or any(character in profile_name for character in "\r\n"):
                raise ValueError("Profile name must contain 1-120 characters")
            fields["profile_name"] = profile_name
        if "email" in fields:
            email = str(fields["email"]).strip().casefold()
            if not EMAIL_RE.fullmatch(email):
                raise ValueError("Invalid email")
            fields["email"] = email
        if "country" in fields:
            fields["country"] = normalize_country(str(fields["country"]))
        if "fingerprint_os" in fields:
            fields["fingerprint_os"] = normalize_os(str(fields["fingerprint_os"]))
        if not fields:
            raise ValueError("No editable fields supplied")
        with self.connect() as connection:
            existing = connection.execute(
                "SELECT * FROM accounts WHERE id = ?",
                (account_id,),
            ).fetchone()
            if not existing:
                return None
            if existing["status"] in {"queued", "running", "rotating", "deleting"}:
                raise ValueError("Account is busy")
            if "code" in fields:
                target_name = str(fields.get("profile_name") or existing["profile_name"])
                fields["code"] = ensure_account_code(target_name, str(fields["code"]))
            fields = {key: value for key, value in fields.items() if value != existing[key]}
            if not fields:
                return self.public_account(existing)
            if existing["vision_profile_id"] and {"profile_name", "email", "code", "country"}.intersection(fields):
                fields["status"] = "pending_sync"
            fields["updated_at"] = now_iso()
            assignments = ", ".join(f"{key} = ?" for key in fields)
            try:
                connection.execute(
                    f"UPDATE accounts SET {assignments} WHERE id = ?", (*fields.values(), account_id)
                )
            except sqlite3.IntegrityError as exc:
                raise ValueError("Profile name and email must be unique") from exc
            row = connection.execute("SELECT * FROM accounts WHERE id = ?", (account_id,)).fetchone()
        return self.public_account(row) if row else None

    def delete_account(
        self,
        account_id: int,
        previous_status: str = "not_created",
        clear_vision: bool = False,
    ) -> bool:
        with self.connect() as connection:
            row = connection.execute("SELECT * FROM accounts WHERE id = ?", (account_id,)).fetchone()
            if not row:
                return False
            if row["status"] in {"queued", "running", "rotating"}:
                raise ValueError("Account is busy")
            snapshot = dict(row)
            snapshot["status"] = "not_created" if clear_vision else previous_status
            if clear_vision:
                snapshot.update(
                    {
                        "vision_profile_id": "",
                        "vision_proxy_id": "",
                        "proxy_endpoint": "",
                        "error": "",
                    }
                )
            snapshot.pop("deleted_at", None)
            snapshot.pop("deleted_status", None)
            timestamp = now_iso()
            connection.execute(
                "INSERT INTO account_trash (original_id, snapshot, deleted_at) VALUES (?, ?, ?)",
                (account_id, json.dumps(snapshot, ensure_ascii=False), timestamp),
            )
            connection.execute("DELETE FROM accounts WHERE id = ?", (account_id,))
        return True

    def restore_account(self, trash_id: int) -> dict | None:
        with self.connect() as connection:
            row = connection.execute(
                "SELECT * FROM account_trash WHERE id = ?", (trash_id,)
            ).fetchone()
            if not row:
                return None
            snapshot = json.loads(row["snapshot"])
            status = str(snapshot.get("status") or "not_created")
            if status in {"queued", "running", "rotating", "deleting", "deleted"}:
                status = "not_created"
            values = {
                "id": int(row["original_id"]),
                "profile_name": snapshot["profile_name"],
                "email": snapshot["email"],
                "code": snapshot.get("code", ""),
                "country": snapshot.get("country", ""),
                "fingerprint_os": snapshot.get("fingerprint_os", "win"),
                "status": status,
                "vision_profile_id": snapshot.get("vision_profile_id", ""),
                "vision_proxy_id": snapshot.get("vision_proxy_id", ""),
                "proxy_endpoint": snapshot.get("proxy_endpoint", ""),
                "last_synced_at": snapshot.get("last_synced_at", ""),
                "fraud_score": int(snapshot.get("fraud_score", -1)),
                "fraud_ip": snapshot.get("fraud_ip", ""),
                "fraud_risk": snapshot.get("fraud_risk", ""),
                "fraud_checked_at": snapshot.get("fraud_checked_at", ""),
                "auth_secret": snapshot.get("auth_secret", ""),
                "error": snapshot.get("error", ""),
                "created_at": snapshot.get("created_at", now_iso()),
                "updated_at": now_iso(),
            }
            try:
                connection.execute(
                    """
                    INSERT INTO accounts (
                        id, profile_name, email, code, country, fingerprint_os, status,
                        vision_profile_id, vision_proxy_id, proxy_endpoint, last_synced_at,
                        fraud_score, fraud_ip, fraud_risk, fraud_checked_at, auth_secret, error, created_at, updated_at
                    ) VALUES (
                        :id, :profile_name, :email, :code, :country, :fingerprint_os, :status,
                        :vision_profile_id, :vision_proxy_id, :proxy_endpoint, :last_synced_at,
                        :fraud_score, :fraud_ip, :fraud_risk, :fraud_checked_at, :auth_secret,
                        :error, :created_at, :updated_at
                    )
                    """,
                    values,
                )
            except sqlite3.IntegrityError as exc:
                raise ValueError("A profile with this name or email already exists") from exc
            connection.execute("DELETE FROM account_trash WHERE id = ?", (trash_id,))
            restored = connection.execute("SELECT * FROM accounts WHERE id = ?", (values["id"],)).fetchone()
        return self.public_account(restored) if restored else None

    def permanently_delete_uncreated_account(self, account_id: int) -> bool:
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT status, vision_profile_id FROM accounts WHERE id = ?", (account_id,)
            ).fetchone()
            if not row:
                return False
            if row["vision_profile_id"]:
                raise ValueError("Created Vision profiles cannot be permanently deleted here")
            if row["status"] in {"queued", "running", "rotating", "deleting"}:
                raise ValueError("Account is busy")
            active = connection.execute(
                """
                SELECT COUNT(*) FROM job_accounts
                JOIN jobs ON jobs.id = job_accounts.job_id
                WHERE job_accounts.account_id = ? AND jobs.status IN ('queued', 'running')
                """,
                (account_id,),
            ).fetchone()[0]
            if active:
                raise ValueError("Account is part of an active job")
            connection.execute("DELETE FROM accounts WHERE id = ?", (account_id,))
        return True

    def create_job(self, account_ids: list[int], country: str = "", fingerprint_os: str = "") -> int:
        if not account_ids:
            raise ValueError("Select at least one account")
        country = normalize_country(country) if country.strip() else ""
        fingerprint_os = normalize_os(fingerprint_os) if fingerprint_os.strip() else ""
        timestamp = now_iso()
        unique_ids = list(dict.fromkeys(int(value) for value in account_ids))
        placeholders = ",".join("?" for _ in unique_ids)
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            rows = connection.execute(
                f"SELECT id, profile_name, code, country, status FROM accounts WHERE id IN ({placeholders})",
                unique_ids,
            ).fetchall()
            if len(rows) != len(unique_ids):
                raise ValueError("Some selected accounts no longer exist")
            active = connection.execute(
                f"""
                SELECT COUNT(*) FROM job_accounts
                JOIN jobs ON jobs.id = job_accounts.job_id
                WHERE job_accounts.account_id IN ({placeholders})
                  AND jobs.status IN ('queued', 'running')
                """,
                unique_ids,
            ).fetchone()[0]
            if active:
                raise ValueError("Some selected accounts already have an active job")
            if any(row["status"] in {"rotating", "deleting"} for row in rows):
                raise ValueError("A selected account is busy")
            if not country and any(not row["country"] for row in rows):
                raise ValueError("Every selected account must have a country")
            for row in rows:
                code = ensure_account_code(row["profile_name"], row["code"])
                if code != row["code"]:
                    connection.execute(
                        "UPDATE accounts SET code = ?, updated_at = ? WHERE id = ?",
                        (code, timestamp, row["id"]),
                    )
            if country or fingerprint_os:
                updates = []
                values: list[str | int] = []
                if country:
                    updates.append("country = ?")
                    values.append(country)
                if fingerprint_os:
                    updates.append("fingerprint_os = ?")
                    values.append(fingerprint_os)
                updates.extend(["status = 'queued'", "error = ''", "updated_at = ?"])
                values.append(timestamp)
                values.extend(unique_ids)
                connection.execute(
                    f"UPDATE accounts SET {', '.join(updates)} WHERE id IN ({placeholders})", values
                )
            else:
                connection.execute(
                    f"UPDATE accounts SET status = 'queued', error = '', updated_at = ? WHERE id IN ({placeholders})",
                    [timestamp, *unique_ids],
                )
            cursor = connection.execute(
                "INSERT INTO jobs (status, total, created_at, updated_at) VALUES ('queued', ?, ?, ?)",
                (len(unique_ids), timestamp, timestamp),
            )
            job_id = int(cursor.lastrowid)
            connection.executemany(
                "INSERT INTO job_accounts (job_id, account_id) VALUES (?, ?)",
                [(job_id, account_id) for account_id in unique_ids],
            )
        return job_id

    def job(self, job_id: int) -> dict | None:
        with self.connect() as connection:
            row = connection.execute("SELECT * FROM jobs WHERE id = ?", (job_id,)).fetchone()
            if not row:
                return None
            errors = connection.execute(
                """
                SELECT accounts.error FROM accounts
                JOIN job_accounts ON job_accounts.account_id = accounts.id
                WHERE job_accounts.job_id = ? AND accounts.error != '' ORDER BY accounts.id
                """,
                (job_id,),
            ).fetchall()
        result = dict(row)
        result["errors"] = [str(error["error"]) for error in errors]
        return result

    def job_accounts(self, job_id: int) -> list[dict]:
        with self.connect() as connection:
            rows = connection.execute(
                """
                SELECT accounts.* FROM accounts
                JOIN job_accounts ON job_accounts.account_id = accounts.id
                WHERE job_accounts.job_id = ? ORDER BY accounts.id
                """,
                (job_id,),
            ).fetchall()
        return [dict(row) for row in rows]

    def claim_next_job(self) -> int | None:
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT id FROM jobs WHERE status = 'queued' ORDER BY id LIMIT 1"
            ).fetchone()
            if not row:
                return None
            job_id = int(row["id"])
            connection.execute(
                "UPDATE jobs SET status = 'running', updated_at = ? WHERE id = ? AND status = 'queued'",
                (now_iso(), job_id),
            )
            return job_id

    def fail_interrupted_jobs(self) -> int:
        message = "Worker was interrupted; verify Vision before retrying"
        with self.connect() as connection:
            rows = connection.execute("SELECT id FROM jobs WHERE status = 'running'").fetchall()
            for row in rows:
                job_id = int(row["id"])
                connection.execute(
                    "UPDATE jobs SET status = 'interrupted', updated_at = ? WHERE id = ?",
                    (now_iso(), job_id),
                )
                connection.execute(
                    """
                    UPDATE accounts SET status = 'error', error = ?, updated_at = ?
                    WHERE id IN (SELECT account_id FROM job_accounts WHERE job_id = ?)
                      AND status = 'queued'
                    """,
                    (message, now_iso(), job_id),
                )
        return len(rows)

    def fail_job(self, job_id: int, error: str) -> None:
        accounts = self.job_accounts(job_id)
        job = self.job(job_id) or {}
        completed = int(job.get("completed", 0))
        failed = int(job.get("failed", 0))
        for account in accounts:
            if account["status"] == "queued":
                failed += 1
                self.mark_account_result(account["id"], error=error)
        self.mark_job(job_id, "failed", completed, failed)

    def mark_job(self, job_id: int, status: str, completed: int, failed: int) -> None:
        with self.connect() as connection:
            connection.execute(
                "UPDATE jobs SET status = ?, completed = ?, failed = ?, updated_at = ? WHERE id = ?",
                (status, completed, failed, now_iso(), job_id),
            )

    def mark_account_result(
        self,
        account_id: int,
        *,
        profile_id: str = "",
        proxy_id: str = "",
        proxy_endpoint: str = "",
        error: str = "",
    ) -> None:
        with self.connect() as connection:
            connection.execute(
                """
                UPDATE accounts SET status = ?, vision_profile_id = ?, vision_proxy_id = ?,
                    proxy_endpoint = ?, error = ?, updated_at = ? WHERE id = ?
                """,
                (
                    "error" if error else "created",
                    profile_id,
                    proxy_id,
                    proxy_endpoint,
                    error,
                    now_iso(),
                    account_id,
                ),
            )

    def mark_synced(
        self,
        account_id: int,
        *,
        exists: bool,
        profile_id: str = "",
        proxy_id: str = "",
        proxy_endpoint: str = "",
        error: str = "",
        preserve_pending: bool = False,
    ) -> bool:
        status = "created" if exists else "not_created"
        with self.connect() as connection:
            cursor = connection.execute(
                """
                UPDATE accounts SET status = CASE
                        WHEN ? AND status = 'pending_sync' AND ? THEN 'pending_sync'
                        ELSE ?
                    END,
                    vision_profile_id = ?, vision_proxy_id = ?,
                    proxy_endpoint = ?, last_synced_at = ?, error = ?, updated_at = ?
                WHERE id = ? AND status NOT IN ('queued', 'running', 'rotating')
                """,
                (
                    preserve_pending,
                    exists,
                    status,
                    profile_id,
                    proxy_id,
                    proxy_endpoint,
                    now_iso(),
                    error,
                    now_iso(),
                    account_id,
                ),
            )
        return cursor.rowcount == 1

    def begin_proxy_rotation(self, account_id: int) -> bool:
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            active = connection.execute(
                """
                SELECT COUNT(*) FROM job_accounts
                JOIN jobs ON jobs.id = job_accounts.job_id
                WHERE job_accounts.account_id = ? AND jobs.status IN ('queued', 'running')
                """,
                (account_id,),
            ).fetchone()[0]
            if active:
                return False
            cursor = connection.execute(
                "UPDATE accounts SET status = 'rotating', updated_at = ? WHERE id = ? AND status = 'created'",
                (now_iso(), account_id),
            )
            return cursor.rowcount == 1

    def fail_proxy_rotation(self, account_id: int, error: str) -> None:
        with self.connect() as connection:
            connection.execute(
                """
                UPDATE accounts SET status = 'created', error = ?, updated_at = ?
                WHERE id = ? AND status = 'rotating'
                """,
                (error, now_iso(), account_id),
            )

    def begin_account_delete(self, account_id: int) -> str | None:
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute("SELECT status FROM accounts WHERE id = ?", (account_id,)).fetchone()
            if not row or row["status"] in {"queued", "running", "rotating", "deleting"}:
                return None
            active = connection.execute(
                """
                SELECT COUNT(*) FROM job_accounts
                JOIN jobs ON jobs.id = job_accounts.job_id
                WHERE job_accounts.account_id = ? AND jobs.status IN ('queued', 'running')
                """,
                (account_id,),
            ).fetchone()[0]
            if active:
                return None
            previous_status = str(row["status"])
            connection.execute(
                "UPDATE accounts SET status = 'deleting', updated_at = ? WHERE id = ?",
                (now_iso(), account_id),
            )
            return previous_status

    def cancel_account_delete(self, account_id: int, previous_status: str) -> None:
        with self.connect() as connection:
            connection.execute(
                "UPDATE accounts SET status = ?, updated_at = ? WHERE id = ? AND status = 'deleting'",
                (previous_status, now_iso(), account_id),
            )

    def mark_vision_deleted(self, account_id: int) -> bool:
        with self.connect() as connection:
            cursor = connection.execute(
                """
                UPDATE accounts SET status = 'not_created', vision_profile_id = '',
                    vision_proxy_id = '', proxy_endpoint = '', last_synced_at = ?,
                    error = '', updated_at = ?
                WHERE id = ? AND status = 'deleting'
                """,
                (now_iso(), now_iso(), account_id),
            )
        return cursor.rowcount == 1

    def mark_proxy_changed(
        self, account_id: int, proxy_id: str, proxy_endpoint: str, country: str = ""
    ) -> None:
        with self.connect() as connection:
            if country:
                connection.execute(
                    """
                    UPDATE accounts SET status = 'created', country = ?, vision_proxy_id = ?,
                        proxy_endpoint = ?, last_synced_at = ?, fraud_score = -1, fraud_ip = '',
                        fraud_risk = '', fraud_checked_at = '', error = '', updated_at = ? WHERE id = ?
                    """,
                    (country, proxy_id, proxy_endpoint, now_iso(), now_iso(), account_id),
                )
            else:
                connection.execute(
                    """
                    UPDATE accounts SET status = 'created', vision_proxy_id = ?, proxy_endpoint = ?,
                        last_synced_at = ?, fraud_score = -1, fraud_ip = '', fraud_risk = '',
                        fraud_checked_at = '', error = '', updated_at = ? WHERE id = ?
                    """,
                    (proxy_id, proxy_endpoint, now_iso(), now_iso(), account_id),
                )

    def mark_fraud_checked(self, account_id: int, score: int, ip: str, risk: str) -> dict | None:
        if not 0 <= int(score) <= 100:
            raise ValueError("Fraud score must be between 0 and 100")
        timestamp = now_iso()
        with self.connect() as connection:
            connection.execute(
                """
                UPDATE accounts SET fraud_score = ?, fraud_ip = ?, fraud_risk = ?,
                    fraud_checked_at = ?, updated_at = ? WHERE id = ?
                """,
                (int(score), ip, risk, timestamp, timestamp, account_id),
            )
            connection.execute(
                "INSERT INTO ip_history (account_id, ip, fraud_score, fraud_risk, checked_at) VALUES (?, ?, ?, ?, ?)",
                (account_id, ip, int(score), risk, timestamp),
            )
            row = connection.execute("SELECT * FROM accounts WHERE id = ?", (account_id,)).fetchone()
        return self.public_account(row) if row else None

    def ip_history(self, account_id: int, limit: int = 50) -> list[dict]:
        with self.connect() as connection:
            rows = connection.execute(
                "SELECT ip, fraud_score, fraud_risk, checked_at FROM ip_history WHERE account_id = ? ORDER BY id DESC LIMIT ?",
                (account_id, limit),
            ).fetchall()
        return [dict(row) for row in rows]

    def store_email(self, account_id: int, message_id: str, sender: str, subject: str, body_text: str, extracted_code: str, received_at: str) -> int | None:
        with self.connect() as connection:
            if message_id:
                existing = connection.execute("SELECT id FROM emails WHERE message_id = ?", (message_id,)).fetchone()
                if existing:
                    return None
            cursor = connection.execute(
                "INSERT INTO emails (account_id, message_id, sender, subject, body_text, extracted_code, received_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (account_id, message_id, sender, subject, body_text, extracted_code, received_at),
            )
            return cursor.lastrowid

    def account_emails(self, account_id: int, limit: int = 50) -> list[dict]:
        with self.connect() as connection:
            rows = connection.execute(
                "SELECT id, sender, subject, body_text, extracted_code, received_at, is_read FROM emails WHERE account_id = ? ORDER BY id DESC LIMIT ?",
                (account_id, limit),
            ).fetchall()
        return [dict(row) for row in rows]

    def mark_email_read(self, email_id: int) -> bool:
        with self.connect() as connection:
            cursor = connection.execute("UPDATE emails SET is_read = 1 WHERE id = ? AND is_read = 0", (email_id,))
            return cursor.rowcount == 1

    def unread_email_count(self, account_id: int) -> int:
        with self.connect() as connection:
            row = connection.execute("SELECT COUNT(*) FROM emails WHERE account_id = ? AND is_read = 0", (account_id,)).fetchone()
            return row[0]

    def all_account_emails_by_address(self) -> dict[str, int]:
        """Return {email_lower: account_id} mapping for all accounts."""
        with self.connect() as connection:
            rows = connection.execute("SELECT id, email FROM accounts").fetchall()
        return {row["email"].lower(): row["id"] for row in rows}
