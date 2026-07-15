from __future__ import annotations

import base64
import json
import os
import secrets
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter
from dataclasses import dataclass
from typing import Any

from admin_panel.core import normalize_country, normalize_os


MAX_ACCOUNT_IDS = 100
MAX_DOWNLOAD_BYTES = 1_000_000
PENDING_TTL_SECONDS = 120
ACCOUNTS_PAGE_SIZE = 10


class BotError(Exception):
    pass


class ConfigError(BotError):
    pass


class CommandError(BotError):
    pass


def parse_allowed_user_ids(value: str) -> set[int]:
    ids: set[int] = set()
    for raw in value.split(","):
        item = raw.strip()
        if not item:
            continue
        try:
            user_id = int(item)
        except ValueError as exc:
            raise ConfigError("TELEGRAM_ALLOWED_USER_IDS must contain numeric ids") from exc
        if user_id <= 0:
            raise ConfigError("TELEGRAM_ALLOWED_USER_IDS must contain positive ids")
        ids.add(user_id)
    if not ids:
        raise ConfigError("TELEGRAM_ALLOWED_USER_IDS is required")
    return ids


def parse_account_ids(value: str, limit: int = MAX_ACCOUNT_IDS) -> list[int]:
    if not value.strip():
        raise CommandError("Account ids are required")
    result: list[int] = []
    seen: set[int] = set()
    parts = value.replace(" ", ",").split(",")
    for raw in parts:
        item = raw.strip()
        if not item:
            continue
        if "-" in item:
            left, separator, right = item.partition("-")
            if not separator or not left.isdigit() or not right.isdigit():
                raise CommandError("Use ids like 1,2,5-8")
            start = int(left)
            end = int(right)
            if start <= 0 or end <= 0 or end < start:
                raise CommandError("Invalid account id range")
            values = range(start, end + 1)
        else:
            if not item.isdigit():
                raise CommandError("Use numeric account ids")
            account_id = int(item)
            if account_id <= 0:
                raise CommandError("Account ids must be positive")
            values = (account_id,)
        for account_id in values:
            if account_id in seen:
                continue
            if len(result) >= limit:
                raise CommandError(f"Select at most {limit} account ids")
            seen.add(account_id)
            result.append(account_id)
    if not result:
        raise CommandError("Account ids are required")
    return result


def _command_name(token: str) -> str:
    return token.split("@", 1)[0].casefold()


@dataclass(frozen=True)
class CreateCommand:
    country: str
    fingerprint_os: str
    account_ids: list[int]


@dataclass(frozen=True)
class ImportCommand:
    country: str
    fingerprint_os: str


def parse_create_command(text: str) -> CreateCommand:
    parts = text.strip().split(maxsplit=3)
    if len(parts) != 4 or _command_name(parts[0]) != "/create":
        raise CommandError("Usage: /create COUNTRY OS IDS_OR_RANGE")
    try:
        country = normalize_country(parts[1])
        fingerprint_os = normalize_os(parts[2])
    except ValueError as exc:
        raise CommandError(str(exc)) from exc
    return CreateCommand(country, fingerprint_os, parse_account_ids(parts[3]))


def parse_import_command(text: str) -> ImportCommand:
    parts = text.strip().split()
    if len(parts) != 3 or _command_name(parts[0]) != "/import":
        raise CommandError("Use /import COUNTRY OS as the .txt caption")
    try:
        return ImportCommand(normalize_country(parts[1]), normalize_os(parts[2]))
    except ValueError as exc:
        raise CommandError(str(exc)) from exc


@dataclass(frozen=True)
class PendingAction:
    user_id: int
    action: str
    payload: dict[str, Any]
    expires_at: float


class PendingActions:
    def __init__(self, ttl_seconds: int = PENDING_TTL_SECONDS):
        self.ttl_seconds = ttl_seconds
        self._items: dict[str, PendingAction] = {}

    def add(self, user_id: int, action: str, payload: dict[str, Any], now: float | None = None) -> str:
        self.cleanup(now)
        token = secrets.token_urlsafe(12)
        current = time.monotonic() if now is None else now
        self._items[token] = PendingAction(user_id, action, payload, current + self.ttl_seconds)
        return token

    def pop(self, token: str, user_id: int, now: float | None = None) -> PendingAction | None:
        current = time.monotonic() if now is None else now
        item = self._items.get(token)
        if item is None or item.user_id != user_id or item.expires_at < current:
            if item is not None and item.expires_at < current:
                self._items.pop(token, None)
            return None
        return self._items.pop(token)

    def cancel(self, token: str, user_id: int, now: float | None = None) -> bool:
        return self.pop(token, user_id, now) is not None

    def cleanup(self, now: float | None = None) -> None:
        current = time.monotonic() if now is None else now
        expired = [token for token, item in self._items.items() if item.expires_at < current]
        for token in expired:
            self._items.pop(token, None)


@dataclass(frozen=True)
class BotConfig:
    telegram_token: str
    allowed_user_ids: set[int]
    admin_url: str
    admin_user: str
    admin_password: str

    @classmethod
    def from_env(cls) -> "BotConfig":
        token = os.environ.get("TELEGRAM_BOT_TOKEN", "").strip()
        if not token:
            raise ConfigError("TELEGRAM_BOT_TOKEN is required")
        allowed_raw = os.environ.get("TELEGRAM_ALLOWED_USER_IDS", "")
        admin_user = os.environ.get("ADMIN_USER", "")
        admin_password = os.environ.get("ADMIN_PASSWORD", "")
        if bool(admin_user) != bool(admin_password):
            raise ConfigError("ADMIN_USER and ADMIN_PASSWORD must both be set or both be empty")
        return cls(
            telegram_token=token,
            allowed_user_ids=parse_allowed_user_ids(allowed_raw),
            admin_url=os.environ.get("ADMIN_INTERNAL_URL", "http://web:8765").rstrip("/"),
            admin_user=admin_user,
            admin_password=admin_password,
        )


class JsonHttpClient:
    def __init__(self, timeout: int = 30):
        self.timeout = timeout

    def request(
        self,
        url: str,
        *,
        method: str = "GET",
        headers: dict[str, str] | None = None,
        body: bytes | None = None,
    ) -> tuple[int, bytes]:
        request = urllib.request.Request(url, data=body, method=method, headers=headers or {})
        with urllib.request.urlopen(request, timeout=self.timeout) as response:
            return response.status, response.read()


class BackendClient:
    def __init__(self, base_url: str, user: str = "", password: str = "", http: JsonHttpClient | None = None):
        self.base_url = base_url.rstrip("/")
        self.user = user
        self.password = password
        self.http = http or JsonHttpClient()

    def request(self, method: str, path: str, payload: dict[str, Any] | None = None) -> dict[str, Any]:
        headers = {"Accept": "application/json"}
        body = None
        if payload is not None:
            body = json.dumps(payload).encode("utf-8")
            headers["Content-Type"] = "application/json"
        if self.user or self.password:
            raw = f"{self.user}:{self.password}".encode("utf-8")
            headers["Authorization"] = "Basic " + base64.b64encode(raw).decode("ascii")
        url = self.base_url + path
        try:
            status, data = self.http.request(url, method=method, headers=headers, body=body)
        except urllib.error.HTTPError as exc:
            data = exc.read()
            status = exc.code
        except urllib.error.URLError as exc:
            raise BotError("Admin API is unavailable") from exc
        try:
            parsed = json.loads(data.decode("utf-8") or "{}")
        except (UnicodeDecodeError, json.JSONDecodeError):
            parsed = {}
        if status >= 400:
            message = parsed.get("error") if isinstance(parsed, dict) else None
            raise BotError(str(message or f"Admin API HTTP {status}"))
        if not isinstance(parsed, dict):
            raise BotError("Admin API returned invalid JSON")
        return parsed

    def accounts(self) -> list[dict[str, Any]]:
        data = self.request("GET", "/api/accounts")
        accounts = data.get("accounts", [])
        if not isinstance(accounts, list):
            raise BotError("Admin API returned invalid accounts")
        return accounts

    def job(self, job_id: int) -> dict[str, Any] | None:
        data = self.request("GET", f"/api/jobs/{job_id}")
        job = data.get("job")
        return job if isinstance(job, dict) else None

    def create_job(self, command: CreateCommand) -> int:
        data = self.request(
            "POST",
            "/api/jobs",
            {
                "account_ids": command.account_ids,
                "country": command.country,
                "fingerprint_os": command.fingerprint_os,
            },
        )
        return int(data["job_id"])

    def import_text(self, command: ImportCommand, text: str) -> dict[str, Any]:
        return self.request(
            "POST",
            "/api/import",
            {"text": text, "default_country": command.country, "default_os": command.fingerprint_os},
        )


class TelegramClient:
    def __init__(self, token: str, http: JsonHttpClient | None = None):
        self.token = token
        self.http = http or JsonHttpClient(timeout=65)
        self.api_base = f"https://api.telegram.org/bot{token}"
        self.file_base = f"https://api.telegram.org/file/bot{token}"

    def call(self, method: str, payload: dict[str, Any] | None = None) -> dict[str, Any]:
        body = json.dumps(payload or {}).encode("utf-8")
        headers = {"Content-Type": "application/json"}
        try:
            status, data = self.http.request(f"{self.api_base}/{method}", method="POST", headers=headers, body=body)
        except urllib.error.HTTPError as exc:
            status = exc.code
            data = exc.read()
        parsed = json.loads(data.decode("utf-8") or "{}")
        if status >= 400 or not parsed.get("ok"):
            description = parsed.get("description", "unknown error")
            raise BotError(f"Telegram API error in {method}: {status} {description}")
        result = parsed.get("result")
        return result if isinstance(result, dict) else {"value": result}

    def get_updates(self, offset: int | None) -> list[dict[str, Any]]:
        payload: dict[str, Any] = {"timeout": 50, "allowed_updates": ["message", "callback_query"]}
        if offset is not None:
            payload["offset"] = offset
        result = self.call("getUpdates", payload).get("value", [])
        return result if isinstance(result, list) else []

    def send_message(self, chat_id: int, text: str, reply_markup: dict[str, Any] | None = None) -> None:
        payload: dict[str, Any] = {"chat_id": chat_id, "text": text}
        if reply_markup:
            payload["reply_markup"] = reply_markup
        self.call("sendMessage", payload)

    def edit_message(self, chat_id: int, message_id: int, text: str) -> None:
        self.call("editMessageText", {"chat_id": chat_id, "message_id": message_id, "text": text})

    def answer_callback(self, callback_query_id: str, text: str = "") -> None:
        payload: dict[str, Any] = {"callback_query_id": callback_query_id}
        if text:
            payload["text"] = text
        self.call("answerCallbackQuery", payload)

    def get_file(self, file_id: str) -> dict[str, Any]:
        return self.call("getFile", {"file_id": file_id})

    def download_file(self, file_path: str, limit: int = MAX_DOWNLOAD_BYTES) -> bytes:
        url = f"{self.file_base}/{urllib.parse.quote(file_path, safe='/')}"
        request = urllib.request.Request(url, method="GET")
        chunks: list[bytes] = []
        total = 0
        with urllib.request.urlopen(request, timeout=30) as response:
            while True:
                chunk = response.read(65536)
                if not chunk:
                    break
                total += len(chunk)
                if total > limit:
                    raise BotError("File is too large")
                chunks.append(chunk)
        return b"".join(chunks)


class AdminTelegramBot:
    def __init__(self, telegram: TelegramClient, backend: BackendClient, allowed_user_ids: set[int]):
        self.telegram = telegram
        self.backend = backend
        self.allowed_user_ids = allowed_user_ids
        self.pending = PendingActions()

    def authorized(self, user_id: int | None) -> bool:
        return user_id in self.allowed_user_ids if user_id is not None else False

    def handle_update(self, update: dict[str, Any]) -> None:
        if "callback_query" in update:
            self.handle_callback(update["callback_query"])
            return
        message = update.get("message")
        if isinstance(message, dict):
            self.handle_message(message)

    def handle_message(self, message: dict[str, Any]) -> None:
        chat_id = int(message["chat"]["id"])
        user_id = int(message.get("from", {}).get("id", 0) or 0)
        if not self.authorized(user_id) or message.get("chat", {}).get("type") != "private":
            self.telegram.send_message(chat_id, "Unauthorized.")
            return
        text = str(message.get("text") or message.get("caption") or "").strip()
        command = _command_name(text.split(maxsplit=1)[0]) if text else ""
        try:
            if command == "/start":
                self.telegram.send_message(chat_id, help_text(), main_keyboard())
            elif command == "/status":
                self.telegram.send_message(chat_id, format_status(self.backend.accounts()), main_keyboard())
            elif command == "/accounts":
                self._send_accounts_page(chat_id, text)
            elif command == "/job":
                self.telegram.send_message(chat_id, self.job_message(text))
            elif command == "/create":
                self.prepare_create(chat_id, user_id, text)
            elif command == "/import":
                self.handle_import(chat_id, text, message)
            else:
                self.telegram.send_message(chat_id, "Unknown command. Use /start.")
        except CommandError as exc:
            self.telegram.send_message(chat_id, str(exc))
        except BotError as exc:
            self.telegram.send_message(chat_id, f"Error: {exc}")

    def _parse_page(self, text: str) -> int:
        parts = text.split()
        page = 1
        if len(parts) > 2:
            raise CommandError("Usage: /accounts [page]")
        if len(parts) == 2:
            try:
                page = int(parts[1])
            except ValueError as exc:
                raise CommandError("Page must be a number") from exc
        if page < 1:
            raise CommandError("Page must be positive")
        return page

    def _format_accounts_page(self, page: int) -> tuple[str, int]:
        accounts = self.backend.accounts()
        total_pages = max(1, (len(accounts) + ACCOUNTS_PAGE_SIZE - 1) // ACCOUNTS_PAGE_SIZE)
        start = (page - 1) * ACCOUNTS_PAGE_SIZE
        rows = accounts[start : start + ACCOUNTS_PAGE_SIZE]
        status_icons = {"created": "🟢", "pending_sync": "🟡", "not_created": "⚪", "ready": "⚪", "error": "🔴", "running": "🔵", "queued": "🔵"}
        lines = [f"📋 Аккаунты — страница {page}/{total_pages}\n"]
        for account in rows:
            icon = status_icons.get(account.get("status", ""), "⚫")
            lines.append(
                "{icon} #{id} {profile} · {country} · {status}".format(
                    icon=icon,
                    id=account.get("id", "?"),
                    profile=account.get("profile_name", ""),
                    country=str(account.get("country", "-") or "-").upper(),
                    status=account.get("status", "-") or "-",
                )
            )
        if not rows:
            lines.append("Нет аккаунтов на этой странице.")
        return "\n".join(lines), total_pages

    def _send_accounts_page(self, chat_id: int, text: str, message_id: int | None = None) -> None:
        page = self._parse_page(text)
        content, total_pages = self._format_accounts_page(page)
        markup = accounts_keyboard(page, total_pages)
        if message_id:
            self.telegram.edit_message(chat_id, message_id, content)
            self.telegram.call("editMessageReplyMarkup", {"chat_id": chat_id, "message_id": message_id, "reply_markup": markup})
        else:
            self.telegram.send_message(chat_id, content, markup)

    def job_message(self, text: str) -> str:
        parts = text.split()
        if len(parts) != 2 or not parts[1].isdigit():
            raise CommandError("Usage: /job ID")
        job = self.backend.job(int(parts[1]))
        if not job:
            return "Job not found."
        return (
            f"Job #{job.get('id')}: {job.get('status')}\n"
            f"Total: {job.get('total')} Completed: {job.get('completed')} Failed: {job.get('failed')}"
        )

    def prepare_create(self, chat_id: int, user_id: int, text: str) -> None:
        command = parse_create_command(text)
        token = self.pending.add(
            user_id,
            "create",
            {
                "country": command.country,
                "fingerprint_os": command.fingerprint_os,
                "account_ids": command.account_ids,
            },
        )
        markup = {
            "inline_keyboard": [
                [
                    {"text": "Confirm", "callback_data": f"confirm:{token}"},
                    {"text": "Cancel", "callback_data": f"cancel:{token}"},
                ]
            ]
        }
        self.telegram.send_message(
            chat_id,
            f"Create profiles for {len(command.account_ids)} accounts in {command.country}/{command.fingerprint_os}?",
            markup,
        )

    def handle_import(self, chat_id: int, text: str, message: dict[str, Any]) -> None:
        command = parse_import_command(text)
        document = message.get("document")
        if not isinstance(document, dict):
            raise CommandError("Attach a .txt document with caption /import COUNTRY OS")
        name = str(document.get("file_name", ""))
        if not name.casefold().endswith(".txt"):
            raise CommandError("Only .txt documents are supported")
        file_size = int(document.get("file_size") or 0)
        if file_size > MAX_DOWNLOAD_BYTES:
            raise CommandError("File is too large")
        file_id = str(document.get("file_id") or "")
        if not file_id:
            raise CommandError("Document file id is missing")
        file_info = self.telegram.get_file(file_id)
        file_path = str(file_info.get("file_path") or "")
        if not file_path:
            raise BotError("Telegram did not return a file path")
        try:
            content = self.telegram.download_file(file_path).decode("utf-8-sig")
        except UnicodeDecodeError as exc:
            raise CommandError("The .txt file must use UTF-8 encoding") from exc
        result = self.backend.import_text(command, content)
        self.telegram.send_message(
            chat_id,
            "Imported: added {added}, duplicates {duplicates}, invalid {invalid}".format(
                added=result.get("added", 0),
                duplicates=len(result.get("duplicates", [])),
                invalid=len(result.get("invalid", [])),
            ),
        )

    def handle_callback(self, callback: dict[str, Any]) -> None:
        query_id = str(callback.get("id", ""))
        user_id = int(callback.get("from", {}).get("id", 0) or 0)
        message = callback.get("message") if isinstance(callback.get("message"), dict) else {}
        chat_id = int(message.get("chat", {}).get("id", 0) or 0)
        message_id = int(message.get("message_id", 0) or 0)
        if not self.authorized(user_id) or message.get("chat", {}).get("type") != "private":
            self.telegram.answer_callback(query_id, "Unauthorized.")
            return
        data = str(callback.get("data") or "")

        # Menu buttons
        if data.startswith("menu:"):
            self._handle_menu_callback(query_id, chat_id, message_id, data)
            return

        action, separator, token = data.partition(":")
        if separator != ":" or action not in {"confirm", "cancel"}:
            self.telegram.answer_callback(query_id, "Expired.")
            return
        if action == "cancel":
            self.pending.cancel(token, user_id)
            self.telegram.answer_callback(query_id, "Cancelled.")
            if chat_id and message_id:
                self.telegram.edit_message(chat_id, message_id, "Cancelled.")
            return
        item = self.pending.pop(token, user_id)
        if item is None or item.action != "create":
            self.telegram.answer_callback(query_id, "Expired.")
            return
        command = CreateCommand(
            str(item.payload["country"]),
            str(item.payload["fingerprint_os"]),
            [int(value) for value in item.payload["account_ids"]],
        )
        try:
            job_id = self.backend.create_job(command)
            self.telegram.answer_callback(query_id, "Started.")
            if chat_id and message_id:
                self.telegram.edit_message(chat_id, message_id, f"Job #{job_id} started.")
        except BotError as exc:
            self.telegram.answer_callback(query_id, "Error.")
            if chat_id:
                self.telegram.send_message(chat_id, f"Error: {exc}")

    def _handle_menu_callback(self, query_id: str, chat_id: int, message_id: int, data: str) -> None:
        parts = data.split(":")
        menu_action = parts[1] if len(parts) > 1 else ""
        try:
            if menu_action == "home":
                self.telegram.answer_callback(query_id)
                if chat_id and message_id:
                    self.telegram.edit_message(chat_id, message_id, help_text())
                    self.telegram.call("editMessageReplyMarkup", {"chat_id": chat_id, "message_id": message_id, "reply_markup": main_keyboard()})
            elif menu_action == "status":
                self.telegram.answer_callback(query_id)
                content = format_status(self.backend.accounts())
                if chat_id and message_id:
                    self.telegram.edit_message(chat_id, message_id, content)
                    self.telegram.call("editMessageReplyMarkup", {"chat_id": chat_id, "message_id": message_id, "reply_markup": main_keyboard()})
            elif menu_action == "accounts":
                page = int(parts[2]) if len(parts) > 2 else 1
                self.telegram.answer_callback(query_id)
                self._send_accounts_page(chat_id, f"/accounts {page}", message_id)
            elif menu_action == "create_all":
                accounts = self.backend.accounts()
                not_created = [a for a in accounts if a.get("status") in ("not_created", "ready")]
                if not not_created:
                    self.telegram.answer_callback(query_id, "Нет аккаунтов для создания")
                    return
                # Group by country+os
                groups: dict[str, list[int]] = {}
                for a in not_created:
                    key = f"{a.get('country', 'mz')}_{a.get('fingerprint_os', 'win')}"
                    groups.setdefault(key, []).append(a["id"])
                lines = ["➕ Создать профили?\n"]
                for key, ids in groups.items():
                    country, os_type = key.split("_", 1)
                    lines.append(f"  {country.upper()}/{os_type}: {len(ids)} шт. (#{ids[0]}–#{ids[-1]})")
                lines.append(f"\nВсего: {len(not_created)}")
                confirm_markup = {
                    "inline_keyboard": [
                        [
                            {"text": "✅ Создать", "callback_data": "menu:confirm_create_all"},
                            {"text": "❌ Отмена", "callback_data": "menu:home"},
                        ]
                    ]
                }
                self.telegram.answer_callback(query_id)
                if chat_id and message_id:
                    self.telegram.edit_message(chat_id, message_id, "\n".join(lines))
                    self.telegram.call("editMessageReplyMarkup", {"chat_id": chat_id, "message_id": message_id, "reply_markup": confirm_markup})
            elif menu_action == "confirm_create_all":
                accounts = self.backend.accounts()
                not_created = [a for a in accounts if a.get("status") in ("not_created", "ready")]
                if not not_created:
                    self.telegram.answer_callback(query_id, "Нет аккаунтов для создания")
                    return
                groups: dict[str, list[int]] = {}
                for a in not_created:
                    key = f"{a.get('country', 'mz')}_{a.get('fingerprint_os', 'win')}"
                    groups.setdefault(key, []).append(a["id"])
                job_ids = []
                for key, ids in groups.items():
                    country, os_type = key.split("_", 1)
                    cmd = CreateCommand(country, os_type, ids)
                    job_id = self.backend.create_job(cmd)
                    job_ids.append(job_id)
                self.telegram.answer_callback(query_id, "Запущено ✓")
                if chat_id and message_id:
                    jobs_text = ", ".join(f"#{jid}" for jid in job_ids)
                    self.telegram.edit_message(chat_id, message_id, f"🚀 Запущено {len(not_created)} профилей\nЗадачи: {jobs_text}")
            elif menu_action == "refresh":
                self.telegram.answer_callback(query_id, "Обновлено ✓")
                content = format_status(self.backend.accounts())
                if chat_id and message_id:
                    self.telegram.edit_message(chat_id, message_id, content)
                    self.telegram.call("editMessageReplyMarkup", {"chat_id": chat_id, "message_id": message_id, "reply_markup": main_keyboard()})
            else:
                self.telegram.answer_callback(query_id, "Unknown action")
        except BotError as exc:
            self.telegram.answer_callback(query_id, f"Error: {exc}")


def format_status(accounts: list[dict[str, Any]]) -> str:
    counts = Counter(str(account.get("status") or "unknown") for account in accounts)
    if not counts:
        return "No accounts."
    parts = [f"{status}: {count}" for status, count in sorted(counts.items())]
    return "Account status\n" + "\n".join(parts)


def help_text() -> str:
    return (
        "📋 Profile Admin Bot\n\n"
        "Команды:\n"
        "/status — сводка по статусам\n"
        "/accounts [page] — список профилей\n"
        "/job ID — статус задачи\n"
        "/create COUNTRY OS IDS — создать профили\n"
        "/import COUNTRY OS — импорт из .txt файла"
    )


def main_keyboard() -> dict[str, Any]:
    return {
        "inline_keyboard": [
            [
                {"text": "📊 Статус", "callback_data": "menu:status"},
                {"text": "📋 Аккаунты", "callback_data": "menu:accounts:1"},
            ],
            [
                {"text": "➕ Создать все", "callback_data": "menu:create_all"},
                {"text": "🔄 Обновить", "callback_data": "menu:refresh"},
            ],
        ]
    }


def accounts_keyboard(page: int, total_pages: int) -> dict[str, Any]:
    buttons: list[list[dict[str, Any]]] = []
    nav: list[dict[str, Any]] = []
    if page > 1:
        nav.append({"text": "◀ Назад", "callback_data": f"menu:accounts:{page - 1}"})
    if page < total_pages:
        nav.append({"text": "Вперед ▶", "callback_data": f"menu:accounts:{page + 1}"})
    if nav:
        buttons.append(nav)
    buttons.append([{"text": "🏠 Меню", "callback_data": "menu:home"}])
    return {"inline_keyboard": buttons}


def main() -> None:
    config = BotConfig.from_env()
    telegram = TelegramClient(config.telegram_token)
    backend = BackendClient(config.admin_url, config.admin_user, config.admin_password)
    bot = AdminTelegramBot(telegram, backend, config.allowed_user_ids)
    offset: int | None = None
    print(f"Bot started, allowed users: {config.allowed_user_ids}", flush=True)
    while True:
        try:
            updates = telegram.get_updates(offset)
            if updates:
                print(f"Got {len(updates)} update(s)", flush=True)
            for update in updates:
                update_id = int(update.get("update_id", 0))
                offset = update_id + 1
                bot.handle_update(update)
        except KeyboardInterrupt:
            raise
        except Exception as exc:
            print(f"Bot polling error: {exc.__class__.__name__}: {exc}")
            if "409" in str(exc) or "Conflict" in str(exc):
                time.sleep(30)
            else:
                time.sleep(2)


if __name__ == "__main__":
    main()
