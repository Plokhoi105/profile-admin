from __future__ import annotations

import argparse
import ipaddress
import json
import logging
import mimetypes
import os
import threading
import time
import webbrowser
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

from admin_panel.core import Database, normalize_country, parse_import
from admin_panel.integrations import ProfileCreator, ProxySelectionError, VisionApiError, fallback_country_catalog
from admin_panel.jobs import run_job
from admin_panel.security import basic_auth_matches


logger = logging.getLogger("admin_panel")

ROOT = Path(__file__).resolve().parents[1]
STATIC = Path(__file__).resolve().parent / "static"

DB: Database | None = None
ADMIN_USER = os.getenv("ADMIN_USER", "")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "")
REQUIRE_AUTH = os.getenv("ADMIN_REQUIRE_AUTH", "0").strip().casefold() in {"1", "true", "yes"}
if bool(ADMIN_USER) != bool(ADMIN_PASSWORD):
    raise RuntimeError("ADMIN_USER and ADMIN_PASSWORD must both be set or both be empty")
if REQUIRE_AUTH and not ADMIN_USER:
    raise RuntimeError("ADMIN_USER and ADMIN_PASSWORD are required for this deployment")
COUNTRY_CACHE: dict[str, object] = {"expires_at": 0.0, "countries": None, "source": "fallback"}
COUNTRY_CACHE_LOCK = threading.Lock()
INLINE_WORKER = os.getenv("ADMIN_INLINE_WORKER", "1").strip().casefold() not in {"0", "false", "no"}


def init_db() -> Database:
    global DB
    db_path = Path(os.getenv("ADMIN_DB_PATH", str(ROOT / "admin_panel" / "data" / "profiles.sqlite3")))
    DB = Database(db_path)
    bootstrap_notes = Path(os.getenv("ADMIN_BOOTSTRAP_NOTES", str(ROOT / "outputs" / "vision_notes.txt")))
    bootstrap_proxies = Path(os.getenv("ADMIN_BOOTSTRAP_PROXIES", str(ROOT / "outputs" / "proxies.example.csv")))
    DB.bootstrap(bootstrap_notes)
    DB.enrich_from_proxy_csv(bootstrap_proxies)
    return DB


def get_db() -> Database:
    if DB is None:
        raise RuntimeError("Database has not been initialized; call init_db() first")
    return DB


def is_loopback_host(host: str) -> bool:
    normalized = host.strip().casefold()
    if normalized == "localhost":
        return True
    try:
        return ipaddress.ip_address(normalized).is_loopback
    except ValueError:
        return False


def country_catalog() -> tuple[list[dict[str, str]], str]:
    now = time.monotonic()
    with COUNTRY_CACHE_LOCK:
        cached = COUNTRY_CACHE["countries"]
        if isinstance(cached, list) and now < float(COUNTRY_CACHE["expires_at"]):
            return cached, str(COUNTRY_CACHE["source"])
        try:
            countries = ProfileCreator(ROOT).list_available_countries()
            source = "iproyal"
            ttl = 6 * 60 * 60
        except Exception:
            countries = fallback_country_catalog()
            source = "fallback"
            ttl = 5 * 60
        COUNTRY_CACHE.update({"countries": countries, "source": source, "expires_at": now + ttl})
        return countries, source


class Handler(BaseHTTPRequestHandler):
    server_version = "ProfileAdmin/1.0"

    def log_message(self, format: str, *args) -> None:
        logger.info(format, *args)

    def authorize(self, path: str) -> bool:
        if path == "/healthz":
            return True
        if basic_auth_matches(self.headers.get("Authorization", ""), ADMIN_USER, ADMIN_PASSWORD):
            return True
        body = b"Authentication required"
        self.send_response(HTTPStatus.UNAUTHORIZED)
        self.send_header("WWW-Authenticate", 'Basic realm="Profile Admin", charset="UTF-8"')
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_security_headers()
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
        return False

    def send_security_headers(self) -> None:
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'; base-uri 'none'")

    def reject_cross_site(self) -> bool:
        if self.headers.get("Sec-Fetch-Site", "").casefold() != "cross-site":
            return False
        self.send_json({"error": "Cross-site requests are not allowed"}, HTTPStatus.FORBIDDEN)
        return True

    def send_json(self, payload: object, status: int = 200) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_security_headers()
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def read_json(self) -> dict:
        content_type = self.headers.get("Content-Type", "").split(";", 1)[0].strip().casefold()
        if content_type != "application/json":
            raise ValueError("Content-Type must be application/json")
        length = int(self.headers.get("Content-Length", "0"))
        if length > 2_000_000:
            raise ValueError("Request is too large")
        raw = self.rfile.read(length)
        data = json.loads(raw.decode("utf-8") or "{}")
        if not isinstance(data, dict):
            raise ValueError("JSON object required")
        return data

    def do_GET(self) -> None:
        path = urlparse(self.path).path
        if not self.authorize(path):
            return
        db = get_db()
        if path == "/healthz":
            self.send_json({"status": "ok"})
            return
        if path == "/api/accounts":
            self.send_json({"accounts": db.list_accounts()})
            return
        if path == "/api/authenticator/codes":
            self.send_json({"codes": db.authenticator_codes()})
            return
        if path == "/api/trash":
            self.send_json({"accounts": db.trashed_accounts()})
            return
        if path == "/api/countries":
            countries, source = country_catalog()
            self.send_json({"countries": countries, "source": source})
            return
        if path.startswith("/api/accounts/") and path.endswith("/ip-history"):
            try:
                account_id = int(path.split("/")[3])
            except (IndexError, ValueError):
                self.send_json({"error": "Invalid account id"}, 400)
                return
            self.send_json({"history": db.ip_history(account_id)})
            return
        if path.startswith("/api/jobs/"):
            try:
                job_id = int(path.rsplit("/", 1)[1])
            except ValueError:
                self.send_json({"error": "Invalid job id"}, 400)
                return
            job = db.job(job_id)
            self.send_json({"job": job}, 200 if job else 404)
            return
        self.serve_static(path)

    def do_POST(self) -> None:
        path = urlparse(self.path).path
        if not self.authorize(path):
            return
        if self.reject_cross_site():
            return
        try:
            data = self.read_json()
            if path == "/api/import":
                self._handle_import(data)
            elif path.startswith("/api/accounts/") and path.endswith("/authenticator"):
                self._handle_authenticator(path, data)
            elif path == "/api/sync":
                self._handle_sync(data)
            elif path.startswith("/api/trash/") and path.endswith("/restore"):
                self._handle_restore(path)
            elif path.startswith("/api/accounts/") and path.endswith("/delete-vision"):
                self._handle_delete_vision(path)
            elif path.startswith("/api/accounts/") and path.endswith("/fraud-check"):
                self._handle_fraud_check(path)
            elif path.startswith("/api/accounts/") and path.endswith("/proxy-credentials"):
                self._handle_proxy_credentials(path)
            elif path.startswith("/api/accounts/") and path.endswith("/rotate-proxy"):
                self._handle_rotate_proxy(path, data)
            elif path == "/api/jobs":
                self._handle_create_job(data)
            else:
                self.send_json({"error": "Not found"}, 404)
        except (ValueError, json.JSONDecodeError) as exc:
            self.send_json({"error": str(exc)}, 400)
        except RuntimeError as exc:
            logger.error("External service error: %s", exc)
            self.send_json({"error": "External service request failed"}, HTTPStatus.BAD_GATEWAY)
        except Exception as exc:
            logger.error("Internal request error: %s", exc)
            self.send_json({"error": "Internal server error"}, 500)

    def _handle_import(self, data: dict) -> None:
        db = get_db()
        accounts, errors = parse_import(
            str(data.get("text", "")),
            str(data.get("default_country", "")),
            str(data.get("default_os", "win")),
        )
        prefix = str(data.get("prefix", "")).strip()
        result = db.import_accounts(accounts, prefix=prefix)
        self.send_json({**result, "invalid": errors})

    def _handle_authenticator(self, path: str, data: dict) -> None:
        db = get_db()
        try:
            account_id = int(path.split("/")[3])
        except (IndexError, ValueError) as exc:
            raise ValueError("Invalid account id") from exc
        account = db.set_authenticator(account_id, str(data.get("secret", "")))
        self.send_json({"account": account}, 200 if account else 404)

    def _handle_sync(self, data: dict) -> None:
        db = get_db()
        creator = ProfileCreator(ROOT)
        creator.validate_vision()
        push_changes = data.get("push_changes", False)
        if not isinstance(push_changes, bool):
            raise ValueError("push_changes must be a boolean")
        requested_ids = data.get("account_ids")
        if requested_ids is not None and not isinstance(requested_ids, list):
            raise ValueError("account_ids must be a list")
        selected_ids = {int(value) for value in requested_ids} if requested_ids is not None else None
        if selected_ids is not None and (len(selected_ids) > 500 or any(value <= 0 for value in selected_ids)):
            raise ValueError("Select between 0 and 500 valid account ids")
        accounts = db.list_accounts()
        if selected_ids is not None:
            accounts = [account for account in accounts if account["id"] in selected_ids]
            if len(accounts) != len(selected_ids):
                raise ValueError("Some selected accounts no longer exist")
        synced = 0
        missing = 0
        failed = 0
        pushed = 0
        for account in accounts:
            if account["status"] in {"queued", "running", "rotating", "deleting"}:
                continue
            try:
                result = creator.sync_account(account, push_changes=push_changes)
                updated = db.mark_synced(
                    account["id"],
                    exists=bool(result.get("exists")),
                    profile_id=str(result.get("profile_id") or ""),
                    proxy_id=str(result.get("proxy_id") or ""),
                    proxy_endpoint=str(result.get("proxy_endpoint") or ""),
                    preserve_pending=not push_changes,
                )
                if not updated:
                    continue
                if result.get("exists"):
                    synced += 1
                    pushed += int(bool(result.get("pushed")))
                else:
                    missing += 1
            except Exception as exc:
                failed += 1
                logger.warning("Vision sync failed for account %d: %s", account["id"], exc)
        self.send_json({"synced": synced, "missing": missing, "failed": failed, "pushed": pushed})

    def _handle_restore(self, path: str) -> None:
        db = get_db()
        try:
            trash_id = int(path.split("/")[3])
        except (IndexError, ValueError) as exc:
            raise ValueError("Invalid trash id") from exc
        account = db.restore_account(trash_id)
        self.send_json({"account": account}, 200 if account else 404)

    def _handle_delete_vision(self, path: str) -> None:
        db = get_db()
        try:
            account_id = int(path.split("/")[3])
        except (IndexError, ValueError) as exc:
            raise ValueError("Invalid account id") from exc
        account = db.account(account_id)
        if not account:
            self.send_json({"error": "Account not found"}, 404)
            return
        if not account["vision_profile_id"]:
            self.send_json({"error": "Profile has not been created in Vision"}, HTTPStatus.CONFLICT)
            return
        previous_status = db.begin_account_delete(account_id)
        if previous_status is None:
            self.send_json({"error": "Account is busy"}, HTTPStatus.CONFLICT)
            return
        try:
            creator = ProfileCreator(ROOT)
            creator.validate_vision()
            try:
                creator.delete_vision_profile(account["vision_profile_id"])
            except VisionApiError as exc:
                if exc.status != 404:
                    raise
            if not db.mark_vision_deleted(account_id):
                raise RuntimeError("Could not update the local account after Vision deletion")
        except Exception:
            db.cancel_account_delete(account_id, previous_status)
            raise
        self.send_json({"deleted": True, "account": db.account(account_id)})

    def _handle_fraud_check(self, path: str) -> None:
        db = get_db()
        try:
            account_id = int(path.split("/")[3])
        except (IndexError, ValueError) as exc:
            raise ValueError("Invalid account id") from exc
        account = db.account(account_id)
        if not account:
            self.send_json({"error": "Account not found"}, 404)
            return
        if account["status"] in {"queued", "running", "rotating", "deleting"}:
            self.send_json({"error": "Account is busy"}, HTTPStatus.CONFLICT)
            return
        creator = ProfileCreator(ROOT)
        creator.validate_vision()
        try:
            result = creator.check_proxy_fraud(account)
        except RuntimeError as exc:
            detail = str(exc)
            if detail.startswith("SOCKS5 proxy error:"):
                detail = f"\u041f\u0440\u043e\u043a\u0441\u0438 \u043d\u0435\u0434\u043e\u0441\u0442\u0443\u043f\u0435\u043d: {detail.removeprefix('SOCKS5 proxy error:').strip()}"
            logger.warning("Fraud score check failed: %s", exc)
            self.send_json({"error": detail}, HTTPStatus.BAD_GATEWAY)
            return
        updated = db.mark_fraud_checked(
            account_id, result["score"], result["ip"], result["risk"]
        )
        self.send_json({"account": updated})

    def _handle_proxy_credentials(self, path: str) -> None:
        db = get_db()
        try:
            account_id = int(path.split("/")[3])
        except (IndexError, ValueError) as exc:
            raise ValueError("Invalid account id") from exc
        account = db.account(account_id)
        if not account:
            self.send_json({"error": "Account not found"}, 404)
            return
        creator = ProfileCreator(ROOT)
        creator.validate_vision()
        endpoint = creator.account_proxy_endpoint(account)
        self.send_json({"proxy": endpoint})

    def _handle_rotate_proxy(self, path: str, data: dict) -> None:
        db = get_db()
        try:
            account_id = int(path.split("/")[3])
        except (IndexError, ValueError) as exc:
            raise ValueError("Invalid account id") from exc
        account = db.account(account_id)
        if not account:
            self.send_json({"error": "Account not found"}, 404)
            return
        if not db.begin_proxy_rotation(account_id):
            self.send_json(
                {"error": "Profile is busy or has not been created"}, HTTPStatus.CONFLICT
            )
            return
        account = db.account(account_id) or account
        try:
            requested_country = str(data.get("country") or "").strip()
            target_country = normalize_country(requested_country) if requested_country else account["country"]
            target_account = {**account, "country": target_country}
            result = ProfileCreator(ROOT).rotate_proxy(target_account)
            db.mark_proxy_changed(
                account_id,
                result["proxy_id"],
                result["proxy_endpoint"],
                target_country if target_country != account["country"] else "",
            )
            fraud = result["fraud"]
            db.mark_fraud_checked(account_id, fraud["score"], fraud["ip"], fraud["risk"])
            self.send_json({"account": db.account(account_id)})
        except ProxySelectionError as exc:
            db.fail_proxy_rotation(account_id, str(exc))
            self.send_json({"error": str(exc), "warning": True}, HTTPStatus.UNPROCESSABLE_ENTITY)
        except Exception as exc:
            db.fail_proxy_rotation(account_id, "Proxy change failed")
            raise

    def _handle_create_job(self, data: dict) -> None:
        db = get_db()
        account_ids = data.get("account_ids")
        if not isinstance(account_ids, list):
            raise ValueError("account_ids must be a list")
        job_id = db.create_job(
            account_ids,
            str(data.get("country", "")),
            str(data.get("fingerprint_os", "")),
        )
        if INLINE_WORKER:
            threading.Thread(target=run_job, args=(db, ROOT, job_id), daemon=True).start()
        self.send_json({"job_id": job_id}, HTTPStatus.ACCEPTED)

    def do_DELETE(self) -> None:
        path = urlparse(self.path).path
        if not self.authorize(path):
            return
        if self.reject_cross_site():
            return
        db = get_db()
        try:
            data = self.read_json()
            if path.startswith("/api/accounts/") and path.endswith("/permanent"):
                try:
                    account_id = int(path.split("/")[3])
                except (IndexError, ValueError) as exc:
                    raise ValueError("Invalid account id") from exc
                if data.get("confirmed") is not True:
                    raise ValueError("Permanent deletion must be confirmed")
                deleted = db.permanently_delete_uncreated_account(account_id)
                self.send_json({"deleted": True}, 200 if deleted else 404)
                return
            if not path.startswith("/api/accounts/"):
                self.send_json({"error": "Not found"}, 404)
                return
            account_id = int(path.rsplit("/", 1)[1])
            account = db.account(account_id)
            if not account:
                self.send_json({"error": "Account not found"}, 404)
                return
            delete_vision = data.get("delete_vision", False)
            if not isinstance(delete_vision, bool):
                raise ValueError("delete_vision must be a boolean")
            previous_status = db.begin_account_delete(account_id)
            if previous_status is None:
                self.send_json({"error": "Account is busy"}, HTTPStatus.CONFLICT)
                return
            try:
                if delete_vision and account["vision_profile_id"]:
                    creator = ProfileCreator(ROOT)
                    creator.validate_vision()
                    try:
                        creator.delete_vision_profile(account["vision_profile_id"])
                    except VisionApiError as exc:
                        if exc.status != 404:
                            raise
                db.delete_account(account_id, previous_status, clear_vision=delete_vision)
            except Exception:
                db.cancel_account_delete(account_id, previous_status)
                raise
            self.send_json({"deleted": True})
        except (ValueError, json.JSONDecodeError) as exc:
            self.send_json({"error": str(exc)}, 400)
        except RuntimeError as exc:
            logger.error("External service error: %s", exc)
            self.send_json({"error": "External service request failed"}, HTTPStatus.BAD_GATEWAY)
        except Exception as exc:
            logger.error("Internal delete error: %s", exc)
            self.send_json({"error": "Internal server error"}, 500)

    def do_PATCH(self) -> None:
        path = urlparse(self.path).path
        if not self.authorize(path):
            return
        if self.reject_cross_site():
            return
        if not path.startswith("/api/accounts/"):
            self.send_json({"error": "Not found"}, 404)
            return
        db = get_db()
        try:
            account_id = int(path.rsplit("/", 1)[1])
            account = db.update_account(account_id, self.read_json())
            self.send_json({"account": account}, 200 if account else 404)
        except (ValueError, json.JSONDecodeError) as exc:
            self.send_json({"error": str(exc)}, 400)

    def serve_static(self, path: str) -> None:
        relative = "index.html" if path in {"", "/"} else path.lstrip("/")
        candidate = (STATIC / relative).resolve()
        if STATIC.resolve() not in candidate.parents and candidate != STATIC.resolve():
            self.send_error(404)
            return
        if not candidate.is_file():
            self.send_error(404)
            return
        body = candidate.read_bytes()
        content_type = mimetypes.guess_type(candidate.name)[0] or "application/octet-stream"
        self.send_response(200)
        self.send_header("Content-Type", f"{content_type}; charset=utf-8")
        self.send_security_headers()
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s")
    parser = argparse.ArgumentParser(description="Local account and Vision profile administration panel")
    parser.add_argument("--host", default=os.getenv("ADMIN_HOST", "127.0.0.1"))
    parser.add_argument("--port", type=int, default=int(os.getenv("ADMIN_PORT", "8765")))
    parser.add_argument("--no-browser", action="store_true")
    args = parser.parse_args()
    init_db()
    if not is_loopback_host(args.host) and not ADMIN_USER:
        raise RuntimeError(
            "ADMIN_USER and ADMIN_PASSWORD are required when binding to a non-loopback host"
        )
    server = ThreadingHTTPServer((args.host, args.port), Handler)
    url = f"http://{args.host}:{args.port}"
    logger.info("Profile admin: %s", url)
    if not args.no_browser:
        threading.Timer(0.5, lambda: webbrowser.open(url)).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
