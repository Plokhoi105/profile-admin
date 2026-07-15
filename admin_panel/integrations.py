from __future__ import annotations

import json
import ipaddress
import os
import secrets
import socket
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path


DEFAULT_PORTS_PROTECTION = [3389, 5900, 5901, 5800, 7070, 6568, 5938, 1080, 8080, 3128, 3030]
IP_ECHO_HOST = "api.ipify.org"
FRAUD_SCORE_LIMIT = 25
MAX_PROXY_FRAUD_ATTEMPTS = 5
SOCKS5_STATUS_MESSAGES = {
    1: "general failure",
    2: "connection not allowed",
    3: "network unreachable",
    4: "host unreachable",
    5: "connection refused",
    6: "TTL expired",
    7: "command not supported",
    8: "address type not supported",
}


class VisionApiError(RuntimeError):
    def __init__(self, status: int, detail: str = ""):
        self.status = status
        self.detail = detail.strip()[:500]
        suffix = f": {self.detail}" if self.detail else ""
        super().__init__(f"Vision API request failed with HTTP {status}{suffix}")


class ProxySelectionError(RuntimeError):
    pass


def vision_error_detail(raw: bytes) -> str:
    text = raw.decode("utf-8", errors="replace").strip()
    if not text:
        return ""
    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        return text[:500]
    if isinstance(payload, dict):
        for key in ("message", "error", "detail", "errors"):
            value = payload.get(key)
            if isinstance(value, str):
                return value[:500]
            if isinstance(value, (dict, list)):
                return json.dumps(value, ensure_ascii=False)[:500]
    return ""

FALLBACK_COUNTRIES = [
    ("al", "Albania"), ("dz", "Algeria"), ("ar", "Argentina"), ("am", "Armenia"),
    ("au", "Australia"), ("at", "Austria"), ("az", "Azerbaijan"), ("bh", "Bahrain"),
    ("bd", "Bangladesh"), ("by", "Belarus"), ("be", "Belgium"), ("bo", "Bolivia"),
    ("ba", "Bosnia and Herzegovina"), ("br", "Brazil"), ("bg", "Bulgaria"),
    ("kh", "Cambodia"), ("ca", "Canada"), ("cl", "Chile"), ("cn", "China"),
    ("co", "Colombia"), ("cr", "Costa Rica"), ("hr", "Croatia"), ("cy", "Cyprus"),
    ("cz", "Czechia"), ("dk", "Denmark"), ("do", "Dominican Republic"),
    ("ec", "Ecuador"), ("eg", "Egypt"), ("ee", "Estonia"), ("fi", "Finland"),
    ("fr", "France"), ("ge", "Georgia"), ("de", "Germany"), ("gh", "Ghana"),
    ("gr", "Greece"), ("gt", "Guatemala"), ("hk", "Hong Kong"), ("hu", "Hungary"),
    ("is", "Iceland"), ("in", "India"), ("id", "Indonesia"), ("ie", "Ireland"),
    ("il", "Israel"), ("it", "Italy"), ("jp", "Japan"), ("jo", "Jordan"),
    ("kz", "Kazakhstan"), ("ke", "Kenya"), ("kr", "South Korea"), ("kw", "Kuwait"),
    ("lv", "Latvia"), ("lt", "Lithuania"), ("lu", "Luxembourg"), ("my", "Malaysia"),
    ("mt", "Malta"), ("mx", "Mexico"), ("md", "Moldova"), ("mn", "Mongolia"),
    ("me", "Montenegro"), ("ma", "Morocco"), ("mz", "Mozambique"),
    ("nl", "Netherlands"), ("nz", "New Zealand"), ("ng", "Nigeria"),
    ("mk", "North Macedonia"), ("no", "Norway"), ("om", "Oman"), ("pk", "Pakistan"),
    ("pa", "Panama"), ("py", "Paraguay"), ("pe", "Peru"), ("ph", "Philippines"),
    ("pl", "Poland"), ("pt", "Portugal"), ("qa", "Qatar"), ("ro", "Romania"),
    ("sa", "Saudi Arabia"), ("rs", "Serbia"), ("sg", "Singapore"), ("sk", "Slovakia"),
    ("si", "Slovenia"), ("za", "South Africa"), ("es", "Spain"), ("se", "Sweden"),
    ("ch", "Switzerland"), ("tw", "Taiwan"), ("th", "Thailand"), ("tn", "Tunisia"),
    ("tr", "Turkey"), ("ua", "Ukraine"), ("ae", "United Arab Emirates"),
    ("gb", "United Kingdom"), ("us", "United States"), ("uy", "Uruguay"),
    ("uz", "Uzbekistan"), ("ve", "Venezuela"), ("vn", "Vietnam"),
]


def load_env(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    if not path.exists():
        return values
    for raw_line in path.read_text(encoding="utf-8-sig").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key.strip()] = value.strip().strip('"').strip("'")
    return values


def request_json(method: str, url: str, token: str, payload: dict | None = None) -> dict:
    body = json.dumps(payload, ensure_ascii=False).encode("utf-8") if payload is not None else None
    request = urllib.request.Request(
        url,
        data=body,
        method=method,
        headers={"X-Token": token, "Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            raw = response.read().decode("utf-8")
            return json.loads(raw) if raw else {}
    except urllib.error.HTTPError as exc:
        raise VisionApiError(exc.code, vision_error_detail(exc.read())) from exc
    except urllib.error.URLError as exc:
        raise RuntimeError("Vision API is unavailable") from exc


def receive_exact(connection: socket.socket, length: int) -> bytes:
    chunks = []
    remaining = length
    while remaining:
        chunk = connection.recv(remaining)
        if not chunk:
            raise RuntimeError("SOCKS5 proxy closed the connection")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def socks5_connect(proxy: dict, target_host: str, target_port: int) -> socket.socket:
    connection = socket.create_connection((str(proxy["host"]), int(proxy["port"])), timeout=20)
    try:
        connection.settimeout(20)
        connection.sendall(b"\x05\x02\x00\x02")
        version, method = receive_exact(connection, 2)
        if version != 5 or method == 0xFF:
            raise RuntimeError("SOCKS5 proxy rejected authentication methods")
        if method == 2:
            username = str(proxy.get("login") or "").encode("utf-8")
            password = str(proxy.get("password") or "").encode("utf-8")
            if not username or len(username) > 255 or len(password) > 255:
                raise RuntimeError("Invalid SOCKS5 credentials")
            connection.sendall(b"\x01" + bytes((len(username),)) + username + bytes((len(password),)) + password)
            auth_version, auth_status = receive_exact(connection, 2)
            if auth_version != 1 or auth_status != 0:
                raise RuntimeError("SOCKS5 authentication failed")
        elif method != 0:
            raise RuntimeError("Unsupported SOCKS5 authentication method")

        host = target_host.encode("idna")
        if len(host) > 255:
            raise RuntimeError("SOCKS5 target hostname is too long")
        connection.sendall(b"\x05\x01\x00\x03" + bytes((len(host),)) + host + int(target_port).to_bytes(2, "big"))
        version, status, _, address_type = receive_exact(connection, 4)
        if version != 5 or status != 0:
            detail = SOCKS5_STATUS_MESSAGES.get(status, "unknown error")
            raise RuntimeError(f"SOCKS5 proxy error: {detail} (status {status})")
        address_length = {1: 4, 4: 16}.get(address_type)
        if address_type == 3:
            address_length = receive_exact(connection, 1)[0]
        if address_length is None:
            raise RuntimeError("SOCKS5 returned an unknown address type")
        receive_exact(connection, address_length + 2)
        return connection
    except Exception:
        connection.close()
        raise


def resolve_proxy_exit_ip(proxy: dict) -> str:
    connection = socks5_connect(proxy, IP_ECHO_HOST, 443)
    try:
        context = ssl.create_default_context()
        with context.wrap_socket(connection, server_hostname=IP_ECHO_HOST) as secure:
            secure.sendall(
                f"GET /?format=json HTTP/1.1\r\nHost: {IP_ECHO_HOST}\r\nConnection: close\r\nAccept: application/json\r\n\r\n".encode(
                    "ascii"
                )
            )
            response = bytearray()
            while len(response) <= 64_000:
                chunk = secure.recv(4096)
                if not chunk:
                    break
                response.extend(chunk)
        headers, separator, body = bytes(response).partition(b"\r\n\r\n")
        if not separator or not headers.startswith(b"HTTP/1.1 200"):
            raise RuntimeError("Could not determine the proxy exit IP")
        value = json.loads(body.decode("utf-8")).get("ip")
        return str(ipaddress.ip_address(str(value)))
    except (json.JSONDecodeError, UnicodeDecodeError, ValueError) as exc:
        raise RuntimeError("Proxy exit IP response was invalid") from exc
    finally:
        connection.close()


def parse_scamalytics_response(response: dict, expected_ip: str) -> dict:
    result = response.get("scamalytics") if isinstance(response, dict) else None
    if not isinstance(result, dict) or result.get("status") != "ok":
        raise RuntimeError("Scamalytics returned an unsuccessful response")
    try:
        score = int(result["scamalytics_score"])
    except (KeyError, TypeError, ValueError) as exc:
        raise RuntimeError("Scamalytics response did not include a fraud score") from exc
    if not 0 <= score <= 100:
        raise RuntimeError("Scamalytics fraud score is outside the expected range")
    response_ip = str(ipaddress.ip_address(str(result.get("ip") or expected_ip)))
    return {"ip": response_ip, "score": score, "risk": str(result.get("scamalytics_risk") or "")}


def scamalytics_lookup(user: str, api_key: str, ip: str) -> dict:
    query = urllib.parse.urlencode({"key": api_key, "ip": ip})
    url = f"https://api11.scamalytics.com/v3/{urllib.parse.quote(user, safe='')}?{query}"
    request = urllib.request.Request(url, headers={"Accept": "application/json"})
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            data = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        exc.read()
        raise RuntimeError(f"Scamalytics request failed with HTTP {exc.code}") from exc
    except (urllib.error.URLError, json.JSONDecodeError) as exc:
        raise RuntimeError("Scamalytics API is unavailable") from exc
    return parse_scamalytics_response(data, ip)


def iproyal_request_json(
    method: str,
    base_url: str,
    token: str,
    path: str,
    payload: dict | None = None,
) -> dict | list:
    body = json.dumps(payload).encode("utf-8") if payload is not None else None
    headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}
    if body is not None:
        headers["Content-Type"] = "application/json"
    request = urllib.request.Request(
        f"{base_url.rstrip('/')}/{path.lstrip('/')}", data=body, method=method, headers=headers
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            raw = response.read().decode("utf-8")
            return json.loads(raw) if raw else {}
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode("utf-8", errors="replace")
        try:
            data = json.loads(raw)
            message = data.get("message") or data.get("error") or data.get("detail")
        except (json.JSONDecodeError, AttributeError):
            message = None
        raise RuntimeError(f"IPRoyal HTTP {exc.code}: {str(message or 'request failed')[:200]}") from exc
    except urllib.error.URLError as exc:
        raise RuntimeError(f"IPRoyal network error: {exc.reason}") from exc


def first_data(response: dict) -> dict:
    data = response.get("data")
    if isinstance(data, list):
        return data[0] if data else {}
    return data if isinstance(data, dict) else {}


def fallback_country_catalog() -> list[dict[str, str]]:
    return [{"code": code, "name": name} for code, name in FALLBACK_COUNTRIES]


def country_display_name(code: str) -> str:
    names = dict(FALLBACK_COUNTRIES)
    return names.get(code.strip().lower(), code.strip().upper())


def normalize_country_catalog(response: dict) -> list[dict[str, str]]:
    countries = response.get("countries") if isinstance(response, dict) else None
    if not isinstance(countries, list):
        return []
    catalog: dict[str, str] = {}
    for item in countries:
        if not isinstance(item, dict):
            continue
        code = str(item.get("code") or "").strip().lower()
        if len(code) != 2 or not code.isalpha():
            continue
        name = str(item.get("name") or item.get("label") or item.get("country") or code.upper()).strip()
        catalog[code] = name or code.upper()
    return [{"code": code, "name": catalog[code]} for code in sorted(catalog, key=lambda key: catalog[key].casefold())]


class ProfileCreator:
    def __init__(self, root: Path):
        vision_env = load_env(root / ".env.local")
        scamalytics_env = load_env(root / ".new-api.env.local")
        iproyal_env = load_env(Path(os.getenv("IPROYAL_ENV", str(root / ".env"))))
        self.vision_token = os.getenv("VISION_TOKEN", vision_env.get("VISION_TOKEN", ""))
        self.vision_base = os.getenv(
            "VISION_API_BASE", vision_env.get("VISION_API_BASE", "https://api.browser.vision/api/v1")
        ).rstrip("/")
        self.folder_id = os.getenv(
            "VISION_FOLDER_ID",
            vision_env.get("VISION_FOLDER_ID", ""),
        )
        self.iproyal_token = os.getenv("IPROYAL_API_TOKEN", iproyal_env.get("IPROYAL_API_TOKEN", ""))
        self.iproyal_base = os.getenv("IPROYAL_API_BASE", "https://resi-api.iproyal.com/v1").rstrip("/")
        self.subuser = os.getenv("IPROYAL_SUBUSER", vision_env.get("IPROYAL_SUBUSER", ""))
        self.hostname = os.getenv("IPROYAL_HOSTNAME", "geo.iproyal.com")
        self.lifetime = os.getenv("IPROYAL_LIFETIME", "168h")
        self.scamalytics_user = os.getenv(
            "SCAMALYTICS_USER", scamalytics_env.get("SCAMALYTICS_USER", "")
        )
        self.scamalytics_key = os.getenv(
            "SCAMALYTICS_API_KEY",
            scamalytics_env.get("SCAMALYTICS_API_KEY", scamalytics_env.get("API_TOKEN", "")),
        )
        self._vision_proxy_cache: dict[str, dict] | None = None

    def validate_vision(self) -> None:
        if not self.vision_token:
            raise RuntimeError("VISION_TOKEN is missing")
        if not self.folder_id:
            raise RuntimeError("VISION_FOLDER_ID is missing")

    def validate(self) -> None:
        self.validate_vision()
        if not self.iproyal_token:
            raise RuntimeError("IPROYAL_API_TOKEN is missing")
        if not self.subuser:
            raise RuntimeError("IPROYAL_SUBUSER is missing")

    def list_available_countries(self) -> list[dict[str, str]]:
        if not self.iproyal_token:
            raise RuntimeError("IPROYAL_API_TOKEN is missing")
        response = iproyal_request_json(
            "GET", self.iproyal_base, self.iproyal_token, "/access/countries"
        )
        catalog = normalize_country_catalog(response if isinstance(response, dict) else {})
        if not catalog:
            raise RuntimeError("IPRoyal returned an empty country catalog")
        return catalog

    def generate_proxies(self, country: str, count: int) -> list[dict]:
        self.validate()
        response = iproyal_request_json(
            "GET", self.iproyal_base, self.iproyal_token, "/residential-subusers"
        )
        subusers = response.get("data", response) if isinstance(response, dict) else response
        if not isinstance(subusers, list):
            raise RuntimeError("IPRoyal returned an invalid subuser list")
        subuser_hash = ""
        for item in subusers:
            if not isinstance(item, dict):
                continue
            user_hash = str(item.get("hash") or item.get("user_hash") or item.get("subuser_hash") or "")
            username = str(item.get("username") or item.get("name") or user_hash)
            if self.subuser.casefold() in {username.casefold(), user_hash.casefold()}:
                subuser_hash = user_hash
                break
        if not subuser_hash:
            raise RuntimeError(f"IPRoyal subuser not found: {self.subuser}")
        payload = {
            "format": "{hostname}:{port}:{username}:{password}",
            "hostname": self.hostname,
            "port": "socks5",
            "rotation": "sticky",
            "proxy_count": count,
            "subuser_hash": subuser_hash,
            "location": f"_country-{country.lower()}",
            "lifetime": self.lifetime,
        }
        generated = iproyal_request_json(
            "POST", self.iproyal_base, self.iproyal_token, "/access/generate-proxy-list", payload
        )
        raw_value: object = generated
        if isinstance(generated, dict):
            raw_value = generated.get("proxy_list") or generated.get("proxies") or generated.get("data") or ""
        if isinstance(raw_value, list):
            raw_text = "\n".join(str(value) for value in raw_value)
        else:
            raw_text = str(raw_value)
        raw_lines = [line for line in raw_text.splitlines() if line.strip()]
        if len(raw_lines) < count:
            raise RuntimeError(f"IPRoyal returned {len(raw_lines)} proxies instead of {count}")
        proxies = []
        for line in raw_lines[:count]:
            host, port, login, password = line.split(":", 3)
            proxies.append({"host": host, "port": int(port), "login": login, "password": password})
        return proxies

    def create_vision_proxy(self, name: str, proxy: dict) -> str:
        payload = {
            "proxies": [
                {
                    "proxy_name": name,
                    "proxy_type": "SOCKS5",
                    "proxy_ip": proxy["host"],
                    "proxy_port": proxy["port"],
                    "proxy_username": proxy["login"],
                    "proxy_password": proxy["password"],
                    "update_url": None,
                }
            ]
        }
        response = request_json(
            "POST", f"{self.vision_base}/folders/{self.folder_id}/proxies", self.vision_token, payload
        )
        data = response.get("data") or []
        if not isinstance(data, list) or not data or not data[0].get("id"):
            raise RuntimeError("Vision API response did not include a proxy id")
        return str(data[0]["id"])

    def display_profile_name(self, account: dict) -> str:
        return f"{account['profile_name']} {country_display_name(account['country'])}".strip()

    @staticmethod
    def profile_notes(account: dict) -> str:
        return str(account["email"]) + (f":{account['code']}" if account.get("code") else "")

    def list_vision_profiles(self) -> list[dict]:
        """Fetch all profiles from the Vision folder."""
        response = request_json(
            "GET", f"{self.vision_base}/folders/{self.folder_id}/profiles", self.vision_token
        )
        data = response.get("data")
        if isinstance(data, list):
            return [p for p in data if isinstance(p, dict)]
        return []

    def get_vision_profile(self, profile_id: str) -> dict:
        response = request_json(
            "GET", f"{self.vision_base}/folders/{self.folder_id}/profiles/{profile_id}", self.vision_token
        )
        profile = first_data(response)
        if not profile.get("id"):
            raise RuntimeError("Vision API response did not include a profile")
        return profile

    def update_vision_profile(self, profile_id: str, payload: dict) -> dict:
        response = request_json(
            "PATCH",
            f"{self.vision_base}/folders/{self.folder_id}/profiles/{profile_id}",
            self.vision_token,
            payload,
        )
        return first_data(response)

    def delete_vision_profile(self, profile_id: str) -> None:
        request_json(
            "DELETE",
            f"{self.vision_base}/folders/{self.folder_id}/profiles/{profile_id}",
            self.vision_token,
        )

    def get_vision_proxy(self, proxy_id: str) -> dict | None:
        if self._vision_proxy_cache is None:
            response = request_json(
                "GET", f"{self.vision_base}/folders/{self.folder_id}/proxies", self.vision_token
            )
            items = response.get("data") if isinstance(response, dict) else None
            self._vision_proxy_cache = {
                str(item.get("id")): item
                for item in (items if isinstance(items, list) else [])
                if isinstance(item, dict) and item.get("id")
            }
        return self._vision_proxy_cache.get(proxy_id)

    @staticmethod
    def proxy_endpoint(proxy: dict | None) -> str:
        if not isinstance(proxy, dict):
            return ""
        proxy_type = str(proxy.get("proxy_type") or "SOCKS5").lower()
        host = str(proxy.get("proxy_ip") or proxy.get("host") or "")
        port = str(proxy.get("proxy_port") or proxy.get("port") or "")
        login = str(proxy.get("proxy_username") or proxy.get("login") or "")
        if not host or not port:
            return ""
        authority = f"{login}@" if login else ""
        return f"{proxy_type}://{authority}{host}:{port}"

    @staticmethod
    def full_proxy_endpoint(proxy: dict | None) -> str:
        if not isinstance(proxy, dict):
            return ""
        proxy_type = str(proxy.get("proxy_type") or "SOCKS5").lower()
        host = str(proxy.get("proxy_ip") or proxy.get("host") or "")
        port = str(proxy.get("proxy_port") or proxy.get("port") or "")
        login = str(proxy.get("proxy_username") or proxy.get("login") or "")
        password = str(proxy.get("proxy_password") or proxy.get("password") or "")
        if not host or not port:
            return ""
        authority = ""
        if login:
            encoded_login = urllib.parse.quote(login, safe="")
            encoded_password = urllib.parse.quote(password, safe="")
            authority = f"{encoded_login}:{encoded_password}@"
        return f"{proxy_type}://{authority}{host}:{port}"

    def account_proxy_endpoint(self, account: dict) -> str:
        proxy_id = str(account.get("vision_proxy_id") or "")
        if not proxy_id:
            raise ValueError("Profile does not have a proxy")
        proxy = self.get_vision_proxy(proxy_id)
        if not proxy:
            raise RuntimeError("Vision proxy was not found")
        endpoint = self.full_proxy_endpoint(proxy)
        if not endpoint:
            raise RuntimeError("Vision proxy credentials are incomplete")
        return endpoint

    def sync_account(self, account: dict, push_changes: bool = False) -> dict:
        profile_id = str(account.get("vision_profile_id") or "")
        if not profile_id:
            return {"exists": False}
        try:
            profile = self.get_vision_profile(profile_id)
        except VisionApiError as exc:
            if exc.status == 404:
                return {"exists": False}
            raise
        expected_name = self.display_profile_name(account)
        expected_notes = self.profile_notes(account)
        changes = {}
        if push_changes and profile.get("profile_name") != expected_name:
            changes["profile_name"] = expected_name
        if push_changes and profile.get("profile_notes") != expected_notes:
            changes["profile_notes"] = expected_notes
        if changes:
            updated = self.update_vision_profile(profile_id, changes)
            if updated:
                profile = {**profile, **updated}
        proxy = profile.get("proxy") if isinstance(profile.get("proxy"), dict) else None
        proxy_id = str(profile.get("proxy_id") or (proxy or {}).get("id") or "")
        if proxy is None and proxy_id:
            proxy = self.get_vision_proxy(proxy_id)
        return {
            "exists": True,
            "profile_id": str(profile.get("id") or profile_id),
            "proxy_id": proxy_id,
            "proxy_endpoint": self.proxy_endpoint(proxy),
            "pushed": bool(changes),
        }

    def rotate_proxy(self, account: dict) -> dict:
        profile_id = str(account.get("vision_profile_id") or "")
        if not profile_id:
            raise ValueError("Profile has not been created in Vision")
        self.get_vision_profile(profile_id)
        selected = self.select_low_fraud_proxy(str(account["country"]))
        proxy = selected["proxy"]
        proxy_id = self.create_vision_proxy(self.display_profile_name(account), proxy)
        self.update_vision_profile(
            profile_id,
            {
                "proxy_id": {"id": proxy_id},
                "profile_name": self.display_profile_name(account),
                "profile_notes": self.profile_notes(account),
            },
        )
        return {
            "proxy_id": proxy_id,
            "proxy_endpoint": self.proxy_endpoint(proxy),
            "fraud": selected["fraud"],
            "attempts": selected["attempts"],
        }

    @staticmethod
    def _normalize_raw_proxy(proxy: dict) -> dict:
        return {
            "host": proxy.get("proxy_ip") or proxy.get("host"),
            "port": proxy.get("proxy_port") or proxy.get("port"),
            "login": proxy.get("proxy_username") or proxy.get("login") or "",
            "password": proxy.get("proxy_password") or proxy.get("password") or "",
        }

    def check_candidate_proxy(self, proxy: dict) -> dict:
        if not self.scamalytics_user or not self.scamalytics_key:
            raise RuntimeError("Scamalytics credentials are missing")
        normalized = self._normalize_raw_proxy(proxy)
        exit_ip = resolve_proxy_exit_ip(normalized)
        return scamalytics_lookup(self.scamalytics_user, self.scamalytics_key, exit_ip)

    def confirm_candidate_proxy(self, proxy: dict, expected_ip: str) -> None:
        normalized = self._normalize_raw_proxy(proxy)
        last_error: Exception | None = None
        for check in range(2):
            try:
                actual_ip = resolve_proxy_exit_ip(normalized)
                if actual_ip != expected_ip:
                    raise RuntimeError(
                        f"Proxy exit IP changed during stability check: {expected_ip} -> {actual_ip}"
                    )
                return
            except (OSError, ssl.SSLError, TimeoutError, RuntimeError) as exc:
                last_error = exc
                if check == 0:
                    time.sleep(1)
        raise RuntimeError(f"Proxy stability check failed: {last_error}")

    def select_low_fraud_proxy(self, country: str) -> dict:
        if not self.scamalytics_user or not self.scamalytics_key:
            raise RuntimeError("Scamalytics credentials are missing")
        rejected_scores: list[int] = []
        connection_failures = 0
        for attempt in range(1, MAX_PROXY_FRAUD_ATTEMPTS + 1):
            proxy = self.generate_proxies(country, 1)[0]
            try:
                fraud = self.check_candidate_proxy(proxy)
            except (OSError, ssl.SSLError, TimeoutError) as exc:
                connection_failures += 1
                continue
            except RuntimeError as exc:
                detail = str(exc).casefold()
                if any(marker in detail for marker in ("socks5", "proxy closed", "proxy exit ip")):
                    connection_failures += 1
                    continue
                raise
            score = int(fraud["score"])
            if score < FRAUD_SCORE_LIMIT:
                try:
                    self.confirm_candidate_proxy(proxy, str(fraud["ip"]))
                except (OSError, ssl.SSLError, TimeoutError, RuntimeError):
                    connection_failures += 1
                    continue
                return {"proxy": proxy, "fraud": fraud, "attempts": attempt}
            rejected_scores.append(score)

        if len(rejected_scores) == MAX_PROXY_FRAUD_ATTEMPTS:
            scores = ", ".join(str(score) for score in rejected_scores)
            raise ProxySelectionError(
                f"\u041f\u0440\u0435\u0434\u0443\u043f\u0440\u0435\u0436\u0434\u0435\u043d\u0438\u0435: 5 \u043f\u0440\u043e\u043a\u0441\u0438 \u043f\u043e\u0434\u0440\u044f\u0434 \u043f\u043e\u043b\u0443\u0447\u0438\u043b\u0438 fraud score 25 \u0438\u043b\u0438 \u0432\u044b\u0448\u0435 ({scores}). \u041f\u0440\u043e\u0444\u0438\u043b\u044c \u043d\u0435 \u043e\u0442\u043f\u0440\u0430\u0432\u043b\u0435\u043d \u0432 Vision"
            )
        raise ProxySelectionError(
            f"\u041d\u0435 \u0443\u0434\u0430\u043b\u043e\u0441\u044c \u043f\u043e\u0434\u043e\u0431\u0440\u0430\u0442\u044c \u0440\u0430\u0431\u043e\u0447\u0438\u0439 \u043f\u0440\u043e\u043a\u0441\u0438 \u0441\u043e score \u043d\u0438\u0436\u0435 25 \u0437\u0430 5 \u043f\u043e\u043f\u044b\u0442\u043e\u043a: "
            f"\u0432\u044b\u0441\u043e\u043a\u0438\u0439 score \u2014 {len(rejected_scores)}, \u043d\u0435\u0434\u043e\u0441\u0442\u0443\u043f\u043d\u044b \u2014 {connection_failures}"
        )

    def check_proxy_fraud(self, account: dict) -> dict:
        if not self.scamalytics_user or not self.scamalytics_key:
            raise RuntimeError("Scamalytics credentials are missing")
        proxy_id = str(account.get("vision_proxy_id") or "")
        if not proxy_id:
            raise ValueError("Profile does not have a proxy")
        proxy = self.get_vision_proxy(proxy_id)
        if not proxy:
            raise RuntimeError("Vision proxy was not found")
        return self.check_candidate_proxy(proxy)

    def fingerprint(self, fingerprint_os: str) -> tuple[str, dict]:
        platform = "Windows" if fingerprint_os == "win" else "MacOS"
        slug = "windows" if fingerprint_os == "win" else "macos"
        response = request_json("GET", f"{self.vision_base}/fingerprints/{slug}/latest", self.vision_token)
        fingerprint = first_data(response).get("fingerprint")
        if not isinstance(fingerprint, dict):
            raise RuntimeError(f"Vision fingerprint missing for {slug}")
        fingerprint = dict(fingerprint)
        fingerprint.update(
            {
                "webrtc_pref": "auto",
                "canvas_pref": {"noise": 1.0},
                "webgl_pref": {"noise": 1.0},
                "audio_pref": 1,
                "media_devices": {
                    "audio_input": 1,
                    "audio_output": secrets.choice((1, 2)),
                    "video_input": secrets.choice((0, 1)),
                },
                "ports_protection": DEFAULT_PORTS_PROTECTION,
            }
        )
        navigator = dict(fingerprint.get("navigator") or {})
        navigator.update({"language": "auto", "languages": []})
        fingerprint["navigator"] = navigator
        return platform, fingerprint

    def create_vision_profile(self, account: dict, proxy_id: str) -> str:
        platform, fingerprint = self.fingerprint(account["fingerprint_os"])
        notes = self.profile_notes(account)
        payload = {
            "profile_name": self.display_profile_name(account),
            "profile_notes": notes,
            "profile_tags": [],
            "new_profile_tags": [],
            "proxy_id": proxy_id,
            "profile_status": None,
            "browser": "Chrome",
            "platform": platform,
            "fingerprint": fingerprint,
        }
        response = request_json(
            "POST", f"{self.vision_base}/folders/{self.folder_id}/profiles", self.vision_token, payload
        )
        profile_id = first_data(response).get("id")
        if not profile_id:
            raise RuntimeError("Vision API response did not include a profile id")
        return str(profile_id)
