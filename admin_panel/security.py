from __future__ import annotations

import base64
import binascii
import secrets


def basic_auth_matches(header: str, username: str, password: str) -> bool:
    if not username and not password:
        return True
    if not username or not password or not header.startswith("Basic "):
        return False
    try:
        decoded = base64.b64decode(header[6:], validate=True).decode("utf-8")
    except (binascii.Error, UnicodeDecodeError):
        return False
    supplied_user, separator, supplied_password = decoded.partition(":")
    if not separator:
        return False
    return secrets.compare_digest(supplied_user, username) and secrets.compare_digest(
        supplied_password, password
    )

