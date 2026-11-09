"""Signed, stateless tokens for links in mail. Nothing is stored: the token is
base64url(email|expiry) "." base64url(HMAC-SHA256(secret, kind|email|expiry|extra)). The kind is
signed but not carried, so a token of one kind never passes as another; extra lets the reset
token bind to the current password hash, so it stops working once the password changes."""
import base64
import binascii
import hashlib
import hmac
import time

MAX_TOKEN_LENGTH = 1024


def _b64encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64decode(text: str) -> bytes:
    return base64.b64decode(text + "=" * (-len(text) % 4), altchars=b"-_", validate=True)


def _mac(secret: bytes, kind: str, email: str, expiry: int, extra: bytes) -> bytes:
    message = b"|".join([kind.encode("utf-8"), email.encode("utf-8"), str(expiry).encode("ascii"),
                         extra])
    return hmac.new(secret, message, hashlib.sha256).digest()


def make(kind: str, email: str, ttl_seconds: int, secret: bytes, extra: bytes = b"",
         now: float | None = None) -> str:
    expiry = int((time.time() if now is None else now) + ttl_seconds)
    payload = _b64encode(f"{email}|{expiry}".encode("utf-8"))
    return f"{payload}.{_b64encode(_mac(secret, kind, email, expiry, extra))}"


def _parse(token: str) -> tuple[str, int, bytes] | None:
    if not isinstance(token, str) or not token.isascii() or len(token) > MAX_TOKEN_LENGTH:
        return None
    try:
        payload, sig = token.split(".")
        email, expiry = _b64decode(payload).decode("utf-8").rsplit("|", 1)
        given = _b64decode(sig)
    except (ValueError, UnicodeDecodeError, binascii.Error):
        return None
    if not expiry.isascii() or not expiry.isdigit() or not email or not email.isprintable():
        return None
    return email, int(expiry), given


def unverified_email(token: str) -> str | None:
    """The address a token names, before its signature is checked. Use only to look up the row
    whose current state check() needs as extra."""
    parsed = _parse(token)
    return parsed[0] if parsed else None


def check(token: str, kind: str, secret: bytes, extra: bytes = b"",
          now: float | None = None) -> str | None:
    """The email address when the token is genuine, of this kind and not expired; else None."""
    parsed = _parse(token)
    if parsed is None:
        return None
    email, expiry, given = parsed
    if not hmac.compare_digest(given, _mac(secret, kind, email, expiry, extra)):
        return None
    if expiry <= (time.time() if now is None else now):
        return None
    return email
