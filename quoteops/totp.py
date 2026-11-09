"""The administrator's second factor: time-based one-time codes (RFC 6238) on HOTP (RFC 4226)
with HMAC-SHA1, as authenticator apps compute them. Standard library only.

Product parameters: 6 digits, a 30-second step, and one step either side of the current one, so
a code typed just before or after a step changes is still accepted. The caller records the
matched step (qo_admin_totp_use) so a code is never accepted twice."""
import base64
import hashlib
import hmac
import secrets
import struct
from urllib.parse import quote

DIGITS, STEP, WINDOW, SECRET_BYTES = 6, 30, 1, 20
ISSUER = "QuoteOps"
_ASCII_DIGITS = frozenset("0123456789")


def new_secret() -> bytes:
    return secrets.token_bytes(SECRET_BYTES)


def hotp(secret: bytes, counter: int, digits: int = DIGITS) -> str:
    """RFC 4226 section 5.3: HMAC-SHA1 over the 8-byte counter, dynamic truncation."""
    mac = hmac.new(secret, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = mac[-1] & 0x0F
    value = struct.unpack(">I", mac[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(value % 10 ** digits).zfill(digits)


def counter_at(at: float, step: int = STEP) -> int:
    return int(at // step)


def totp(secret: bytes, at: float, digits: int = DIGITS, step: int = STEP) -> str:
    return hotp(secret, counter_at(at, step), digits)


def well_formed(code, digits: int = DIGITS) -> bool:
    """Exactly `digits` ASCII digits: no space, no sign, no newline, no other script's digits
    (which str.isdigit and int() would accept)."""
    return isinstance(code, str) and len(code) == digits and all(c in _ASCII_DIGITS for c in code)


def match(secret: bytes, code, at: float, digits: int = DIGITS, step: int = STEP,
          window: int = WINDOW) -> int | None:
    """The time step whose code equals `code`, within `window` steps of `at`, else None.
    The same work on every input: every step of the window is computed and compared with
    hmac.compare_digest, even after a match and even for a malformed code."""
    ok = well_formed(code, digits)
    given = (code if ok else "x" * digits).encode("ascii")
    now = counter_at(at, step)
    found = None
    for counter in range(now - window, now + window + 1):
        expected = hotp(secret, max(counter, 0), digits).encode("ascii")
        if hmac.compare_digest(expected, given) and counter >= 0:
            found = counter
    return found if ok else None


def encode_secret(secret: bytes) -> str:
    """Base32 without padding, as authenticator apps expect it."""
    return base64.b32encode(secret).decode("ascii").rstrip("=")


def otpauth_uri(secret: bytes, email: str) -> str:
    """The key URI an authenticator app reads (as text or from a QR code)."""
    return (f"otpauth://totp/{quote(ISSUER, safe='')}:{quote(email, safe='')}"
            f"?secret={encode_secret(secret)}&issuer={quote(ISSUER, safe='')}"
            f"&algorithm=SHA1&digits={DIGITS}&period={STEP}")
