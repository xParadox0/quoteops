"""Password policy and scrypt hashing (PRD section 6). Standard library only."""
import hashlib
import hmac
import secrets
import threading
import unicodedata
from contextlib import contextmanager

from quoteops.config import scrypt_limits

SCRYPT_N, SCRYPT_R, SCRYPT_P, SCRYPT_DKLEN = 2 ** 15, 8, 1, 32
SCRYPT_MAXMEM = 64 * 1024 * 1024  # the work needs 128 * r * n = 32 MiB; the default cap is 32 MiB
SALT_BYTES = 16
MIN_LENGTH, MAX_LENGTH = 10, 128
# NFKC makes a string at most 4 times shorter: one character of its result composes from at most
# four (U+1F82 from alpha and three marks; tests/test_stage2b2_fix1.py scans every code point).
# So a password of more than 4 * MAX_LENGTH characters is too long after normalising as well,
# and one of more than MAX_RAW (twice that, as margin) is refused as too long without being
# normalised: the work an attacker-sized password costs stays bounded.
MAX_RAW = 1024
TOO_LONG = f"Use at most {MAX_LENGTH} characters."

# Compared after NFKC normalisation and case folding. Short entries stay in the list because the
# length rule may change; most of the useful ones are 10 characters or more.
COMMON_PASSWORDS = frozenset("""
password password1 password12 password123 password1234 passw0rd p@ssw0rd p@ssword1 passwordpassword
password! password1! mypassword mypassword1 mypassword123 secretpassword
123456 1234567 12345678 123456789 1234567890 12345678910 0123456789 9876543210 0987654321
1111111111 0000000000 1234512345 1122334455 123123123 123123123123 147258369 741852963 789456123
7777777777 9999999999 5555555555 11111111 22222222 88888888 87654321 159753 159753456
qwerty qwerty123 qwerty1234 qwertyuiop qwertyuiop1 qwerty!@# 1234qwer asdfghjkl asdfghjkl1
zxcvbnm123 zxcvbnmasdf 1q2w3e4r5t 1q2w3e4r5t6y q1w2e3r4t5 q1w2e3r4 1qaz2wsx3edc qazwsxedc
qazwsxedc123 zaq12wsx zaq1zaq1 abc123 abcd1234 abcdefghij abcdefg123 abc1234567 a1b2c3d4e5
aaaaaaaaaa !@#$%^&*() 1234567890!
iloveyou iloveyou1 iloveyou12 iloveyou123 loveyou123 letmein letmein123 letmeinplease
welcome welcome1 welcome123 welcome1234 admin admin123 admin12345 administrator adminadmin
rootroot changeme changeme12 changeme123 trustno1 trustno123 secret secret1234
monkey monkey1234 dragon dragon1234 football football1 baseball basketball superman superman123
batman1234 starwars starwars123 princess princess123 sunshine sunshine123 shadow1234 master
master1234 michael123 jennifer jessica123 charlie123 freedom123 whatever whatever123 computer
computer123 internet internet123 test123456 testtest testing123 guest12345 login12345 hello12345
helloworld helloworld1
indonesia indonesia1 indonesia123 jakarta123 bismillah bismillah1 bismillah123 sayang123 sayangku
rahasia rahasia123 quoteops quoteops123 chronyx chronyxlabs
""".split())

# A salt and a hash that no password produces in practice. Sign-in for an unknown email runs one
# scrypt against them so that it costs the same as checking a real account.
_DUMMY_SALT = bytes.fromhex("6a1f0c9e57d24b3880e1f2a4c5b6d7e8")
_DUMMY_HASH = bytes.fromhex("3c9d1e7a5b2f40c8a6e9d1b3f5a7c9e0b2d4f6a8c0e2f4a6b8d0f2a4c6e8a0b2")


class Busy(Exception):
    """No scrypt slot came free within QO_SCRYPT_WAIT_SECONDS: the caller answers 503."""


# One limit for the whole process around every scrypt: each needs 32 MiB, and without a bound
# anonymous requests could start enough at once to exceed the container's memory. The settings
# are read at the first use.
_limit: tuple[threading.BoundedSemaphore, float] | None = None
_limit_lock = threading.Lock()
_held = threading.local()  # depth of scrypt_slot in this thread: only the outermost acquires


def _limiter() -> tuple[threading.BoundedSemaphore, float]:
    global _limit
    with _limit_lock:
        if _limit is None:
            concurrency, wait = scrypt_limits()
            _limit = threading.BoundedSemaphore(concurrency), wait
        return _limit


@contextmanager
def scrypt_slot():
    """Hold one scrypt slot. A route that hashes takes it first, before any throttle hit or
    database connection, so a Busy answer has changed nothing. Reentrant in one thread: the
    hash and verify functions below reuse a slot their caller holds, and take one on their own
    otherwise, so with QO_SCRYPT_CONCURRENCY=1 nothing waits for itself. Raises Busy."""
    depth = getattr(_held, "depth", 0)
    if depth == 0:
        semaphore, wait = _limiter()
        if not semaphore.acquire(timeout=wait):
            raise Busy()
    _held.depth = depth + 1
    try:
        yield
    finally:
        _held.depth = depth
        if depth == 0:
            semaphore.release()


def normalise(password: str) -> str:
    return unicodedata.normalize("NFKC", password)


def policy_error(password: str, email: str) -> str | None:
    """The reason a new password is refused, or None when it is acceptable. Every caller passes
    an address already checked to be at most 254 characters (or read from the database)."""
    if len(password) > MAX_RAW:  # too long after NFKC as well; not normalised
        return TOO_LONG
    pw = normalise(password)
    # NUL, tab, newline, escape, DEL and the rest of category Cc: a password field cannot type
    # them, so only a crafted request carries one, and they are refused rather than stored.
    if any(unicodedata.category(c) == "Cc" for c in pw):
        return "Do not use control characters."
    if len(pw) < MIN_LENGTH:
        return f"Use at least {MIN_LENGTH} characters."
    if len(pw) > MAX_LENGTH:
        return TOO_LONG
    folded, address = pw.casefold(), normalise(email).strip().casefold()
    if folded == address or folded == address.split("@", 1)[0]:
        return "Do not use your email address as the password."
    if folded in COMMON_PASSWORDS:
        return "This password is too common. Choose another."
    return None


def _scrypt(password: str, salt: bytes) -> bytes:
    return hashlib.scrypt(normalise(password).encode("utf-8"), salt=salt, n=SCRYPT_N, r=SCRYPT_R,
                          p=SCRYPT_P, dklen=SCRYPT_DKLEN, maxmem=SCRYPT_MAXMEM)


def _matches(password: str, pw_hash: bytes, pw_salt: bytes) -> bool:
    """One scrypt computation whatever the input, so the time does not depend on the password.
    The caller holds a slot."""
    # Cannot be right; still pay for one hash. Over MAX_RAW it is not even normalised.
    too_long = len(password) > MAX_RAW or len(normalise(password)) > MAX_LENGTH
    same = hmac.compare_digest(_scrypt("" if too_long else password, bytes(pw_salt)), bytes(pw_hash))
    return same and not too_long


def hash_password(password: str) -> tuple[bytes, bytes]:
    """Returns (hash, salt) for app_user.pw_hash and pw_salt. Raises Busy. Every caller checks
    policy_error first; a password over MAX_RAW is refused here too (ValueError) unnormalised."""
    if len(password) > MAX_RAW:
        raise ValueError(TOO_LONG)
    salt = secrets.token_bytes(SALT_BYTES)
    with scrypt_slot():
        return _scrypt(password, salt), salt


def verify_password(password: str, pw_hash: bytes, pw_salt: bytes) -> bool:
    """Raises Busy."""
    with scrypt_slot():
        return _matches(password, pw_hash, pw_salt)


def verify_dummy(password: str) -> bool:
    """The unknown-email path: one scrypt against a fixed hash, always False. It takes a slot like
    a real check, so a busy answer does not tell whether the account exists. Raises Busy."""
    with scrypt_slot():
        _matches(password, _DUMMY_HASH, _DUMMY_SALT)
    return False
