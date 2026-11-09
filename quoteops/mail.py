"""Outgoing mail behind one interface, mailer(settings).send(to, subject, text). Two backends:
FileMailer (a directory with one private file per mail, for development and tests; the default)
and GraphMailer (Microsoft Graph, stage 2b part 3, PRD Q1)."""
import hashlib
import http.client
import json
import math
import os
import secrets
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

from quoteops.config import Settings
from quoteops.guard import valid_email

# The only places a token or a mail is ever sent. They are constants, not settings: no
# environment variable can point them elsewhere. A test replaces them (monkeypatch) or passes
# other values to the GraphMailer constructor.
LOGIN_BASE = "https://login.microsoftonline.com"
GRAPH_BASE = "https://graph.microsoft.com/v1.0"
SCOPE = "https://graph.microsoft.com/.default"
TIMEOUT_SECONDS = 10
REFRESH_MARGIN_SECONDS = 300  # a token is renewed this long before it expires
MAX_TOKEN_REPLY_BYTES = 65536
MAX_TOKEN_LIFETIME_SECONDS = 86400  # Entra tokens live about an hour; a day is already generous


class MailError(Exception):
    """A mail could not be sent. The message is a fixed phrase and an HTTP status number, never
    the reply body, a secret, a token, an address or a subject."""


class FileMailer:
    def __init__(self, directory: str):
        self.directory = directory

    def send(self, to: str, subject: str, text: str) -> None:
        if any(c in to + subject for c in "\r\n"):
            raise ValueError("header values must be one line")
        os.makedirs(self.directory, mode=0o700, exist_ok=True)
        path = os.path.join(self.directory, secrets.token_hex(16) + ".txt")
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            os.fchmod(f.fileno(), 0o600)
            f.write(f"To: {to}\nSubject: {subject}\n\n{text}")


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None  # a 3xx stays an HTTPError: it is a failure, never followed


class GraphMailer:
    """Sends through Graph with an app-only token (client-credentials grant) for the shared
    mailbox `sender`. One instance per process, so the token cache serves every request."""

    def __init__(self, tenant: str, client_id: str, client_secret: str, sender: str, *,
                 login_base: str | None = None, graph_base: str | None = None,
                 timeout: float = TIMEOUT_SECONDS, clock=time.monotonic):
        self.tenant, self.client_id, self.sender = tenant, client_id, sender
        self._client_secret = client_secret
        self.login_base = (LOGIN_BASE if login_base is None else login_base).rstrip("/")
        self.graph_base = (GRAPH_BASE if graph_base is None else graph_base).rstrip("/")
        self.timeout = timeout
        self._clock = clock
        # No proxy from the environment, no redirect: the token goes only where it was aimed.
        self._opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect())
        self._lock = threading.Lock()
        self._token: str | None = None
        self._token_until = 0.0

    def __repr__(self) -> str:
        return f"GraphMailer(sender={self.sender!r})"

    def _post(self, url: str, data: bytes, headers: dict, what: str) -> tuple[int, bytes]:
        """(status, body) of one POST; any status, including 3xx, 4xx and 5xx, is returned. Only
        a failure to get an answer at all raises."""
        req = urllib.request.Request(url, data=data, method="POST",
                                     headers={"User-Agent": "QuoteOps", **headers})
        try:
            with self._opener.open(req, timeout=self.timeout) as resp:
                return resp.status, resp.read(MAX_TOKEN_REPLY_BYTES)
        except urllib.error.HTTPError as exc:
            status = exc.code
            exc.close()
            return status, b""
        except (OSError, ValueError, urllib.error.URLError, http.client.HTTPException):
            raise MailError(f"{what} failed: no answer") from None

    def _fetch_token(self) -> tuple[str, float]:
        form = urllib.parse.urlencode([
            ("client_id", self.client_id), ("client_secret", self._client_secret),
            ("scope", SCOPE), ("grant_type", "client_credentials")])
        status, body = self._post(
            f"{self.login_base}/{self.tenant}/oauth2/v2.0/token", form.encode("ascii"),
            {"Content-Type": "application/x-www-form-urlencoded"}, "token request")
        if status != 200:
            raise MailError(f"token request failed with status {status}")
        try:
            reply = json.loads(body)
            token, lifetime = reply["access_token"], reply["expires_in"]
            usable = (isinstance(token, str) and bool(token) and token.isprintable() and token.isascii()
                      and not any(c.isspace() for c in token)
                      and isinstance(lifetime, (int, float)) and not isinstance(lifetime, bool)
                      and math.isfinite(lifetime) and lifetime <= MAX_TOKEN_LIFETIME_SECONDS)
        except (ValueError, KeyError, TypeError, OverflowError):  # a huge integer
            usable = False
        if not usable:
            raise MailError(f"token request failed with status {status}")
        return token, lifetime

    def _get_token(self) -> str:
        """The cached token, or one new one; at most one refresh runs at a time, and a failed
        refresh caches nothing."""
        with self._lock:
            now = self._clock()
            if self._token is None or now >= self._token_until:
                token, lifetime = self._fetch_token()
                self._token, self._token_until = token, now + lifetime - REFRESH_MARGIN_SECONDS
            return self._token

    def _drop(self, token: str) -> None:
        with self._lock:
            if self._token == token:  # not a newer token another thread already fetched
                self._token = None

    def _send_once(self, token: str, payload: bytes) -> int:
        url = f"{self.graph_base}/users/{urllib.parse.quote(self.sender, safe='')}/sendMail"
        return self._post(url, payload, {"Authorization": f"Bearer {token}",
                                         "Content-Type": "application/json"}, "send")[0]

    def send(self, to: str, subject: str, text: str) -> None:
        if any(c in to + subject for c in "\r\n"):
            raise ValueError("header values must be one line")
        if not valid_email(to):
            raise ValueError("the recipient must be one email address")
        payload = json.dumps({"message": {
            "subject": subject, "body": {"contentType": "Text", "content": text},
            "toRecipients": [{"emailAddress": {"address": to}}]},
            "saveToSentItems": False}).encode("ascii")
        token = self._get_token()
        status = self._send_once(token, payload)
        if status == 401:  # the token was refused: one retry with a fresh one, never more
            self._drop(token)
            status = self._send_once(self._get_token(), payload)
        if status != 202:  # 202 means Graph queued it, not that it was delivered
            raise MailError(f"send failed with status {status}")


_GRAPH_MAILERS: dict[str, GraphMailer] = {}
_GRAPH_MAILERS_LOCK = threading.Lock()


def _cache_key(s: Settings) -> str:
    fields = (s.graph_tenant, s.graph_client_id, s.graph_client_secret, s.mail_from)
    return hashlib.sha256("\0".join(fields).encode("utf-8")).hexdigest()


def mailer(settings: Settings) -> FileMailer | GraphMailer:
    if settings.mail != "graph":
        return FileMailer(settings.mail_dir)
    key = _cache_key(settings)
    with _GRAPH_MAILERS_LOCK:
        if key not in _GRAPH_MAILERS:
            _GRAPH_MAILERS[key] = GraphMailer(settings.graph_tenant, settings.graph_client_id,
                                              settings.graph_client_secret, settings.mail_from)
        return _GRAPH_MAILERS[key]
