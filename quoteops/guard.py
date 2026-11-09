"""What the public web app and the admin service share without importing each other's routes:
the security headers and generic error pages on every response, the request body limit, and the
request helpers for CSRF, the Origin check, the client address and email addresses. Moved here
from app.py and auth.py in stage 2b part 2; the web app's behaviour is unchanged."""
import hashlib
import hmac
import ipaddress
import logging
import re
from urllib.parse import urlsplit

from fastapi import Request
from fastapi.exception_handlers import http_exception_handler
from fastapi.exceptions import RequestValidationError
from fastapi.responses import Response
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.routing import Match

from quoteops import pages

log = logging.getLogger("quoteops")

CSP = ("default-src 'none'; style-src 'self'; form-action 'self'; frame-ancestors 'none';"
       " base-uri 'none'")
# same-origin, not no-referrer: under no-referrer a browser sends "Origin: null" with a form
# POST, which the Origin check must refuse. same-origin still sends nothing to other sites.
SECURITY_HEADERS = [
    (b"content-security-policy", CSP.encode("ascii")),
    (b"x-content-type-options", b"nosniff"),
    (b"referrer-policy", b"same-origin"),
    (b"x-frame-options", b"DENY"),
]
_SET_HERE = {k for k, _ in SECURITY_HEADERS} | {b"cache-control"}

EMAIL_RE = re.compile(r"[^@\s|]+@[^@\s|]+\.[^@\s|]+")
COOKIE_RE = re.compile(r"[A-Za-z0-9_-]{43}")

# The largest request body of any route of either application, except the routes named in
# ROUTE_BODY_LIMITS below. The largest real form is a few hundred bytes; the limit stops a client
# from making the form parser hold megabytes, and from handing an attacker-sized password to the
# password code.
MAX_BODY_BYTES = 16384

# Stage 3a: the routes with their own, larger body limit, keyed by method and exact path; there
# is no other way past MAX_BODY_BYTES. The middleware does not buffer such a body: it refuses a
# declared Content-Length over the limit before reading, counts the bytes as the route reads
# them (BodyTooLarge at the part that passes the limit), and closes the connection after any
# answer given before the body was read to its end. The route streams the body itself; the
# fields beside the file still have MAX_BODY_BYTES (quoteops/uploads.py).
UPLOAD_OVERHEAD = 64 * 1024  # multipart framing and the non-file fields of one upload


def _upload_limit() -> int:
    from quoteops.config import max_file_bytes  # config imports nothing from here at the top
    return max_file_bytes() + UPLOAD_OVERHEAD


ROUTE_BODY_LIMITS = {
    ("POST", "/jobs/upload"): _upload_limit,
}
_DIGITS = re.compile(rb"[0-9]+")  # ASCII digits only: int() would also take "+1", " 1", "\u0661"


class _Malformed(Exception):
    """A Content-Length that is not one whole number."""


class BodyTooLarge(Exception):
    """A streamed body (ROUTE_BODY_LIMITS) passed its limit; raised by receive()."""


def _declared_length(headers) -> int | None:
    """The request's Content-Length, None when it has none. Raises _Malformed for anything but
    ASCII digits, or for two headers that disagree."""
    values = {v for k, v in headers if k.lower() == b"content-length"}
    if not values:
        return None
    value = values.pop()
    if values or not _DIGITS.fullmatch(value):
        raise _Malformed()
    digits = value.lstrip(b"0") or b"0"
    return int(digits) if len(digits) <= 12 else 10 ** 12  # no int() of a huge string


async def _read_body(receive):
    """Read the whole body before the application sees the request, counting the bytes; stop
    at the part that passes MAX_BODY_BYTES and return None. Otherwise return a receive() that
    hands the application the body in one message and then defers to the server's. So no route
    runs on part of a body, and at most the limit plus one part is ever held."""
    parts, size = [], 0
    while True:
        message = await receive()
        if message["type"] != "http.request":  # the client left: pass that on
            break
        size += len(message.get("body", b""))
        if size > MAX_BODY_BYTES:
            return None
        parts.append(message.get("body", b""))
        if not message.get("more_body", False):
            message = {"type": "http.request", "body": b"".join(parts), "more_body": False}
            break
    pending = [message]

    async def replay():
        return pending.pop() if pending else await receive()
    return replay


def _counted(receive, limit: int, state: dict):
    """receive() for a streamed route: counts the bytes, raises BodyTooLarge at the part that
    passes `limit`, and records in state["complete"] whether the body was read to its end."""
    size = 0

    async def counted():
        nonlocal size
        message = await receive()
        if message["type"] == "http.request":
            size += len(message.get("body", b""))
            if size > limit:
                raise BodyTooLarge()
            if not message.get("more_body", False):
                state["complete"] = True
        return message
    return counted


class GuardMiddleware:
    """Outermost application layer: the request body limit (MAX_BODY_BYTES; 413, or 400 for a
    malformed Content-Length, before any route runs; a route in `route_limits` gets its own
    limit and its body streamed, see ROUTE_BODY_LIMITS), security headers on every response,
    no-store on everything but paths under `static_prefix`, and a generic 500 page (`template`)
    for any unhandled error. The error is logged by class name only, and it does not travel
    further, so no traceback (which can quote a database row) reaches the server log."""

    def __init__(self, app, template: str = "message.html", static_prefix: str | None = "/static/",
                 route_limits: dict | None = None):
        self.app = app
        self.template = template
        self.static_prefix = static_prefix
        self.route_limits = route_limits or {}  # the web app passes ROUTE_BODY_LIMITS

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        static = bool(self.static_prefix) and scope["path"].startswith(self.static_prefix)
        started = False
        limit_of = self.route_limits.get((scope["method"], scope["path"]))
        stream = {"complete": False}

        async def send_with_headers(msg):
            nonlocal started
            if msg["type"] == "http.response.start":
                started = True
                own = msg.get("headers", [])
                # A route may add a Content-Security-Policy of its own (the drawing download's
                # sandbox); it is sent beside ours, and a browser enforces both.
                headers = [(k, v) for k, v in own
                           if k.lower() not in _SET_HERE or (static and k.lower() == b"cache-control")]
                headers += [(k, v) for k, v in own if k.lower() == b"content-security-policy"
                            and v != SECURITY_HEADERS[0][1]]
                headers += SECURITY_HEADERS
                if not static:
                    headers.append((b"cache-control", b"no-store"))
                if limit_of is not None and not stream["complete"] and not any(
                        k.lower() == b"connection" for k, _ in headers):
                    # Answered before the body was read to its end: the rest is never read.
                    headers.append((b"connection", b"close"))
                msg = {**msg, "headers": headers}
            await send(msg)

        async def page(status: int, title: str, text: str, close: bool = False):
            body = pages.html(self.template, title=title, text=text, link=None).encode("utf-8")
            headers = [(b"content-type", b"text/html; charset=utf-8"),
                       (b"content-length", str(len(body)).encode("ascii"))]
            if close:
                # A refused body may be partly unread, so the connection ends here; and the
                # page is no-store even under the static prefix.
                headers += [(b"connection", b"close"), (b"cache-control", b"no-store")]
            await send_with_headers({"type": "http.response.start", "status": status,
                                     "headers": headers})
            await send_with_headers({"type": "http.response.body", "body": body})

        # The declared length first, before a byte of the body is read; then the body itself,
        # counted, which also covers a body without Content-Length (chunked).
        try:
            declared = _declared_length(scope["headers"])
        except _Malformed:
            await page(400, "Request not understood", "The request could not be read.", close=True)
            return
        if limit_of is not None:
            limit = limit_of()
            if declared is not None and declared > limit:
                await page(413, "Upload too large",
                           f"The upload is larger than {limit // 1048576} MB. The limit for one"
                           " drawing is shown on the form. Choose a smaller file.", close=True)
                return
            replay = _counted(receive, limit, stream)
        else:
            if declared is not None and declared > MAX_BODY_BYTES:
                await page(413, "Request too large", "The request is too large.", close=True)
                return
            replay = await _read_body(receive)
            if replay is None:
                await page(413, "Request too large", "The request is too large.", close=True)
                return

        try:
            await self.app(scope, replay, send_with_headers)
        except BodyTooLarge:
            if not started:  # the route did not answer it itself
                await page(413, "Upload too large", "The upload is too large.", close=True)
        except Exception as exc:
            log.error("unhandled error: %s", type(exc).__name__)
            if started:
                return
            await page(500, "Something went wrong",
                       "Something went wrong on our side. Try again in a few minutes.")


def http_error_handler(message):
    """404 and 405 as generic pages made by `message(title, text, status=...)`; anything else
    (the /healthz 503) keeps FastAPI's JSON body."""
    async def handler(request: Request, exc: StarletteHTTPException) -> Response:
        if exc.status_code == 404:
            return message("Page not found", "There is no page at this address.", status=404)
        if exc.status_code == 405:
            response = message("Not allowed", "This page does not accept that kind of request.",
                               status=405)
            # A 405 must carry Allow. Starlette fills it from the first route with this path
            # only, and /login has one route per method, so ask every route about every method.
            allowed = [m for m in ("GET", "HEAD", "POST", "PUT", "PATCH", "DELETE")
                       if any(r.matches({**request.scope, "method": m})[0] == Match.FULL
                              for r in request.app.router.routes)]
            response.headers["allow"] = ", ".join(allowed)
            return response
        return await http_exception_handler(request, exc)
    return handler


def validation_error_handler(message):
    async def handler(request: Request, exc: RequestValidationError) -> Response:
        return message("Request not understood", "The request could not be read.", status=422)
    return handler


# --- request helpers ------------------------------------------------------------------------------
# `s` is the web app's Settings or the admin service's AdminSettings: both carry secret,
# base_origin and client_ip_header.

def client_ip(request: Request, s) -> str:
    """The socket address, or the configured header when a trusted proxy sets it."""
    if s.client_ip_header:
        raw = request.headers.get(s.client_ip_header, "").split(",")[0].strip()
        if raw:
            return raw[:64]
    return request.client.host if request.client else "unknown"


def inet(ip: str) -> str | None:
    try:
        return str(ipaddress.ip_address(ip))
    except ValueError:
        return None


def mac(s, *parts: str) -> str:
    return hmac.new(s.secret, "|".join(parts).encode("utf-8"), hashlib.sha256).hexdigest()


def same(given: str, expected: str) -> bool:
    return hmac.compare_digest(given.encode("utf-8"), expected.encode("utf-8"))


def origin_ok(request: Request, s) -> bool:
    """Origin must be ours; only when a browser sends none is the Referer's origin used."""
    origin = request.headers.get("origin")
    if origin is not None:
        return origin.strip().lower() == s.base_origin
    referer = urlsplit(request.headers.get("referer", ""))
    return bool(referer.netloc) and f"{referer.scheme}://{referer.netloc}".lower() == s.base_origin


def norm_email(email: str) -> str:
    return email.strip().lower()[:320]


def valid_email(email: str) -> bool:
    return len(email) <= 254 and email.isprintable() and bool(EMAIL_RE.fullmatch(email))
