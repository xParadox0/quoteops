"""Stage 2b part 3: a fake Microsoft endpoint on 127.0.0.1 (token and sendMail in one local HTTP
server, started in the test, port 0) that records every request. No test contacts Microsoft;
every value here is fake."""
import json
import threading
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import quote

TENANT = "11111111-2222-3333-4444-555555555555"
CLIENT_ID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
CLIENT_SECRET = "fake~Secret.value_0123456789-abcdefghij"
SENDER = "quoteops@masch.example"
RECIPIENT = "customer@shop.test"
SUBJECT = "Your QuoteOps verification link"
TEXT = "Hello\nOpen https://qo.example/verify?token=abc\n"


@dataclass
class Req:
    kind: str       # "token", "send" or "other"
    path: str
    headers: dict
    body: bytes

    @property
    def json(self):
        return json.loads(self.body)


@dataclass
class Reply:
    status: int = 200
    body: bytes = b""
    headers: dict = field(default_factory=dict)
    delay: float = 0.0


class FakeGraph:
    """Plays the token endpoint and sendMail. token_plan and send_plan are lists of Reply used
    in order; when a plan is empty the default (a new token, or 202) answers."""

    def __init__(self, expires_in: int = 3600):
        self.requests: list[Req] = []
        self.token_plan: list[Reply] = []
        self.send_plan: list[Reply] = []
        self.expires_in = expires_in
        self.tokens_issued = 0
        self.token_delay = 0.0
        self._lock = threading.Lock()
        fake = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_POST(self):
                body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
                kind = ("token" if self.path.endswith("/oauth2/v2.0/token")
                        else "send" if self.path.endswith("/sendMail") else "other")
                with fake._lock:
                    fake.requests.append(Req(kind, self.path, dict(self.headers), body))
                    plan = {"token": fake.token_plan, "send": fake.send_plan}.get(kind, [])
                    reply = plan.pop(0) if plan else None
                    if reply is None and kind == "token":
                        fake.tokens_issued += 1
                        reply = Reply(200, json.dumps({
                            "token_type": "Bearer", "expires_in": fake.expires_in,
                            "access_token": f"tok-{fake.tokens_issued}"}).encode(),
                            delay=fake.token_delay)
                    elif reply is None:
                        reply = Reply(202 if kind == "send" else 200)
                if reply.delay:
                    threading.Event().wait(reply.delay)
                try:
                    self.send_response(reply.status)
                    for k, v in reply.headers.items():
                        self.send_header(k, v)
                    self.send_header("Content-Length", str(len(reply.body)))
                    self.end_headers()
                    self.wfile.write(reply.body)
                except OSError:
                    pass  # the client gave up (a timeout test)

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.server.daemon_threads = True
        self.base = f"http://127.0.0.1:{self.server.server_address[1]}"
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()

    def of(self, kind: str) -> list[Req]:
        with self._lock:
            return [r for r in self.requests if r.kind == kind]

    def tokens(self) -> list[Req]:
        return self.of("token")

    def sends(self) -> list[Req]:
        return self.of("send")

    @property
    def token_path(self) -> str:
        return f"/{TENANT}/oauth2/v2.0/token"

    @property
    def send_path(self) -> str:
        return f"/v1.0/users/{quote(SENDER, safe='')}/sendMail"
