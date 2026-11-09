import logging
from contextlib import asynccontextmanager

import psycopg
from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import PlainTextResponse, RedirectResponse, Response
from starlette.exceptions import HTTPException as StarletteHTTPException

from quoteops import pages, uploads
from quoteops.auth import Forbidden, NotSignedIn, current_principal, router
from quoteops.config import ConfigError, load_settings, web_conninfo
from quoteops.dbconn import tenant_conn  # noqa: F401  (part of this module's interface since stage 1)
from quoteops.guard import (  # noqa: F401  (CSP and SECURITY_HEADERS: this module's interface)
    CSP, ROUTE_BODY_LIMITS, SECURITY_HEADERS, GuardMiddleware, http_error_handler,
    validation_error_handler,
)
from quoteops.jobs import router as jobs_router
from quoteops.team import router as team_router

log = logging.getLogger("quoteops")

# The middleware and the 404/405/422 pages live in quoteops.guard since stage 2b part 2, so the
# admin service can use them without importing these routes. Same names, same behaviour.
_http_error = http_error_handler(pages.message)
_validation_error = validation_error_handler(pages.message)


async def _not_signed_in(request: Request, exc: NotSignedIn) -> Response:
    return RedirectResponse("/login", status_code=303)


async def _forbidden(request: Request, exc: Forbidden) -> Response:
    return pages.message("Not allowed", exc.text, status=403)


def configure(app: FastAPI) -> None:
    """Middleware and error pages shared by the app (and by tests that mount the dependencies)."""
    # The drawing upload is the one route with its own body limit (guard.ROUTE_BODY_LIMITS).
    app.add_middleware(GuardMiddleware, route_limits=ROUTE_BODY_LIMITS)
    app.add_exception_handler(StarletteHTTPException, _http_error)
    app.add_exception_handler(RequestValidationError, _validation_error)
    app.add_exception_handler(NotSignedIn, _not_signed_in)
    app.add_exception_handler(Forbidden, _forbidden)


@asynccontextmanager
async def _lifespan(app: FastAPI):
    try:
        s = load_settings()
    except ConfigError as exc:
        log.critical("QuoteOps refuses to start: %s", exc)
        raise
    # Temporary upload files left by a crash or a restart mid-upload (HLD section 13).
    removed = uploads.sweep_tmp(s.files_dir)
    if removed:
        log.info("removed %d old temporary upload files", removed)
    yield


app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None, lifespan=_lifespan)
configure(app)
app.include_router(router)
app.include_router(team_router)
app.include_router(jobs_router)


@app.get("/healthz", response_class=PlainTextResponse)
def healthz() -> str:
    try:
        with psycopg.connect(web_conninfo(), connect_timeout=3) as conn:
            if conn.execute("SELECT 1").fetchone() != (1,):
                raise RuntimeError("unexpected result")
    except Exception as exc:
        logging.getLogger("quoteops").error("healthz database check failed: %s", type(exc).__name__)
        raise HTTPException(status_code=503, detail="database check failed")
    return "ok"


@app.get("/")
def index(request: Request):
    # Signed in: the app. Anonymous: the sign-in page.
    if current_principal(request):
        return RedirectResponse("/app", status_code=303)
    return RedirectResponse("/login", status_code=303)


@app.get("/static/app.css")
def stylesheet() -> Response:
    return Response(pages.CSS, media_type="text/css",
                    headers={"cache-control": "public, max-age=3600"})
