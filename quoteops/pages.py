"""Server-rendered pages: Jinja templates with autoescaping, and the one stylesheet."""
from importlib import resources

from fastapi.responses import HTMLResponse
from jinja2 import Environment, PackageLoader, select_autoescape

_env = Environment(loader=PackageLoader("quoteops", "templates"),
                   autoescape=select_autoescape(["html"]),
                   trim_blocks=True, lstrip_blocks=True)

CSS = resources.files("quoteops").joinpath("static/app.css").read_bytes()


def html(template: str, **context) -> str:
    context.setdefault("errors", {})
    context.setdefault("values", {})
    return _env.get_template(template).render(**context)


def render(template: str, status: int = 200, **context) -> HTMLResponse:
    return HTMLResponse(html(template, **context), status_code=status)


def message(title: str, text: str, status: int = 200, link: tuple[str, str] | None = None
            ) -> HTMLResponse:
    """A page with a heading, one paragraph and an optional link (href, label)."""
    return render("message.html", status=status, title=title, text=text, link=link)
