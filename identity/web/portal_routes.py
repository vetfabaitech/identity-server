"""The developer portal's pages: `/developer/services` (the single-page app) and `/handoff` (where its sign-in returns).

These routes serve static HTML and carry no data and no credentials. Everything the page shows comes from
`/auth/admin/*`, where every permission is enforced; hiding a button here (or in the script) never grants or removes
anything. Sign-in is the identity service's own: the page sends the person through `/auth/login`, which needs this
host to be one of the allowed return origins (docs/developer-portal.md, "Sign-in for the portal").
"""

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response

router = APIRouter()


@router.get("/developer", include_in_schema=False)
async def developer_root() -> Response:
    return RedirectResponse("/developer/services", status_code=307)


@router.get("/developer/services", include_in_schema=False)
async def developer_portal(request: Request) -> HTMLResponse:
    templates = request.app.state.templates
    return templates.TemplateResponse(request, "developer.html", {"title": "Developer portal"})


@router.get("/handoff", include_in_schema=False)
async def portal_return(request: Request) -> HTMLResponse:
    """Where a sign-in started from the portal comes back. It reads nothing from the URL: the session cookie set by
    the sign-in is what the portal uses, so the token in the fragment is dropped unread."""
    templates = request.app.state.templates
    return templates.TemplateResponse(request, "portal_return.html", {"title": "Signing in"})
