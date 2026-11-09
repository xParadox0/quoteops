"""The permission table for job actions (PRD F6, HLD section 13). One place: every job route
names its action here, and later stages add their actions to the same table. A role outside an
action's set gets 403; a request without a valid session is redirected to /login as elsewhere."""
from fastapi import Depends

from quoteops.auth import Forbidden, Principal, require_user
from quoteops.dbconn import tenant_conn

ALL_ROLES = ("owner", "estimator", "accountant", "viewer")
EDITORS = ("owner", "estimator")

# action -> the roles allowed to do it, compared exactly.
ACTIONS: dict[str, tuple[str, ...]] = {
    "view_jobs": ALL_ROLES,           # the job list, a job, and downloading its drawings
    "create_job": EDITORS,
    "edit_job": EDITORS,
    "upload_drawing": EDITORS,
    "delete_drawing": EDITORS,
}


def allowed(role: str, action: str) -> bool:
    return role in ACTIONS[action]


def nav_for(principal: Principal, current: str) -> dict:
    """The left navigation: only what has a working backend in this stage."""
    return {"current": current, "create": allowed(principal.role, "create_job"),
            "owner": principal.role == "owner"}


ROLE_REFUSAL = ("Your role can see jobs but not change them. Ask the owner of your company if"
                " you need to create or change jobs and drawings.")


def _refusal(action: str) -> str:
    if action == "view_jobs":
        return "Your role does not allow you to see jobs."
    return ROLE_REFUSAL


def require(action: str):
    """A FastAPI dependency: a signed-in user whose role may do `action`, whose address is
    verified and whose company is active (read in the user's own tenant transaction). It reads no
    request body, so on the upload route it runs before a byte of the body is read."""
    if action not in ACTIONS:
        raise KeyError(action)

    def dependency(principal: Principal = Depends(require_user)) -> Principal:
        if not allowed(principal.role, action):
            raise Forbidden(_refusal(action))
        with tenant_conn(principal.company_id) as conn:
            row = conn.execute("SELECT u.email_verified_at IS NOT NULL, c.status FROM app_user u"
                               " JOIN company c ON c.id = u.company_id WHERE u.id = %s",
                               (principal.user_id,)).fetchone()
        if row is None or not row[0]:
            raise Forbidden("Verify your email address first. Open the link we sent when you"
                            " signed up.")
        if row[1] != "active":
            raise Forbidden("This company is not active. Jobs and drawings are available once"
                            " the company's email address is verified.")
        return principal
    return dependency
