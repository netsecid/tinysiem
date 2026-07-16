from starlette.applications import Starlette
from starlette.responses import JSONResponse
from starlette.routing import Route
from httpx import AsyncClient, ASGITransport

from app.mcp_server.server import _JWTMiddleware


def _build_test_app():
    async def _ok(request):
        return JSONResponse({"ok": True})
    app = Starlette(routes=[Route("/ping", _ok)])
    app.add_middleware(_JWTMiddleware)
    return app


async def _call(app, token):
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        headers = {"Authorization": f"Bearer {token}"} if token else {}
        return await ac.get("/ping", headers=headers)


async def test_mcp_rejects_missing_token():
    resp = await _call(_build_test_app(), None)
    assert resp.status_code == 401


async def test_mcp_accepts_valid_analyst_token(client, analyst_headers):
    token = analyst_headers["Authorization"].split(" ", 1)[1]
    resp = await _call(_build_test_app(), token)
    assert resp.status_code == 200


async def test_mcp_rejects_token_after_logout(client, admin_headers):
    token = admin_headers["Authorization"].split(" ", 1)[1]
    # This token is the shared admin_headers fixture's token — logging it out here
    # would break every other test using admin_headers in the same session. Instead,
    # log in fresh with the same credentials the admin_headers fixture uses, so we get
    # an independent token to revoke.
    #
    # NOTE: verified against app/tests/conftest.py rather than assumed. The seeded
    # superadmin ("admin"/"admin" via TINYSIEM_SUPERADMIN_PASSWORD) is NOT what the
    # admin_headers fixture uses — and logging in as that superadmin in this test env
    # sets must_change_password=True (because TINYSIEM_SUPERADMIN_PASSWORD == "admin"),
    # which the fixed MCP middleware correctly rejects outright, making resp_before
    # fail with 401 instead of 200. admin_headers instead calls
    # _get_or_create_fixture_user("fixture-admin", "admin"), which creates a user with
    # username "fixture-admin", password "fixture-only-never-logged-in-with", and
    # must_change_password left at its default (False) — so we log in with those
    # exact credentials instead.
    login = await client.post(
        "/auth/login",
        json={"username": "fixture-admin", "password": "fixture-only-never-logged-in-with"},
    )
    fresh_token = login.json()["access_token"]
    resp_before = await _call(_build_test_app(), fresh_token)
    assert resp_before.status_code == 200
    await client.post("/auth/logout", headers={"Authorization": f"Bearer {fresh_token}"})
    resp_after = await _call(_build_test_app(), fresh_token)
    assert resp_after.status_code == 401
