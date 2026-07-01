"""Tests for API Integrations (v1.2)."""
import uuid


# ── Types endpoint ─────────────────────────────────────────────────────────────

async def test_list_types_returns_known_types(client, analyst_headers):
    r = await client.get("/integrations/types", headers=analyst_headers)
    assert r.status_code == 200
    types = {t["integration_type"] for t in r.json()["types"]}
    assert "aws_cloudtrail" in types
    assert "google_workspace" in types


async def test_list_types_requires_auth(client):
    r = await client.get("/integrations/types")
    assert r.status_code == 401


# ── List integrations ──────────────────────────────────────────────────────────

async def test_list_integrations_empty(client, analyst_headers):
    r = await client.get("/integrations", headers=analyst_headers)
    assert r.status_code == 200
    assert "integrations" in r.json()


async def test_list_integrations_requires_auth(client):
    r = await client.get("/integrations")
    assert r.status_code == 401


# ── Create ────────────────────────────────────────────────────────────────────

async def test_create_integration(client, admin_headers):
    r = await client.post(
        "/integrations",
        json={
            "name": f"test-ct-{uuid.uuid4().hex[:6]}",
            "integration_type": "aws_cloudtrail",
            "schedule_minutes": 30,
            "config": {"region": "us-east-1", "s3_bucket": "my-bucket"},
            "credentials": {"aws_access_key_id": "AKIATEST", "aws_secret_access_key": "secrettest"},
        },
        headers=admin_headers,
    )
    assert r.status_code == 201
    d = r.json()
    assert d["integration_type"] == "aws_cloudtrail"
    assert d["schedule_minutes"] == 30
    # credentials must be masked
    creds = d["credentials"]
    assert "AKIATEST" not in str(creds)
    assert "**..." in str(creds) or "****" in str(creds)


async def test_create_integration_requires_admin(client, analyst_headers):
    r = await client.post(
        "/integrations",
        json={
            "name": "no-permission",
            "integration_type": "aws_cloudtrail",
            "config": {},
            "credentials": {},
        },
        headers=analyst_headers,
    )
    assert r.status_code == 403


async def test_create_integration_unknown_type(client, admin_headers):
    r = await client.post(
        "/integrations",
        json={"name": "bad", "integration_type": "does_not_exist", "config": {}, "credentials": {}},
        headers=admin_headers,
    )
    assert r.status_code == 400


# ── Get / PATCH / DELETE ───────────────────────────────────────────────────────

async def test_get_integration_masked_credentials(client, admin_headers):
    r = await client.post(
        "/integrations",
        json={
            "name": f"ct-get-{uuid.uuid4().hex[:6]}",
            "integration_type": "aws_cloudtrail",
            "config": {"region": "eu-west-1"},
            "credentials": {"aws_access_key_id": "AKIAXXXXTEST", "aws_secret_access_key": "supersecretsauce"},
        },
        headers=admin_headers,
    )
    assert r.status_code == 201
    iid = r.json()["integration_id"]

    r2 = await client.get(f"/integrations/{iid}", headers=admin_headers)
    assert r2.status_code == 200
    creds = r2.json()["credentials"]
    # value must be masked — plaintext must not appear
    assert "AKIAXXXXTEST" not in str(creds)
    assert "supersecretsauce" not in str(creds)
    # last 4 chars of plaintext should appear in mask
    assert "TEST" in str(creds)


async def test_get_integration_not_found(client, analyst_headers):
    r = await client.get(f"/integrations/{uuid.uuid4()}", headers=analyst_headers)
    assert r.status_code == 404


async def test_patch_integration(client, admin_headers):
    r = await client.post(
        "/integrations",
        json={
            "name": f"ct-patch-{uuid.uuid4().hex[:6]}",
            "integration_type": "aws_cloudtrail",
            "config": {},
            "credentials": {"aws_access_key_id": "AKIAold", "aws_secret_access_key": "oldsecret"},
        },
        headers=admin_headers,
    )
    iid = r.json()["integration_id"]

    r2 = await client.patch(
        f"/integrations/{iid}",
        json={"enabled": False, "schedule_minutes": 60},
        headers=admin_headers,
    )
    assert r2.status_code == 200
    assert r2.json()["enabled"] is False
    assert r2.json()["schedule_minutes"] == 60


async def test_delete_integration(client, admin_headers):
    r = await client.post(
        "/integrations",
        json={
            "name": f"ct-del-{uuid.uuid4().hex[:6]}",
            "integration_type": "aws_cloudtrail",
            "config": {},
            "credentials": {"aws_access_key_id": "AKIADEL", "aws_secret_access_key": "delsecret"},
        },
        headers=admin_headers,
    )
    iid = r.json()["integration_id"]
    r2 = await client.delete(f"/integrations/{iid}", headers=admin_headers)
    assert r2.status_code == 204
    r3 = await client.get(f"/integrations/{iid}", headers=admin_headers)
    assert r3.status_code == 404


async def test_delete_not_found(client, admin_headers):
    r = await client.delete(f"/integrations/{uuid.uuid4()}", headers=admin_headers)
    assert r.status_code == 404


# ── Runs ──────────────────────────────────────────────────────────────────────

async def test_list_runs_empty(client, admin_headers):
    r = await client.post(
        "/integrations",
        json={
            "name": f"ct-runs-{uuid.uuid4().hex[:6]}",
            "integration_type": "aws_cloudtrail",
            "config": {},
            "credentials": {"aws_access_key_id": "AKIARUN", "aws_secret_access_key": "runsecret"},
        },
        headers=admin_headers,
    )
    iid = r.json()["integration_id"]
    r2 = await client.get(f"/integrations/{iid}/runs", headers=admin_headers)
    assert r2.status_code == 200
    assert r2.json()["runs"] == []


# ── Store unit tests ───────────────────────────────────────────────────────────

def test_create_and_list_integration():
    from app.integrations import store as istore
    integ = istore.create_integration(
        name=f"unit-{uuid.uuid4().hex[:6]}",
        integration_type="aws_cloudtrail",
        config={"region": "us-east-1"},
        credentials={"aws_access_key_id": "AKIAUNIT", "aws_secret_access_key": "unitsecret"},
        schedule_minutes=15,
        created_by="test",
    )
    assert integ["integration_type"] == "aws_cloudtrail"
    # credentials should be masked in returned dict
    assert "AKIAUNIT" not in str(integ["credentials"])
    listing = istore.list_integrations()
    ids = [i["integration_id"] for i in listing]
    assert integ["integration_id"] in ids


def test_get_integration_unmasked():
    from app.integrations import store as istore
    integ = istore.create_integration(
        name=f"unmask-{uuid.uuid4().hex[:6]}",
        integration_type="aws_cloudtrail",
        config={},
        credentials={"aws_access_key_id": "AKIAraw", "aws_secret_access_key": "rawsecret"},
        schedule_minutes=15,
        created_by="test",
    )
    full = istore.get_integration(integ["integration_id"], masked=False)
    # unmasked should have plaintext
    assert full["credentials"]["aws_access_key_id"] == "AKIAraw"
    assert full["credentials"]["aws_secret_access_key"] == "rawsecret"


def test_run_lifecycle():
    from app.integrations import store as istore
    integ = istore.create_integration(
        name=f"runlc-{uuid.uuid4().hex[:6]}",
        integration_type="aws_cloudtrail",
        config={},
        credentials={"aws_access_key_id": "AKIAx", "aws_secret_access_key": "x"},
        schedule_minutes=15,
        created_by="test",
    )
    iid = integ["integration_id"]
    run_id = istore.insert_run(iid)
    assert isinstance(run_id, str)
    istore.finish_run(run_id, "ok", events_pulled=10, events_ingested=10, next_cursor="cursor123")
    runs = istore.list_runs(iid)
    assert len(runs) == 1
    assert runs[0]["status"] == "ok"
    assert runs[0]["events_pulled"] == 10
    assert istore.get_last_cursor(iid) == "cursor123"
