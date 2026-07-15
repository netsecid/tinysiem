"""Tests for Case <-> Event linkage."""
import pytest

from app.cases import store as case_store


async def test_link_and_unlink_event(client, analyst_headers):
    cr = await client.post("/cases", json={"title": "Event Link"}, headers=analyst_headers)
    case_id = cr.json()["case_id"]

    link_resp = await client.post(
        f"/cases/{case_id}/events",
        json={"event_ids": ["fake-event-001"]},
        headers=analyst_headers,
    )
    assert link_resp.status_code == 200
    assert "fake-event-001" in link_resp.json()["linked"]

    unlink_resp = await client.delete(
        f"/cases/{case_id}/events/fake-event-001", headers=analyst_headers
    )
    assert unlink_resp.status_code == 204

    # Cleanup: remove case so test_cases.py::test_list_cases_empty sees an empty table
    case_store.delete_case(case_id)


async def test_link_event_case_not_found(client, analyst_headers):
    resp = await client.post(
        "/cases/nonexistent-case/events",
        json={"event_ids": ["fake-event-001"]},
        headers=analyst_headers,
    )
    assert resp.status_code == 404


async def test_unlink_event_not_linked(client, analyst_headers):
    cr = await client.post("/cases", json={"title": "Unlink Not Linked"}, headers=analyst_headers)
    case_id = cr.json()["case_id"]
    resp = await client.delete(
        f"/cases/{case_id}/events/never-linked-event", headers=analyst_headers
    )
    assert resp.status_code == 404

    # Cleanup: remove case so test_cases.py::test_list_cases_empty sees an empty table
    case_store.delete_case(case_id)


async def test_get_case_includes_linked_event_ids(client, analyst_headers):
    cr = await client.post("/cases", json={"title": "Linked IDs"}, headers=analyst_headers)
    case_id = cr.json()["case_id"]
    await client.post(
        f"/cases/{case_id}/events", json={"event_ids": ["ev-1", "ev-2"]}, headers=analyst_headers
    )
    resp = await client.get(f"/cases/{case_id}", headers=analyst_headers)
    assert resp.status_code == 200
    linked_ids = {e["event_id"] for e in resp.json()["linked_event_ids"]}
    assert linked_ids == {"ev-1", "ev-2"}

    # Cleanup: remove case so test_cases.py::test_list_cases_empty sees an empty table
    case_store.delete_case(case_id)


async def test_get_cases_for_event(client, analyst_headers):
    cr = await client.post("/cases", json={"title": "Reverse Lookup"}, headers=analyst_headers)
    case_id = cr.json()["case_id"]
    await client.post(
        f"/cases/{case_id}/events", json={"event_ids": ["ev-reverse-1"]}, headers=analyst_headers
    )
    resp = await client.get("/events/ev-reverse-1/cases", headers=analyst_headers)
    assert resp.status_code == 200
    case_ids = {c["case_id"] for c in resp.json()["cases"]}
    assert case_id in case_ids

    # Cleanup: remove case so test_cases.py::test_list_cases_empty sees an empty table
    case_store.delete_case(case_id)


async def test_get_cases_for_event_empty(client, analyst_headers):
    resp = await client.get("/events/never-linked/cases", headers=analyst_headers)
    assert resp.status_code == 200
    assert resp.json()["cases"] == []
