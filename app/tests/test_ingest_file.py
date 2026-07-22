from app.decoder import engine as decoder_engine

CSV_DECODER = {
    "name": "test_ingest_csv",
    "source": "test_ingest_csv",
    "type": "csv",
    "fields": {
        "source_ip": "client_ip",
        "status_code": "http_status",
    },
}

VALID_LOG_LINE = (
    '192.168.1.1 - - [10/Oct/2023:13:55:36 +0000] '
    '"GET /api/v1/health HTTP/1.1" 200 42 "-" "curl/7.88.1"'
)


async def test_ingest_file_generic_source_returns_error_detail(client, auth_headers):
    content = f"{VALID_LOG_LINE}\nthis is not a valid nginx log line\n".encode()
    response = await client.post(
        "/ingest/file",
        params={"source": "nginx"},
        files={"file": ("test.log", content, "text/plain")},
        headers=auth_headers,
    )
    assert response.status_code == 200
    body = response.json()
    assert body["processed"] == 1
    assert body["failed"] == 1
    assert body["errors"] == [{"line": 2, "error": "Log line could not be decoded"}]
    assert body["errors_truncated"] is False


async def test_ingest_file_csv_decodes_all_valid_rows(client, auth_headers, monkeypatch):
    monkeypatch.setitem(decoder_engine._decoders, "test_ingest_csv", CSV_DECODER)
    content = (
        "client_ip,http_status\n"
        "203.0.113.42,200\n"
        "203.0.113.43,404\n"
    ).encode()

    response = await client.post(
        "/ingest/file",
        params={"source": "test_ingest_csv"},
        files={"file": ("evidence.csv", content, "text/csv")},
        headers=auth_headers,
    )

    assert response.status_code == 200
    body = response.json()
    assert body["processed"] == 2
    assert body["failed"] == 0
    assert body["errors"] == []


async def test_ingest_file_csv_reports_bad_row_with_correct_line_number(client, auth_headers, monkeypatch):
    monkeypatch.setitem(decoder_engine._decoders, "test_ingest_csv", CSV_DECODER)
    content = (
        "client_ip,http_status\n"
        "203.0.113.42,200\n"
        "203.0.113.43\n"  # missing http_status column
        "203.0.113.44,404\n"
    ).encode()

    response = await client.post(
        "/ingest/file",
        params={"source": "test_ingest_csv"},
        files={"file": ("evidence.csv", content, "text/csv")},
        headers=auth_headers,
    )

    assert response.status_code == 200
    body = response.json()
    assert body["processed"] == 2
    assert body["failed"] == 1
    assert body["errors"] == [{"line": 3, "error": "CSV row could not be decoded"}]


async def test_ingest_file_csv_no_data_rows_returns_zero_processed(client, auth_headers, monkeypatch):
    monkeypatch.setitem(decoder_engine._decoders, "test_ingest_csv", CSV_DECODER)
    content = b"client_ip,http_status\n"

    response = await client.post(
        "/ingest/file",
        params={"source": "test_ingest_csv"},
        files={"file": ("evidence.csv", content, "text/csv")},
        headers=auth_headers,
    )

    assert response.status_code == 200
    assert response.json() == {
        "status": "ok", "processed": 0, "failed": 0, "errors": [], "errors_truncated": False,
    }


async def test_ingest_file_csv_errors_truncated_past_cap(client, auth_headers, monkeypatch):
    monkeypatch.setitem(decoder_engine._decoders, "test_ingest_csv", CSV_DECODER)
    monkeypatch.setattr("app.ingest.router._MAX_INGEST_ERRORS", 2)
    rows = "\n".join("bad_row_only_one_column" for _ in range(5))
    content = ("client_ip,http_status\n" + rows + "\n").encode()

    response = await client.post(
        "/ingest/file",
        params={"source": "test_ingest_csv"},
        files={"file": ("evidence.csv", content, "text/csv")},
        headers=auth_headers,
    )

    assert response.status_code == 200
    body = response.json()
    assert body["failed"] == 5
    assert len(body["errors"]) == 2
    assert body["errors_truncated"] is True
