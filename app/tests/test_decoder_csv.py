from app.decoder import engine as decoder_engine

DECODER = {
    "name": "test_forensic_csv",
    "source": "test_forensic_csv",
    "type": "csv",
    "fields": {
        "source_ip": "client_ip",
        "status_code": "http_status",
        "uri": "request_path",
        "event_time": "ts",
    },
    "timestamp_field": "event_time",
    "timestamp_format": "%Y-%m-%d %H:%M:%S",
}


def test_parse_csv_header_splits_plain_columns():
    header = decoder_engine.parse_csv_header("client_ip,http_status,request_path,ts")
    assert header == ["client_ip", "http_status", "request_path", "ts"]


def test_parse_csv_header_handles_quoted_comma():
    header = decoder_engine.parse_csv_header('client_ip,"notes, free text",ts')
    assert header == ["client_ip", "notes, free text", "ts"]


def test_decode_csv_row_maps_custom_columns_to_schema_fields():
    header = decoder_engine.parse_csv_header("client_ip,http_status,request_path,ts")
    row = "203.0.113.42,404,/missing,2024-01-15 10:30:00"

    event = decoder_engine.decode_csv_row(DECODER, "test_forensic_csv", header, row)

    assert event is not None
    assert event["source"] == "test_forensic_csv"
    assert event["source_ip"] == "203.0.113.42"
    assert event["status_code"] == 404
    assert event["uri"] == "/missing"
    assert event["event_time"].strftime("%Y-%m-%d %H:%M:%S") == "2024-01-15 10:30:00"
    assert event["id"]
    assert event["raw"] == row


def test_decode_csv_row_handles_quoted_comma_in_value():
    header = decoder_engine.parse_csv_header("client_ip,http_status,request_path,ts")
    row = '203.0.113.42,200,"/search?q=a,b",2024-01-15 10:30:00'

    event = decoder_engine.decode_csv_row(DECODER, "test_forensic_csv", header, row)

    assert event is not None
    assert event["uri"] == "/search?q=a,b"


def test_decode_csv_row_column_count_mismatch_returns_none():
    header = decoder_engine.parse_csv_header("client_ip,http_status,request_path,ts")
    row = "203.0.113.42,404"  # missing two columns

    event = decoder_engine.decode_csv_row(DECODER, "test_forensic_csv", header, row)

    assert event is None


def test_decode_csv_row_unmapped_column_lands_in_extra():
    header = decoder_engine.parse_csv_header(
        "client_ip,http_status,request_path,ts,session_id"
    )
    row = "203.0.113.42,200,/,2024-01-15 10:30:00,abc123"

    event = decoder_engine.decode_csv_row(DECODER, "test_forensic_csv", header, row)

    assert event is not None
    assert event["extra"]["session_id"] == "abc123"


def test_get_decoder_returns_none_for_unknown_source():
    assert decoder_engine.get_decoder("does_not_exist_source") is None
