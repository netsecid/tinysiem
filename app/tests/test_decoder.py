from pathlib import Path

from app.decoder import engine as decoder_engine

DECODERS_DIR = Path(__file__).parent.parent / "decoder" / "decoders"

SAMPLE_LOG = (
    '203.0.113.42 - frank [10/Oct/2023:13:55:36 -0700] '
    '"GET /api/v1/users HTTP/1.1" 200 1234 '
    '"http://example.com/" "Mozilla/5.0 (Windows NT 10.0) Chrome/120.0"'
)


def setup_module(_):
    decoder_engine.load_decoders(DECODERS_DIR)


def test_nginx_decoder_extracts_all_fields():
    event = decoder_engine.decode("nginx", SAMPLE_LOG)

    assert event is not None
    assert event["source"] == "nginx"
    assert event["source_ip"] == "203.0.113.42"
    assert event["method"] == "GET"
    assert event["uri"] == "/api/v1/users"
    assert event["status_code"] == 200
    assert event["response_size"] == 1234
    assert "Mozilla/5.0" in event["user_agent"]
    assert event["referer"] == "http://example.com/"
    assert event["id"]
    assert event["ingested_at"] is not None
    assert event["event_time"] is not None


def test_nginx_decoder_no_match_returns_none():
    event = decoder_engine.decode("nginx", "this is not a valid nginx log line")
    assert event is None


def test_unknown_source_returns_none():
    event = decoder_engine.decode("unknown_source", SAMPLE_LOG)
    assert event is None


def test_dash_response_size_becomes_none():
    log = (
        '10.0.0.1 - - [10/Oct/2023:14:00:00 +0000] '
        '"HEAD /health HTTP/1.1" 204 - "-" "-"'
    )
    event = decoder_engine.decode("nginx", log)
    assert event is not None
    assert event["response_size"] is None
