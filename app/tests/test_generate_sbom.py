from app.generate_sbom import parse_freeze_output


def test_parse_freeze_output_extracts_name_and_version():
    output = "fastapi==0.115.5\nuvicorn==0.32.1\n# a comment\nnodash-no-version\n"
    result = parse_freeze_output(output)
    assert {"name": "fastapi", "version": "0.115.5"} in result
    assert {"name": "uvicorn", "version": "0.32.1"} in result
    assert len(result) == 2


def test_parse_freeze_output_empty_string_returns_empty_list():
    assert parse_freeze_output("") == []
