import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).parent))
import ingest_file  # noqa: E402


def test_map_batch_error_line_no_header():
    assert ingest_file.map_batch_error_line(batch_start_line=1, has_header=False, server_line=1) == 1
    assert ingest_file.map_batch_error_line(batch_start_line=101, has_header=False, server_line=5) == 105


def test_map_batch_error_line_with_header():
    assert ingest_file.map_batch_error_line(batch_start_line=2, has_header=True, server_line=2) == 2
    assert ingest_file.map_batch_error_line(batch_start_line=2002, has_header=True, server_line=5) == 2005


def test_read_batches_splits_into_chunks_of_batch_size(tmp_path):
    f = tmp_path / "data.log"
    f.write_text("line1\nline2\nline3\nline4\nline5\n")

    batches = list(ingest_file.read_batches(str(f), batch_size=2, has_header=False))

    assert batches == [
        (1, None, ["line1", "line2"]),
        (3, None, ["line3", "line4"]),
        (5, None, ["line5"]),
    ]


def test_read_batches_with_header_offsets_data_lines(tmp_path):
    f = tmp_path / "data.csv"
    f.write_text("col_a,col_b\nrow1\nrow2\nrow3\n")

    batches = list(ingest_file.read_batches(str(f), batch_size=2, has_header=True))

    assert batches == [
        (2, "col_a,col_b", ["row1", "row2"]),
        (4, "col_a,col_b", ["row3"]),
    ]


def test_read_batches_skips_blank_lines(tmp_path):
    f = tmp_path / "data.log"
    f.write_text("line1\n\nline2\n")

    batches = list(ingest_file.read_batches(str(f), batch_size=10, has_header=False))

    assert batches == [(1, None, ["line1", "line2"])]


def test_read_batches_header_only_file_yields_nothing(tmp_path):
    f = tmp_path / "data.csv"
    f.write_text("col_a,col_b\n")

    batches = list(ingest_file.read_batches(str(f), batch_size=10, has_header=True))

    assert batches == []
