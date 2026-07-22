import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).parent))
import ingest_file  # noqa: E402


def test_read_batches_splits_into_chunks_of_batch_size(tmp_path):
    f = tmp_path / "data.log"
    f.write_text("line1\nline2\nline3\nline4\nline5\n")

    batches = list(ingest_file.read_batches(str(f), batch_size=2, has_header=False))

    assert batches == [
        (None, ["line1", "line2"], [1, 2]),
        (None, ["line3", "line4"], [3, 4]),
        (None, ["line5"], [5]),
    ]


def test_read_batches_with_header_offsets_data_lines(tmp_path):
    f = tmp_path / "data.csv"
    f.write_text("col_a,col_b\nrow1\nrow2\nrow3\n")

    batches = list(ingest_file.read_batches(str(f), batch_size=2, has_header=True))

    assert batches == [
        ("col_a,col_b", ["row1", "row2"], [2, 3]),
        ("col_a,col_b", ["row3"], [4]),
    ]


def test_read_batches_skips_blank_lines(tmp_path):
    f = tmp_path / "data.log"
    f.write_text("line1\n\nline2\n")

    batches = list(ingest_file.read_batches(str(f), batch_size=10, has_header=False))

    assert batches == [(None, ["line1", "line2"], [1, 3])]


def test_read_batches_header_only_file_yields_nothing(tmp_path):
    f = tmp_path / "data.csv"
    f.write_text("col_a,col_b\n")

    batches = list(ingest_file.read_batches(str(f), batch_size=10, has_header=True))

    assert batches == []


def test_read_batches_blank_line_at_chunk_boundary_reports_correct_line_number(tmp_path):
    f = tmp_path / "data.log"
    f.write_text("line1\n\nline2\n")

    batches = list(ingest_file.read_batches(str(f), batch_size=1, has_header=False))

    assert batches == [(None, ["line1"], [1]), (None, ["line2"], [3])]


def test_read_batches_blank_line_mid_batch_reports_correct_line_numbers(tmp_path):
    f = tmp_path / "data.log"
    f.write_text("line1\n\nline2\nline3\n")

    batches = list(ingest_file.read_batches(str(f), batch_size=3, has_header=False))

    assert batches == [(None, ["line1", "line2", "line3"], [1, 3, 4])]
