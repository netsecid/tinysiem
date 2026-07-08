import importlib
import pathlib

import pytest


def test_chromadb_not_a_dependency():
    req = pathlib.Path(__file__).parent.parent / "requirements.txt"
    content = req.read_text().lower()
    assert "chromadb" not in content


def test_no_chroma_store_module():
    with pytest.raises(ModuleNotFoundError):
        importlib.import_module("app.storage.chroma_store")
