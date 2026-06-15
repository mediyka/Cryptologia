import gc
import os
import sys

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src")))

from database.db import DatabaseHelper


@pytest.fixture(autouse=True)
def close_database_helpers():
    yield
    DatabaseHelper.close_all()
    gc.collect()
