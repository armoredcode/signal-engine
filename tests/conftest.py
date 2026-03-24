import pytest
import os
import tempfile
import shutil
from unittest.mock import patch

@pytest.fixture
def temp_db_dir():
    # Setup: create a temporary directory
    tmp_dir = tempfile.mkdtemp()
    
    # Patch appdirs.user_data_dir to return our temp directory
    with patch("signal_engine.ingest.user_data_dir") as mock_dir:
        mock_dir.return_value = tmp_dir
        yield tmp_dir
    
    # Teardown: remove the temporary directory
    shutil.rmtree(tmp_dir)
