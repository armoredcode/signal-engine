import pytest
import os
from signal_engine.ingest import normalize_tool_fields, hash_message, get_repo_db_path

def test_hash_message():
    msg = "test message"
    h = hash_message(msg)
    assert len(h) == 40  # SHA1 is 40 chars hex
    assert h == hash_message(msg)
    assert h != hash_message("another message")

def test_normalize_semgrep():
    finding = {
        "check_id": "rules.test",
        "path": "test.py",
        "extra": {
            "message": "Found something",
            "severity": "ERROR"
        },
        "start": {
            "line": 10
        }
    }
    normalized = normalize_tool_fields(finding, "semgrep")
    assert normalized["tool"] == "semgrep"
    assert normalized["rule_id"] == "rules.test"
    assert normalized["file_path"] == "test.py"
    assert normalized["message"] == "Found something"
    assert normalized["severity"] == "ERROR"
    assert normalized["line_number"] == 10

def test_normalize_bandit():
    finding = {
        "test_id": "B101",
        "filename": "app.py",
        "issue_text": "Use of assert",
        "issue_severity": "LOW",
        "line_number": 5
    }
    normalized = normalize_tool_fields(finding, "bandit")
    assert normalized["tool"] == "bandit"
    assert normalized["rule_id"] == "B101"
    assert normalized["file_path"] == "app.py"
    assert normalized["message"] == "Use of assert"
    assert normalized["severity"] == "LOW"
    assert normalized["line_number"] == 5

def test_normalize_unsupported_tool():
    with pytest.raises(ValueError, match="Unsupported tool"):
        normalize_tool_fields({}, "unknown-tool")

def test_normalize_missing_fields():
    # Semgrep finding missing path
    finding = {
        "check_id": "rules.test",
        "extra": {"message": "msg", "severity": "info"},
        "start": {"line": 1}
    }
    normalized = normalize_tool_fields(finding, "semgrep")
    assert normalized["file_path"] is None

def test_get_repo_db_path(temp_db_dir):
    path = get_repo_db_path("my-repo")
    assert temp_db_dir in path
    assert path.endswith(".db")
    
    path2 = get_repo_db_path("my-repo")
    assert path == path2
    
    path3 = get_repo_db_path("other-repo")
    assert path != path3

def test_init_db(temp_db_dir):
    from signal_engine.ingest import init_db
    import sqlite3
    
    repo_name = "test-repo"
    db_path = get_repo_db_path(repo_name)
    init_db(db_path)
    
    assert os.path.exists(db_path)
    
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    # Check tables
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
    tables = {row[0] for row in cursor.fetchall()}
    assert "findings" in tables
    assert "metrics" in tables
    assert "metadata" in tables
    
    # Check metadata
    cursor.execute("SELECT key, value FROM metadata")
    metadata = dict(cursor.fetchall())
    assert "db_version" in metadata
    assert "tool_version" in metadata
    
    conn.close()

def test_ingest_and_fetch_findings(temp_db_dir):
    from signal_engine.ingest import ingest_findings, fetch_findings
    
    repo_name = "test-repo"
    findings = [
        {
            "tool": "semgrep",
            "file_path": "test.py",
            "line_number": 10,
            "rule_id": "rule1",
            "message": "msg1",
            "severity": "high"
        },
        {
            "tool": "bandit",
            "file_path": "other.py",
            "line_number": 5,
            "rule_id": "rule2",
            "message": "msg2",
            "severity": "low"
        }
    ]
    
    ingest_findings(findings, repo_name)
    
    # Fetch all
    fetched = fetch_findings(repo_name)
    assert len(fetched) == 2
    
    # Filter by tool
    fetched_semgrep = fetch_findings(repo_name, tool="semgrep")
    assert len(fetched_semgrep) == 1
    assert fetched_semgrep[0]["tool"] == "semgrep"
    
    # Filter by file
    fetched_file = fetch_findings(repo_name, file="other.py")
    assert len(fetched_file) == 1
    assert fetched_file[0]["file_path"] == "other.py"

def test_ingest_metrics(temp_db_dir):
    from signal_engine.ingest import ingest_metrics
    import sqlite3
    
    repo_name = "test-repo"
    cloc_data = {
        "Python": {"nFiles": 2, "blank": 10, "comment": 5, "code": 100},
        "JavaScript": {"nFiles": 1, "blank": 2, "comment": 1, "code": 50},
        "SUM": {"nFiles": 3, "blank": 12, "comment": 6, "code": 150}
    }
    
    ingest_metrics(cloc_data, repo_name)
    
    db_path = get_repo_db_path(repo_name)
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    cursor.execute("SELECT language, metric_type, value FROM metrics WHERE tool='cloc'")
    rows = cursor.fetchall()
    
    # 2 languages * 2 metric types (code_lines and files) = 4 rows
    assert len(rows) == 4
    
    languages = {r[0] for r in rows}
    assert "Python" in languages
    assert "JavaScript" in languages
    assert "SUM" not in languages
    
    conn.close()
