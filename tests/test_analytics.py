import pytest
from signal_engine.analytics import get_language_from_path, get_vulnerability_density
from signal_engine.ingest import ingest_findings, ingest_metrics

def test_get_language_from_path():
    assert get_language_from_path("test.py") == "Python"
    assert get_language_from_path("script.js") == "JavaScript"
    assert get_language_from_path("main.go") == "Go"
    assert get_language_from_path("Unknown.file") == "Unknown"
    assert get_language_from_path("README") == "Unknown"

def test_get_vulnerability_density(temp_db_dir):
    repo_name = "test-repo"
    
    # 1. Ingest metrics
    cloc_data = {
        "Python": {"code": 1000},
        "JavaScript": {"code": 500}
    }
    ingest_metrics(cloc_data, repo_name)
    
    # 2. Ingest findings
    findings = [
        # Python: 1 HIGH (5.0)
        {"tool": "semgrep", "file_path": "a.py", "line_number": 1, "rule_id": "r1", "message": "m1", "severity": "HIGH"},
        # JS: 1 CRITICAL (10.0) + 1 LOW (1.0) = 11.0
        {"tool": "semgrep", "file_path": "b.js", "line_number": 1, "rule_id": "r2", "message": "m2", "severity": "CRITICAL"},
        {"tool": "semgrep", "file_path": "c.js", "line_number": 1, "rule_id": "r3", "message": "m3", "severity": "LOW"},
    ]
    ingest_findings(findings, repo_name)
    
    stats = get_vulnerability_density(repo_name)
    
    # JS: risk 11.0, LOC 500 -> density (11 / 500) * 1000 = 22.0
    # PY: risk 5.0, LOC 1000 -> density (5 / 1000) * 1000 = 5.0
    
    assert stats[0]["language"] == "JavaScript"
    assert stats[0]["density"] == 22.0
    assert stats[0]["risk_score"] == 11.0
    
    assert stats[1]["language"] == "Python"
    assert stats[1]["density"] == 5.0
    assert stats[1]["risk_score"] == 5.0

def test_get_vulnerability_density_no_data(temp_db_dir):
    # Empty repo should return empty results
    stats = get_vulnerability_density("empty-repo")
    assert stats == []
