import json
import os
import pytest
from typer.testing import CliRunner
from signal_engine.cli import app

runner = CliRunner()

@pytest.fixture
def sample_json(tmp_path):
    data = {
        "results": [
            {
                "check_id": "rule1",
                "path": "file1.py",
                "extra": {"message": "msg1", "severity": "high"},
                "start": {"line": 10}
            }
        ]
    }
    json_file = tmp_path / "results.json"
    json_file.write_text(json.dumps(data))
    return json_file

def test_cli_ingest(temp_db_dir, sample_json):
    result = runner.invoke(app, ["ingest", str(sample_json), "--repo-name", "test-repo", "--tool", "semgrep"])
    assert result.exit_code == 0
    assert "Ingested 1 findings" in result.stdout

def test_cli_analyze(temp_db_dir, sample_json):
    # Ingest first
    runner.invoke(app, ["ingest", str(sample_json), "--repo-name", "test-repo", "--tool", "semgrep"])
    
    # Then analyze
    result = runner.invoke(app, ["analyze", "--repo-name", "test-repo"])
    assert result.exit_code == 0
    assert "Top Rules:" in result.stdout
    assert "rule1: 1" in result.stdout

def test_cli_info(temp_db_dir, sample_json):
    # Ingest first
    runner.invoke(app, ["ingest", str(sample_json), "--repo-name", "test-repo", "--tool", "semgrep"])
    
    # Then info
    result = runner.invoke(app, ["info", "--repo-name", "test-repo"])
    assert result.exit_code == 0
    assert "Repository: test-repo" in result.stdout

def test_cli_version():
    from signal_engine import __version__
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert __version__ in result.stdout

def test_cli_hotspots(temp_db_dir, sample_json):
    # Ingest findings
    runner.invoke(app, ["ingest", str(sample_json), "--repo-name", "test-repo", "--tool", "semgrep"])
    # Ingest metrics
    cloc_data = {"Python": {"code": 100}}
    cloc_file = sample_json.parent / "cloc.json"
    cloc_file.write_text(json.dumps(cloc_data))
    runner.invoke(app, ["ingest", str(cloc_file), "--repo-name", "test-repo", "--tool", "cloc"])
    
    result = runner.invoke(app, ["hotspots", "--repo-name", "test-repo"])
    assert result.exit_code == 0
    assert "Risk Hotspots for 'test-repo'" in result.stdout
    assert "Python" in result.stdout

def test_cli_stats(temp_db_dir, sample_json):
    result = runner.invoke(app, ["stats", str(sample_json.parent), "--tool", "semgrep"])
    assert result.exit_code == 0
    assert "Total findings: 1" in result.stdout

def test_cli_report(temp_db_dir, sample_json, tmp_path):
    report_file = tmp_path / "my_report.csv"
    result = runner.invoke(app, ["report", str(sample_json.parent), "--tool", "semgrep", "-o", str(report_file)])
    assert result.exit_code == 0
    assert os.path.exists(report_file)

def test_cli_dedup(temp_db_dir, sample_json):
    # Ingest same finding twice to different tools/rules at same line
    runner.invoke(app, ["ingest", str(sample_json), "--repo-name", "test-repo", "--tool", "semgrep"])
    
    result = runner.invoke(app, ["dedup", "--repo-name", "test-repo"])
    assert result.exit_code == 0
    assert "Smart Deduplication: test-repo" in result.stdout

def test_cli_migrate(temp_db_dir):
    # Create an empty DB (not even initialized)
    repo_name = "migrate-repo"
    
    # Check
    result = runner.invoke(app, ["migrate", "--repo-name", repo_name, "--check"])
    assert "missing" in result.stdout
    
    # Run
    result = runner.invoke(app, ["migrate", "--repo-name", repo_name])
    assert result.exit_code == 0
    assert "Migrating" in result.stdout
    
    # Check again
    result = runner.invoke(app, ["migrate", "--repo-name", repo_name, "--check"])
    assert "up to date" in result.stdout

def test_cli_ingest_sarif(temp_db_dir, tmp_path):
    sarif_data = {
        "runs": [{
            "results": [{
                "ruleId": "r1",
                "message": {"text": "msg1"},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": "file.py"},
                        "region": {"startLine": 1}
                    }
                }]
            }]
        }]
    }
    sarif_file = tmp_path / "scan.sarif.json"
    sarif_file.write_text(json.dumps(sarif_data))
    
    result = runner.invoke(app, ["ingest", str(sarif_file), "--repo-name", "sarif-repo", "--tool", "sarif"])
    assert result.exit_code == 0
    assert "Ingested 1 findings" in result.stdout

def test_cli_analyze_with_filters(temp_db_dir, sample_json, tmp_path):
    # Ingest findings
    runner.invoke(app, ["ingest", str(sample_json), "--repo-name", "test-repo", "--tool", "semgrep"])
    
    # Analyze with filter by tool (match)
    result = runner.invoke(app, ["analyze", "--repo-name", "test-repo", "--tool", "semgrep"])
    assert result.exit_code == 0
    assert "rule1: 1" in result.stdout
    
    # Analyze with filter by tool (no match)
    result = runner.invoke(app, ["analyze", "--repo-name", "test-repo", "--tool", "bandit"])
    assert result.exit_code == 1
    assert "No findings found" in result.stdout
    
    # Analyze with output file
    out_csv = tmp_path / "analyze.csv"
    result = runner.invoke(app, ["analyze", "--repo-name", "test-repo", "-o", str(out_csv)])
    assert result.exit_code == 0
    assert os.path.exists(out_csv)

def test_cli_hotspots_with_tool_filter(temp_db_dir, sample_json):
    # Ingest findings
    runner.invoke(app, ["ingest", str(sample_json), "--repo-name", "test-repo", "--tool", "semgrep"])
    # Ingest metrics
    cloc_data = {"Python": {"code": 100}}
    cloc_file = sample_json.parent / "cloc.json"
    cloc_file.write_text(json.dumps(cloc_data))
    runner.invoke(app, ["ingest", str(cloc_file), "--repo-name", "test-repo", "--tool", "cloc"])
    
    result = runner.invoke(app, ["hotspots", "--repo-name", "test-repo", "--tool", "semgrep"])
    assert result.exit_code == 0
    assert "Tool: semgrep" in result.stdout

def test_cli_info_verbose(temp_db_dir, sample_json):
    runner.invoke(app, ["ingest", str(sample_json), "--repo-name", "test-repo", "--tool", "semgrep"])
    result = runner.invoke(app, ["info", "--repo-name", "test-repo", "--verbose"])
    assert result.exit_code == 0
    assert "Tools in DB: semgrep" in result.stdout

def test_cli_ingest_cloc(temp_db_dir, tmp_path):
    cloc_data = {"Python": {"nFiles": 1, "blank": 1, "comment": 1, "code": 10}}
    cloc_file = tmp_path / "cloc.json"
    cloc_file.write_text(json.dumps(cloc_data))
    
    result = runner.invoke(app, ["ingest", str(cloc_file), "--repo-name", "cloc-repo", "--tool", "cloc"])
    assert result.exit_code == 0
    assert "Ingested metrics" in result.stdout

def test_cli_ingest_no_findings(temp_db_dir, tmp_path):
    empty_data = {"results": []}
    empty_file = tmp_path / "empty.json"
    empty_file.write_text(json.dumps(empty_data))
    
    result = runner.invoke(app, ["ingest", str(empty_file), "--repo-name", "r", "--tool", "semgrep"])
    assert result.exit_code == 1
    assert "No findings found" in result.stdout

def test_cli_ingest_invalid_path(temp_db_dir):
    result = runner.invoke(app, ["ingest", "/non/existent/path", "--repo-name", "r", "--tool", "t"])
    assert result.exit_code == 1
    assert "Invalid input path" in result.stdout
