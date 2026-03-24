import pytest
from signal_engine.cluster import (
    cluster_findings, 
    top_rules, 
    top_files, 
    smart_cluster,
    flatten_clusters
)

@pytest.fixture
def sample_findings():
    return [
        {"rule_id": "rule1", "file_path": "file1.py", "line_number": 10, "tool": "tool1"},
        {"rule_id": "rule1", "file_path": "file1.py", "line_number": 12, "tool": "tool2"},
        {"rule_id": "rule2", "file_path": "file1.py", "line_number": 50, "tool": "tool1"},
        {"rule_id": "rule1", "file_path": "file2.py", "line_number": 5, "tool": "tool1"},
        {"rule_id": "rule3", "file_path": "file2.py", "line_number": 5, "tool": "tool2"},
    ]

def test_cluster_findings(sample_findings):
    clusters = cluster_findings(sample_findings)
    # Grouped by (rule_id, file_path)
    # (rule1, file1.py) -> 2 findings (lines 10, 12)
    # (rule2, file1.py) -> 1 finding (line 50)
    # (rule1, file2.py) -> 1 finding (line 5)
    # (rule3, file2.py) -> 1 finding (line 5)
    assert len(clusters) == 4
    assert len(clusters[("rule1", "file1.py")]) == 2

def test_top_rules(sample_findings):
    top = top_rules(sample_findings)
    # rule1: 3, rule2: 1, rule3: 1
    assert top[0] == ("rule1", 3)
    assert len(top) == 3

def test_top_files(sample_findings):
    top = top_files(sample_findings)
    # file1.py: 3, file2.py: 2
    assert top[0] == ("file1.py", 3)
    assert top[1] == ("file2.py", 2)

def test_smart_cluster(sample_findings):
    # Threshold 3
    clusters = smart_cluster(sample_findings, line_threshold=3)
    
    # file1.py: lines 10, 12 are within 3 -> 1 cluster
    # file1.py: line 50 -> 1 cluster
    # file2.py: line 5 (rule1), line 5 (rule3) are same line -> 1 cluster
    
    assert len(clusters) == 3
    
    # Check if lines 10 and 12 are together
    found_combined = False
    for (fpath, line, _), group in clusters.items():
        if fpath == "file1.py" and len(group) == 2:
            lines = {f["line_number"] for f in group}
            if 10 in lines and 12 in lines:
                found_combined = True
    assert found_combined

def test_smart_cluster_threshold(sample_findings):
    # Threshold 1 (should NOT group lines 10 and 12)
    clusters = smart_cluster(sample_findings, line_threshold=1)
    
    # file1.py: 10, 12 -> 2 clusters
    # file1.py: 50 -> 1 cluster
    # file2.py: 5, 5 -> 1 cluster
    assert len(clusters) == 4

def test_flatten_clusters(sample_findings):
    clusters = cluster_findings(sample_findings)
    flattened = flatten_clusters(clusters)
    assert len(flattened) == len(sample_findings)
