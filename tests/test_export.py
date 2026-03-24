import os
import csv
from signal_engine.export import export_csv

def test_export_csv(tmp_path):
    output_file = tmp_path / "test.csv"
    
    top_rules = [("rule1", 5), ("rule2", 3)]
    top_files = [("file1.py", 4), ("file2.py", 4)]
    clusters = {
        ("rule1", "file1.py"): [1, 2, 3],
        ("rule2", "file2.py"): [4, 5]
    }
    
    export_csv(top_rules, top_files, clusters, output_file=str(output_file))
    
    assert os.path.exists(output_file)
    
    with open(output_file, "r") as f:
        reader = csv.reader(f)
        rows = list(reader)
        
    assert rows[0] == ["Type", "Identifier", "Count"]
    assert ["Rule", "rule1", "5"] in rows
    assert ["File", "file1.py", "4"] in rows
    assert ["Cluster", "rule1 | file1.py", "3"] in rows
