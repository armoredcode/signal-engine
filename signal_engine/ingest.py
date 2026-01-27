import os
import json


def ingest_json(input_dir):
    findings = []
    for filename in os.listdir(input_dir):
        if filename.endswith(".json"):
            with open(os.path.join(input_dir, filename)) as f:
                data = json.load(f)
                findings.extend(data.get("results", []))
    return findings
