def normalize_findings(findings):
    normalized = []
    for f in findings:
        normalized.append(
            {
                "rule_id": f.get("rule_id"),
                "path": f.get("path"),
                "start_line": f.get("start", {}).get("line")
                if f.get("start")
                else None,
                "message": f.get("extra", {}).get("message")
                if f.get("extra")
                else None,
            }
        )
    return normalized
