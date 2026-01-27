from collections import Counter, defaultdict


def top_rules(findings, top_n=10):
    rules_count = Counter(f["rule_id"] for f in findings)
    return rules_count.most_common(top_n)


def top_files(findings, top_n=10):
    files_count = Counter(f["path"] for f in findings)
    return files_count.most_common(top_n)


def cluster_findings(findings):
    clusters = defaultdict(list)
    for f in findings:
        key = (f["rule_id"], f["path"])
        clusters[key].append(f)
    return clusters
