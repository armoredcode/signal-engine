"""
This module operates ONLY on normalized findings.
Do NOT import ingest or tool-specific logic here.
"""

from collections import Counter, defaultdict


def flatten_clusters(clusters):
    """
    Flatten clusters dict into a list of findings.
    Useful for top_rules/top_files functions.
    """
    return [f for group in clusters.values() for f in group]


def top_rules(findings_or_clusters, top_n=10):
    """
    Count the most common rules.
    Accepts either:
      - a list of normalized findings
      - a clusters dict returned by cluster_findings
    """
    # if input is a dict (clusters), flatten it
    if isinstance(findings_or_clusters, dict):
        findings = flatten_clusters(findings_or_clusters)
    else:
        findings = findings_or_clusters

    rules_count = Counter(f["rule_id"] for f in findings)
    return rules_count.most_common(top_n)


def top_files(findings_or_clusters, top_n=10):
    """
    Count the most common files.
    Accepts either:
      - a list of normalized findings
      - a clusters dict returned by cluster_findings
    """
    if isinstance(findings_or_clusters, dict):
        findings = flatten_clusters(findings_or_clusters)
    else:
        findings = findings_or_clusters

    files_count = Counter(f["file_path"] for f in findings)
    return files_count.most_common(top_n)


def cluster_findings(findings):
    """
    Cluster already-normalized findings by (rule_id, file_path).
    """
    clusters = defaultdict(list)

    for f in findings:
        clusters[(f["rule_id"], f["file_path"])].append(f)

    return clusters
