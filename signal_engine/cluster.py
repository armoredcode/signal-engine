"""
This module operates ONLY on normalized findings.
Do NOT import ingest or tool-specific logic here.
"""

from collections import Counter, defaultdict


def flatten_clusters(clusters):
    """
    Flatten clusters dict into a list of findings.
    """
    return [f for group in clusters.values() for f in group]


def top_rules(findings_or_clusters, top_n=10):
    """
    Count the most common rules.
    """
    if isinstance(findings_or_clusters, dict):
        findings = flatten_clusters(findings_or_clusters)
    else:
        findings = findings_or_clusters

    rules_count = Counter(f["rule_id"] for f in findings)
    return rules_count.most_common(top_n)


def top_files(findings_or_clusters, top_n=10):
    """
    Count the most common files.
    """
    if isinstance(findings_or_clusters, dict):
        findings = flatten_clusters(findings_or_clusters)
    else:
        findings = findings_or_clusters

    files_count = Counter(f["file_path"] for f in findings)
    return files_count.most_common(top_n)


def cluster_findings(findings):
    """
    Simple cluster by (rule_id, file_path).
    """
    clusters = defaultdict(list)
    for f in findings:
        clusters[(f["rule_id"], f["file_path"])].append(f)
    return clusters


def smart_cluster(findings, line_threshold=3):
    """
    Intelligent clustering (De-duplication):
    Groups findings in the same file that are within 'line_threshold' lines of each other,
    even if they come from different tools or have different rule_ids.
    """
    if not findings:
        return {}

    # 1. Group by file first
    by_file = defaultdict(list)
    for f in findings:
        by_file[f["file_path"]].append(f)

    smart_clusters = {}
    cluster_id_counter = 0

    for file_path, file_findings in by_file.items():
        # 2. Sort findings in this file by line number
        file_findings.sort(key=lambda x: x["line_number"])

        if not file_findings:
            continue

        current_cluster = [file_findings[0]]
        
        for i in range(1, len(file_findings)):
            prev = file_findings[i-1]
            curr = file_findings[i]

            # 3. If within threshold, add to current cluster
            if curr["line_number"] - prev["line_number"] <= line_threshold:
                current_cluster.append(curr)
            else:
                # 4. Close current cluster and start a new one
                cluster_key = (file_path, current_cluster[0]["line_number"], cluster_id_counter)
                smart_clusters[cluster_key] = current_cluster
                cluster_id_counter += 1
                current_cluster = [curr]
        
        # Add the last cluster for this file
        cluster_key = (file_path, current_cluster[0]["line_number"], cluster_id_counter)
        smart_clusters[cluster_key] = current_cluster
        cluster_id_counter += 1

    return smart_clusters
