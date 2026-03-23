#!/usr/bin/env python3
import os
import typer
import sqlite3

from typing import Optional

from signal_engine.ingest import (
    ingest_findings,
    ingest_metrics,
    normalize_tool_fields,
    fetch_findings,
    get_repo_db_path,
)
from signal_engine.cluster import top_rules, top_files, cluster_findings
from signal_engine.export import export_csv
from signal_engine.analytics import get_vulnerability_density
from signal_engine.migrations import (
    apply_migrations,
    iter_migrations,
    missing_migrations,
)
from signal_engine import __version__


app = typer.Typer(help="Signal Engine CLI")


def _load_json(input_path: str):
    import os, json

    if os.path.isdir(input_path):
        # Directory: return list of dicts from all JSON files
        data_list = []
        for filename in os.listdir(input_path):
            if filename.endswith(".json"):
                with open(os.path.join(input_path, filename)) as f:
                    data_list.append(json.load(f))
        return data_list
    elif os.path.isfile(input_path) and input_path.endswith(".json"):
        # Single JSON file: return it as a list with one element
        with open(input_path) as f:
            return [json.load(f)]
    return []


@app.command()
def ingest(
    input_path: str = typer.Argument(
        ..., help="JSON file or directory with static analysis outputs"
    ),
    repo_name: str = typer.Option(..., help="Repository name for DB storage"),
    tool: str = typer.Option(..., help="Name of the tool that generated the findings"),
):
    """
    Ingest JSON findings into the SQLite DB for a given repository.
    Supports a single file or a directory of JSON files.
    """
    data_list = _load_json(input_path)
    if not data_list:
        typer.echo(
            "Invalid input path or no JSON files found. Must be a JSON file or directory containing JSON files."
        )
        raise typer.Exit(code=1)

    if tool == "cloc":
        # cloc usually produces one JSON per run, we take the first one found or merge them
        # For simplicity, if it's a dir we ingest all, but cloc structure is a dict
        for cloc_data in data_list:
            ingest_metrics(cloc_data, repo_name)
        typer.echo(f"Ingested metrics for repo '{repo_name}'.")
        return

    findings = []
    for data in data_list:
        for r in data.get("results", []):
            normalized = normalize_tool_fields(r, tool)
            findings.append(normalized)

    if not findings:
        typer.echo("No findings found in the given path.")
        raise typer.Exit(code=1)

    ingest_findings(findings, repo_name)
    typer.echo(f"Ingested {len(findings)} findings into DB for repo '{repo_name}'.")


@app.command()
def analyze(
    repo_name: str = typer.Option(..., help="Repository name to analyze"),
    file: str = typer.Option(None, help="Optional JSON file to filter"),
    tool: str = typer.Option(None, help="Optional tool to filter"),
    output: str = typer.Option(None, "-o", "--output", help="Output CSV file"),
):
    """
    Analyze findings previously ingested into the SQLite DB for a repository.
    """

    # Fetch findings from repository DB
    findings = fetch_findings(repo_name, file=file, tool=tool)

    if not findings:
        typer.echo("No findings found in DB for the given parameters.")
        raise typer.Exit(code=1)

    # Normalize, cluster, and extract top rules/files
    clusters = cluster_findings(findings)
    top_r = top_rules(clusters)
    top_f = top_files(clusters)

    if output:
        # Export results to CSV
        export_csv(top_r, top_f, clusters, output)
        typer.echo(f"Analysis completed! Results saved to {output}")
    else:
        # Print a simple table to stdout
        typer.echo("Top Rules:")
        for rule, count in top_r:
            typer.echo(f"  {rule}: {count}")
        typer.echo("\nTop Files:")
        for fpath, count in top_f:
            typer.echo(f"  {fpath}: {count}")


@app.command()
def migrate(
    repo_name: str = typer.Option(..., help="Repository name for DB migrate"),
    check: bool = typer.Option(
        False, "--check", help="Check if DB needs to be migrated"
    ),
):
    db_path = get_repo_db_path(repo_name)
    all_versions = {m.stem for m in iter_migrations()}
    missing = missing_migrations(db_path, all_versions)

    if check:
        if missing:
            typer.secho(
                f"✗ {db_path} → missing {len(missing)} migrations", fg=typer.colors.RED
            )
            for v in sorted(missing):
                typer.echo(f"   - {v}")
        else:
            typer.secho(f"✓ {db_path} → up to date", fg=typer.colors.GREEN)
        return

    if missing:
        typer.echo(f"Migrating {db_path} …")
        apply_migrations(db_path)
        typer.secho("✓ Up to date", fg=typer.colors.GREEN)
    else:
        typer.secho(f"✓ {db_path} → already up to date", fg=typer.colors.GREEN)


# -----------------------------
# STATS: print summary in console
# -----------------------------
@app.command()
def stats(
    input_dir: str = typer.Argument(
        ..., help="Directory with static analysis JSON outputs"
    ),
    tool: str = typer.Option(..., help="Tool name for normalization"),
    top_n: int = typer.Option(
        10, "-n", "--top", help="Number of top rules/files to show"
    ),
):
    """
    Display top rules, top files, and total number of findings.
    """
    data_list = _load_json(input_dir)
    findings = []
    for data in data_list:
        for r in data.get("results", []):
            findings.append(normalize_tool_fields(r, tool))

    clusters = cluster_findings(findings)
    typer.echo(f"Total findings: {len(findings)}\n")

    typer.echo("Top Rules:")
    for rule, count in top_rules(clusters, top_n):
        typer.echo(f"  {rule}: {count}")

    typer.echo("\nTop Files:")
    for path, count in top_files(clusters, top_n):
        typer.echo(f"  {path}: {count}")


# -----------------------------
# REPORT: export summary CSV
# -----------------------------
@app.command()
def report(
    input_dir: str = typer.Argument(
        ..., help="Directory with static analysis JSON outputs"
    ),
    tool: str = typer.Option(..., help="Tool name for normalization"),
    output: str = typer.Option(
        "report.csv", "-o", "--output", help="Output report CSV file"
    ),
    top_n: int = typer.Option(
        10, "-n", "--top", help="Number of top rules/files to include"
    ),
):
    """
    Generate a report CSV with top rules, top files, and clusters.
    """
    data_list = _load_json(input_dir)
    findings = []
    for data in data_list:
        for r in data.get("results", []):
            findings.append(normalize_tool_fields(r, tool))

    clusters = cluster_findings(findings)
    top_r = top_rules(clusters, top_n)
    top_f = top_files(clusters, top_n)

    export_csv(top_r, top_f, clusters, output)
    typer.echo(f"Report saved to {output}")


@app.command()
def hotspots(
    repo_name: str = typer.Option(..., help="Repository name to analyze"),
    tool: str = typer.Option(None, help="Optional tool to filter findings"),
):
    """
    Identify language-based hotspots by calculating risk-weighted vulnerability density
    (Risk Score per 1000 Lines of Code).
    """
    density_stats = get_vulnerability_density(repo_name, tool=tool)

    if not density_stats:
        typer.echo("No metrics or findings found for this repository.")
        return

    title = f"Risk Hotspots for '{repo_name}'"
    if tool:
        title += f" (Tool: {tool})"
    typer.echo(f"\n{title}:")
    typer.echo(f"{'Language':<20} | {'Findings':<10} | {'Risk Score':<12} | {'LOC':<8} | {'Risk Density (R/1kLOC)':<22}")
    typer.echo("-" * 85)

    for s in density_stats:
        typer.echo(f"{s['language']:<20} | {s['findings']:<10} | {s['risk_score']:<12.1f} | {s['loc']:<8} | {s['density']:<22.2f}")


@app.command()
def info(
    repo_name: str = typer.Option(..., help="Repository name to inspect"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Show extended info"),
):
    """
    Show information about the repository ingestion:
    - DB path
    - Ingest timestamp
    - Number of findings
    - (verbose) tool versions and top rules
    """
    db_path = get_repo_db_path(repo_name)

    if not os.path.exists(db_path):
        typer.echo(f"No DB found for repository '{repo_name}'.")
        raise typer.Exit(code=1)

    # Connect to DB
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    # Fetch ingest timestamp
    cursor.execute("SELECT value FROM metadata WHERE key = 'created_at'")
    row = cursor.fetchone()
    ingest_time = row[0] if row else "unknown"

    # Count findings
    cursor.execute("SELECT COUNT(*) FROM findings")
    count = cursor.fetchone()[0]

    typer.echo(f"Repository: {repo_name}")
    typer.echo(f"DB path: {db_path}")
    typer.echo(f"Ingest time: {ingest_time}")
    typer.echo(f"Number of findings: {count}")

    if verbose:
        # Tool version
        cursor.execute("SELECT value FROM metadata WHERE key = 'tool_version'")
        row = cursor.fetchone()
        tool_version = row[0] if row else "unknown"
        typer.echo(f"Tool version used for ingest: {tool_version}")

        # Tools present in findings
        cursor.execute("SELECT DISTINCT tool FROM findings")
        tools = [r[0] for r in cursor.fetchall()]
        typer.echo(f"Tools in DB: {', '.join(tools) if tools else 'none'}")

        # Top 5 rules
        cursor.execute("""
            SELECT rule_id, COUNT(*) as cnt 
            FROM findings 
            GROUP BY rule_id 
            ORDER BY cnt DESC 
            LIMIT 5
        """)
        top_rules = cursor.fetchall()
        typer.echo("Top 5 rules:")
        for rule, cnt in top_rules:
            typer.echo(f"  {rule}: {cnt}")

    conn.close()


def version_callback(value: bool):
    if value:
        typer.echo(__version__)
        raise typer.Exit()


@app.callback()
def main(
    version: bool = typer.Option(
        None,
        "--version",
        callback=version_callback,
        is_eager=True,
        help="Show the application version and exit",
    ),
):
    pass


if __name__ == "__main__":
    app()
