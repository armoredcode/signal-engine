#!/usr/bin/env python3
import os
import typer
import sqlite3
from typing import Optional

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich import box

console = Console()

from signal_engine.ingest import (
    ingest_findings,
    ingest_metrics,
    normalize_tool_fields,
    fetch_findings,
    get_repo_db_path,
)
from signal_engine.cluster import top_rules, top_files, cluster_findings, smart_cluster
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
        # Determine findings list based on tool structure
        raw_results = []
        if isinstance(data, list):
            raw_results = data
        elif isinstance(data, dict):
            # Check for standard results keys
            raw_results = data.get("results") or data.get("Results") or []
            
            # SARIF: findings are in runs[].results
            if not raw_results and "runs" in data and data["runs"]:
                raw_results = data["runs"][0].get("results", [])

        for r in raw_results:
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
        console.print("[yellow]No metrics or findings found for this repository.[/yellow]")
        return

    title = f"Risk Hotspots for '{repo_name}'"
    if tool:
        title += f" (Tool: {tool})"
    
    table = Table(title=title, box=box.ROUNDED)
    table.add_column("Language", style="cyan", no_wrap=True)
    table.add_column("Findings", justify="right")
    table.add_column("Risk Score", justify="right")
    table.add_column("LOC", justify="right", style="blue")
    table.add_column("Risk Density (R/1kLOC)", justify="right")

    for s in density_stats:
        density_style = "white"
        if s["density"] >= 10.0:
            density_style = "bold red"
        elif s["density"] >= 5.0:
            density_style = "yellow"
        elif s["density"] > 0:
            density_style = "green"

        table.add_row(
            s["language"],
            str(s["findings"]),
            f"{s['risk_score']:.1f}",
            str(s["loc"]),
            Text(f"{s['density']:.2f}", style=density_style)
        )

    console.print(table)


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
        console.print(f"[bold red]No DB found for repository '{repo_name}'.[/bold red]")
        raise typer.Exit(code=1)

    # Connect to DB
    conn = sqlite3.connect(db_path)
    try:
        cursor = conn.cursor()

        # Fetch metadata
        cursor.execute("SELECT key, value FROM metadata")
        metadata = dict(cursor.fetchall())
        
        ingest_time = metadata.get("created_at", "unknown")
        db_version = metadata.get("db_version", "unknown")
        tool_version = metadata.get("tool_version", "unknown")

        # Count findings
        cursor.execute("SELECT COUNT(*) FROM findings")
        count = cursor.fetchone()[0]
        
        # Count metrics
        cursor.execute("SELECT COUNT(*) FROM metrics")
        metrics_count = cursor.fetchone()[0]

        info_text = Text()
        info_text.append(f"Repository: ", style="bold cyan")
        info_text.append(f"{repo_name}\n")
        info_text.append(f"DB Path: ", style="bold cyan")
        info_text.append(f"{db_path}\n")
        info_text.append(f"Ingest Time: ", style="bold yellow")
        info_text.append(f"{ingest_time}\n")
        info_text.append(f"Findings: ", style="bold green")
        info_text.append(f"{count}\n")
        info_text.append(f"Metrics: ", style="bold green")
        info_text.append(f"{metrics_count}\n")
        
        if verbose:
            info_text.append(f"DB Version: ", style="dim")
            info_text.append(f"{db_version}\n", style="dim")
            info_text.append(f"Tool Version: ", style="dim")
            info_text.append(f"{tool_version}\n", style="dim")

            # Tools present
            cursor.execute("SELECT DISTINCT tool FROM findings")
            tools = [r[0] for r in cursor.fetchall()]
            if tools:
                info_text.append(f"\nTools in DB: ", style="bold magenta")
                info_text.append(f"{', '.join(tools)}\n")
    finally:
        conn.close()
    
    console.print(Panel(info_text, title=f"[bold]Repo Info: {repo_name}[/bold]", border_style="blue", expand=False))


@app.command()
def dedup(
    repo_name: str = typer.Option(..., help="Repository name to analyze"),
    threshold: int = typer.Option(3, help="Line proximity threshold for deduplication"),
):
    """
    Intelligent deduplication across tools. Groups findings in the same file
    that are within 'threshold' lines of each other.
    """
    findings = fetch_findings(repo_name)
    if not findings:
        console.print("[yellow]No findings found for this repository.[/yellow]")
        return

    clusters = smart_cluster(findings, line_threshold=threshold)
    
    table = Table(title=f"Smart Deduplication: {repo_name} (Threshold: {threshold} lines)", box=box.SIMPLE_HEAD)
    table.add_column("File", style="cyan")
    table.add_column("Line", justify="right")
    table.add_column("Findings", justify="right")
    table.add_column("Tools", style="bold magenta")

    for (file_path, line, _), cluster in clusters.items():
        tools = set(f["tool"] for f in cluster)
        table.add_row(
            file_path,
            str(line),
            str(len(cluster)),
            ", ".join(tools)
        )

    console.print(table)
    console.print(f"\n[bold green]Summary:[/bold green] {len(findings)} raw findings collapsed into {len(clusters)} logical incidents.")


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
