#!/usr/bin/env python3
import typer

from typing import Optional

from signal_engine.ingest import ingest_findings, normalize_tool_fields
from signal_engine.normalize import normalize_findings
from signal_engine.cluster import top_rules, top_files, cluster_findings
from signal_engine.export import export_csv
from signal_engine import __version__


app = typer.Typer(help="Signal Engine CLI")


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
    import os, json

    findings = []

    if os.path.isdir(input_path):
        # Directory: ingest all JSON files
        for filename in os.listdir(input_path):
            if filename.endswith(".json"):
                with open(os.path.join(input_path, filename)) as f:
                    data = json.load(f)
                    for r in data.get("results", []):
                        normalized = normalize_tool_fields(r, tool)
                        findings.append(normalized)
    elif os.path.isfile(input_path) and input_path.endswith(".json"):
        # Single JSON file
        with open(input_path) as f:
            data = json.load(f)
            for r in data.get("results", []):
                normalized = normalize_tool_fields(r, tool)
                findings.append(normalized)
    else:
        typer.echo(
            "Invalid input path. Must be a JSON file or directory containing JSON files."
        )
        raise typer.Exit(code=1)

    if not findings:
        typer.echo("No findings found in the given path.")
        raise typer.Exit(code=1)

    ingest_findings(findings, repo_name)
    typer.echo(f"Ingested {len(findings)} findings into DB for repo '{repo_name}'.")


# -----------------------------
# RUN: full pipeline
# -----------------------------
@app.command()
def analyze(
    input_dir: str = typer.Argument(
        ..., help="Directory with static analysis JSON outputs"
    ),
    output: str = typer.Option("output.csv", "-o", "--output", help="Output CSV file"),
):
    """
    Aggregate, normalize, cluster and export static analysis findings.
    """
    findings = ingest_json(input_dir)
    normalized = normalize_findings(findings)
    top_r = top_rules(normalized)
    top_f = top_files(normalized)
    clusters = cluster_findings(normalized)
    export_csv(top_r, top_f, clusters, output)
    typer.echo(f"Done! Results saved to {output}")


# -----------------------------
# STATS: print summary in console
# -----------------------------
@app.command()
def stats(
    input_dir: str = typer.Argument(
        ..., help="Directory with static analysis JSON outputs"
    ),
    top_n: int = typer.Option(
        10, "-n", "--top", help="Number of top rules/files to show"
    ),
):
    """
    Display top rules, top files, and total number of findings.
    """
    findings = ingest_json(input_dir)
    normalized = normalize_findings(findings)
    typer.echo(f"Total findings: {len(normalized)}\n")

    typer.echo("Top Rules:")
    for rule, count in top_rules(normalized, top_n):
        typer.echo(f"  {rule}: {count}")

    typer.echo("\nTop Files:")
    for path, count in top_files(normalized, top_n):
        typer.echo(f"  {path}: {count}")


# -----------------------------
# REPORT: export summary CSV
# -----------------------------
@app.command()
def report(
    input_dir: str = typer.Argument(
        ..., help="Directory with static analysis JSON outputs"
    ),
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
    findings = ingest_json(input_dir)
    normalized = normalize_findings(findings)
    top_r = top_rules(normalized, top_n)
    top_f = top_files(normalized, top_n)
    clusters = cluster_findings(normalized)
    export_csv(top_r, top_f, clusters, output)
    typer.echo(f"Report saved to {output}")


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
