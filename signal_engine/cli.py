#!/usr/bin/env python3
import typer

from typing import Optional

from signal_engine.ingest import ingest_json, ingest_to_db
from signal_engine.normalize import normalize_findings
from signal_engine.cluster import top_rules, top_files, cluster_findings
from signal_engine.export import export_csv
from signal_engine import __version__


app = typer.Typer(help="Signal Engine CLI")


@app.command()
def ingest(
    file: Optional[str] = typer.Option(None, help="Single JSON file to ingest"),
    dir: Optional[str] = typer.Option(None, help="Directory with JSON files to ingest"),
):
    """
    Ingest findings into SQLite DB with deduplication and timestamp.
    """
    inserted, updated = ingest_to_db(input_dir=dir, file=file)
    typer.echo(f"Ingest completed: inserted={inserted}, updated={updated}")


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
