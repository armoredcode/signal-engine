# Signal Engine

Signal Engine is a modular tool for aggregating, normalizing, and analyzing the
output of static code analysis tools.  
It is designed to provide insight into top rules, top files, and clusters of
findings across multiple scans.

Signal Engine takes scan outputs, in JSON format, and transforms them into
actionable insights:

- Top Rules – see which rules are triggered most frequently
- Top Files – identify the files with the highest number of findings
- Clusters – group related findings to reveal patterns and correlations

## Currently supported tools

- **semgrep**
- **bandit**
- **SARIF** (Generic support for dr_source, CodeQL, etc.)
- **gitleaks**
- **trivy**
- **ruff**
- **brakeman**
- **gosec**
- **checkov**
- **hadolint**
- **dawnscanner**
- **cloc** (for metrics and risk density calculation)

## Features

- Ingest and parse JSON outputs from supported tools
- Normalize findings into a consistent structure
- Compute top rules and top files
- Group findings into basic clusters
- Export results in CSV format

## Installation

```sh
pip install signal-engine
```

## Usage

### Ingesting results

Ingest findings from static analysis JSON files into the repository database.

#### Ingest multiple JSON files from a directory

```sh
signal-cli ingest --repo-name myrepo --tool semgrep /path/to/json_reports/
```

- --repo-name → name of the repository
- --tool → the tool that generated the findings (semgrep, bandit, etc.)
- positional argument → path to JSON file or directory containing multiple JSON
  files

#### Ingest a single JSON file

```sh
signal-cli ingest --repo-name myrepo --tool semgrep /path/to/json_reports/report.json
```

After ingest, all findings are stored in a SQLite database located in the
standard user data directory, and can be queried with analyze or info.

### Analyzing ingested results

By default, analyze prints results to standard output:

```sh
signal-cli analyze --repo-name myrepo
```

Optional CSV export with -o / --output:

```sh
signal-cli analyze --repo-name myrepo -o analysis.csv
```

### Show Repository Info

Basic info about a repository’s ingestion:

```sh
signal-cli info --repo-name myrepo
```

A possible output can be something like:

```sh
Repository: myrepo
DB path: /home/user/.local/share/signal-engine/<hash>.db
Ingest time: 2026-02-03T14:25:01+00:00
Number of findings: 153
```

Verbose mode with top rules and tools:

```sh
signal-cli info --repo-name myrepo --verbose
```

```sh
Repository: myrepo
DB path: /home/user/.local/share/signal-engine/<hash>.db
Ingest time: 2026-02-03T14:25:01+00:00
Number of findings: 153
Tool version used for ingest: 0.1.2
Tools in DB: semgrep, bandit
Top 5 rules:
  javascript.browser.security.eval-detected.eval-detected: 12
  python.security.audit.use-of-exec: 8
  ...
```

## Database migrations

Signal Engine uses a lightweight migration system to manage database schema
changes over time. Each repository database keeps track of applied migrations
via the `schema_migrations` table.

Migrations are distributed with the package and applied explicitly via the CLI.
This allows existing databases to be upgraded safely when new features introduce
schema changes (e.g. new tables such as `metrics`).

When running migrations, Signal Engine will:

- Detect which migrations are missing for a given repository database
- Apply them in order
- Record their application to avoid reapplying them in the future

This approach ensures backward compatibility with existing databases while
allowing the schema to evolve as new analysis features are introduced.

### Applying database migrations

Signal Engine ships with database migrations to evolve the schema of repository
databases over time (for example, when introducing new tables such as
`metrics`).

To apply migrations to a specific repository database, use the `migrate` command
and pass the repository name:

```sh
signal-cli migrate --repo-name myrepo
```

To check if a migration is needed, you can use the --check flag. Please note
that this don't apply pending migrations.

```sh
signal-cli migrate --repo-name myrepo
```

## Development & Testing

Signal Engine uses `pytest` for automated testing and `pytest-cov` for coverage
analysis.

### Running tests

To run the full test suite with coverage reporting:

```sh
pytest
```

This will run all tests in the `tests/` directory and print a coverage report
to the terminal.

### Project structure

- `signal_engine/cli.py` – CLI implementation using `typer`
- `signal_engine/ingest.py` – Data ingestion and tool normalization
- `signal_engine/cluster.py` – Smart clustering and deduplication logic
- `signal_engine/analytics.py` – Risk density and hotspot calculations
- `signal_engine/migrations/` – SQL migration files for DB schema

## Contributing

We welcome contributions to Signal Engine!

### Adding support for a new tool

To add support for a new static analysis tool:

1.  Open `signal_engine/ingest.py`.
2.  Add a new entry to the `TOOL_FIELD_MAP` dictionary.
3.  Define how to map the tool's JSON fields to the standard Signal Engine fields:
    - `rule_id`
    - `file_path`
    - `message`
    - `severity`
    - `line_number`
4.  If the tool has a nested structure, use a `tuple` to represent the path to
    the field (e.g., `("extra", "severity")`).
5.  Add a test case in `tests/test_ingest.py` to verify the mapping.

## LICENSE

[License: AGPL v3](https://img.shields.io/badge/License-AGPL%20v3-blue.svg) This
project is licensed under the [AGPLv3](LICENSE.md) license.
