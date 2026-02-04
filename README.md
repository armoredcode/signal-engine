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

- semgrep

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

## LICENSE

[License: AGPL v3](https://img.shields.io/badge/License-AGPL%20v3-blue.svg) This
project is licensed under the [AGPLv3](LICENSE.md) license.
