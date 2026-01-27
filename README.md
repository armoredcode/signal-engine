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

```sh
signal-cli path/to/scan/outputs
```

## LICENSE

[License: AGPL v3](https://img.shields.io/badge/License-AGPL%20v3-blue.svg) This
project is licensed under the [AGPLv3](LICENSE.md) license.
