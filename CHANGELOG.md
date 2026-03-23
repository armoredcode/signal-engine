# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- New `hotspots` CLI command to identify high-risk areas based on vulnerability density (Risk Score per 1000 LOC).
- Risk-weighted scoring system for findings (Critical: 10.0, High: 5.0, Medium: 3.0, Low: 1.0, Info: 0.1).
- Automatic language detection from file extensions for correlation between findings and LOC metrics.
- New `analytics.py` module for advanced data processing and risk calculation.
- Helper function `_load_json` in CLI to handle both directory and single file inputs consistently.
- Improved `ingest` command to handle `cloc` metrics alongside security tool findings.
- Re-added `ingest_metrics` and `ingest_findings` to CLI with correct data routing.

### Changed
- Refactored `ingest.py` to use `INTEGER PRIMARY KEY AUTOINCREMENT` for the `metrics` table.
- Consolidated normalization logic in `ingest.py`, moving away from fragmented `normalize.py`.
- Updated `stats` and `report` commands to use the new JSON loading and normalization flow.

### Fixed
- Fixed severity mapping for Semgrep findings (nested `extra.severity`).
- Added missing severity mapping for Bandit findings.
- Fixed bug in `ingest_metrics` where undefined variables (`cur`, `cloc_json`) and missing `id` caused failures.
- Fixed `analyze` command to correctly use clustered findings for top rules and files extraction.
- Fixed missing imports in `cli.py` for `ingest_metrics`.

### Removed
- Removed redundant `signal_engine/report.py` and `signal_engine/normalize.py` files to eliminate code duplication.

## [0.2.0] - 2026-02-04

### Added

- `info` CLI command to inspect repository DB:
  - Shows DB path, ingest timestamp, and total findings
  - `--verbose` option shows tools used and top 5 rules
- Metadata fields in DB now include:
  - `created_at` timestamp
  - `tool_version`
  - `db_version`

### Changed

- `analyze` command prints results to stdout by default; CSV export optional via
  `-o/--output`.
- `cluster_findings` no longer performs normalization; expects pre-normalized
  findings.

## [0.1.0] - 2026-01-27

### Added

- MVP features: ingest, normalize, cluster, export
- CLI `signal-cli` con comandi:
  - `run` → full pipeline
  - `stats` → top rules/files + total findings
  - `report` → export CSV
- Support for Semgrep JSON outputs (tool-agnostic design for future tools)
- PyPI packaging with `pyproject.toml` and AGPLv3 license
