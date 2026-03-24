# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **Comprehensive Test Suite**: Implemented a full suite of automated tests using `pytest`, reaching **91% total code coverage**.
  - New tests for `ingest`, `cluster`, `analytics`, `export`, `migrations`, and the `CLI`.
  - Added `pytest-cov` for coverage reporting.
  - Configured `pytest` in `pyproject.toml` with default options.
  - Integrated `typer.testing.CliRunner` for end-to-end CLI validation.
  - Added a shared `conftest.py` with fixtures for isolated database testing.
- **Initial Schema Migration**: Added `20260101_01_initial_schema.sql` to manage the core database structure via the migration system.

### Changed

- **Database Refactoring**: Centralized database schema management. `init_db` now utilizes the migration system as the single source of truth instead of manual table creation.
- **Migration Flexibility**: Added a `quiet` parameter to `apply_migrations` to allow silent schema updates when called programmatically (e.g., during ingestion).
- **Resource Management**: Refactored all SQLite database interactions to use `try...finally` blocks, ensuring connections are explicitly closed. This resolved 50+ `ResourceWarning` issues and improved overall stability.
- **Documentation Overhaul**: Updated `README.md` with:
  - Comprehensive list of all 12+ supported tools.
  - New "Development & Testing" section with `pytest` instructions.
  - New "Contributing" guide specifically explaining how to add support for new static analysis tools.

### Fixed

- **Robustness in Analytics**: Fixed a potential crash in `get_vulnerability_density` when a repository database or its tables were missing or uninitialized.

## [0.3.0] - 2026-03-23

### Added

- **UI/UX Overhaul**: Integrated the `rich` library for professional terminal
  output.
  - Color-coded **Hotspots** table based on risk density (Red for high risk,
    Green for low risk).
  - Modern **Info** panel for repository metadata and statistics.
  - Clean, simplified tables for **Deduplication** and **Analysis** results.
  - Semantic coloring for severity levels and file paths across all commands.
- Native support for **SARIF (Static Analysis Results Interchange Format)**,
  enabling integration with **dr_source**, GitHub CodeQL, and other
  standard-compliant tools.
- Expanded tool support: Added mappings for **Gitleaks**, **Trivy**, **Ruff**,
  **Brakeman**, **Gosec**, **Checkov**, **Hadolint**, and **Dawnscanner**.
- New `dedup` CLI command for intelligent multi-tool deduplication based on line
  proximity.
- New `smart_cluster` algorithm in `cluster.py` to group findings within a
  specified line threshold (default 3 lines).
- New `hotspots` CLI command to identify high-risk areas based on vulnerability
  density (Risk Score per 1000 LOC).
- Risk-weighted scoring system for findings (Critical: 10.0, High: 5.0, Medium:
  3.0, Low: 1.0, Info: 0.1).
- Automatic language detection from file extensions for correlation between
  findings and LOC metrics.
- New `analytics.py` module for advanced data processing and risk calculation.
- Helper function `_load_json` in CLI to handle both directory and single file
  inputs consistently.
- Improved `ingest` command to handle `cloc` metrics alongside security tool
  findings.
- Re-added `ingest_metrics` and `ingest_findings` to CLI with correct data
  routing.

### Changed

- Updated `cli.py` to handle various JSON structures (lists, `Results` key,
  `runs[]` SARIF structure).
- Improved `_get_nested` in `ingest.py` to support deep navigation in both lists
  (via index) and dictionaries.
- Refactored `cluster.py` to support multi-tool clustering and proximity-based
  grouping.
- Refactored `ingest.py` to use `INTEGER PRIMARY KEY AUTOINCREMENT` for the
  `metrics` table.
- Consolidated normalization logic in `ingest.py`, moving away from fragmented
  `normalize.py`.
- Updated `stats` and `report` commands to use the new JSON loading and
  normalization flow.

### Fixed

- Fixed severity mapping for Semgrep findings (nested `extra.severity`).
- Added missing severity mapping for Bandit findings.
- Fixed bug in `ingest_metrics` where undefined variables (`cur`, `cloc_json`)
  and missing `id` caused failures.
- Fixed `analyze` command to correctly use clustered findings for top rules and
  files extraction.
- Fixed missing imports in `cli.py` for `ingest_metrics`.

### Removed

- Removed redundant `signal_engine/report.py` and `signal_engine/normalize.py`
  files to eliminate code duplication.

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
