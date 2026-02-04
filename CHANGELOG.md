# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

### Changed

### Removed

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
