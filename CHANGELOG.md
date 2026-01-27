# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

### Changed

### Removed

## [0.1.0] - 2026-01-27

### Added

- MVP features: ingest, normalize, cluster, export
- CLI `signal-cli` con comandi:
  - `run` → full pipeline
  - `stats` → top rules/files + total findings
  - `report` → export CSV
- Support for Semgrep JSON outputs (tool-agnostic design for future tools)
- PyPI packaging with `pyproject.toml` and AGPLv3 license
