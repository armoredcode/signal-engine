-- Initial schema for signal-engine

CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    repo TEXT NOT NULL,
    tool TEXT NOT NULL,
    file_path TEXT NOT NULL,
    line_number INTEGER NOT NULL,
    rule_id TEXT NOT NULL,
    message TEXT NOT NULL,
    message_hash TEXT NOT NULL,
    severity TEXT,
    ingest_time DATETIME NOT NULL,
    UNIQUE(repo, tool, file_path, line_number, rule_id, message_hash)
);

CREATE TABLE IF NOT EXISTS metadata (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_findings_repo ON findings(repo);
CREATE INDEX IF NOT EXISTS idx_findings_tool ON findings(tool);
CREATE INDEX IF NOT EXISTS idx_findings_file ON findings(file_path);
