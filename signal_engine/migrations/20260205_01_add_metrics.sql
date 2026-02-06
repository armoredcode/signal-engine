-- metrics table
CREATE TABLE IF NOT EXISTS metrics (
    id            TEXT PRIMARY KEY,
    tool          TEXT NOT NULL,
    run_id        TEXT,
    language      TEXT,
    metric_type   TEXT NOT NULL,
    value         REAL NOT NULL,
    created_at    TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    extra         TEXT
);

CREATE INDEX IF NOT EXISTS idx_metrics_tool ON metrics(tool);
CREATE INDEX IF NOT EXISTS idx_metrics_run_id ON metrics(run_id);
CREATE INDEX IF NOT EXISTS idx_metrics_language ON metrics(language);
CREATE INDEX IF NOT EXISTS idx_metrics_type ON metrics(metric_type);
