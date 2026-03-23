import os
import sqlite3
import hashlib
from datetime import datetime, timezone
from typing import List, Optional
from appdirs import user_data_dir
from signal_engine import __version__  # tool version

TOOL_FIELD_MAP = {
    "semgrep": {
        "rule_id": "check_id",
        "file_path": "path",
        "message": ("extra", "message"),
        "severity": ("extra", "severity"),
        "line_number": ("start", "line"),
    },
    "bandit": {
        "file_path": "filename",
        "line_number": "line_number",
        "rule_id": "test_id",
        "message": "issue_text",
        "severity": "issue_severity",
    },
    # tools specific mappings go there...
}


def _get_nested(field, data):
    if isinstance(field, tuple):
        for key in field:
            data = data.get(key, {})
        return data or None
    return data.get(field)


def normalize_tool_fields(finding, tool):
    field_map = TOOL_FIELD_MAP.get(tool)
    if not field_map:
        raise ValueError(f"Unsupported tool: {tool}")

    normalized = {"tool": tool}

    for target, source in field_map.items():
        value = _get_nested(source, finding)
        normalized[target] = value

    if not normalized["rule_id"]:
        raise ValueError("Missing rule_id after normalization (check tool mapping)")

    if normalized.get("line_number") is None:
        raise ValueError(f"Missing line_number after normalization for tool {tool}")

    return normalized


APP_NAME = "signal-engine"
DB_SCHEMA_VERSION = "1"  # increment this if schema changes


def get_repo_db_path(repo_name: str) -> str:
    """Return path to the SQLite DB for a given repository, stored in a central user directory."""
    base_dir = user_data_dir(APP_NAME)
    os.makedirs(base_dir, exist_ok=True)
    safe_name = hashlib.sha1(repo_name.encode()).hexdigest()
    return os.path.join(base_dir, f"{safe_name}.db")


def init_db(db_path: str):
    """Create DB schema if not exists, including metadata table."""
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    # Findings table
    cursor.execute("""
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
    )
    """)
    # metrics table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS metrics (
        id            INTEGER PRIMARY KEY AUTOINCREMENT,
        tool          TEXT NOT NULL,
        run_id        TEXT,
        language      TEXT,
        metric_type   TEXT NOT NULL,
        value         REAL NOT NULL,
        created_at    TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        extra         TEXT)
    """)

    # Metadata table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS metadata (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL
    )
    """)

    # Insert or update metadata
    cursor.execute(
        "INSERT OR REPLACE INTO metadata (key, value) VALUES (?, ?)",
        ("db_version", DB_SCHEMA_VERSION),
    )
    cursor.execute(
        "INSERT OR REPLACE INTO metadata (key, value) VALUES (?, ?)",
        ("tool_version", __version__),
    )
    cursor.execute(
        "INSERT OR REPLACE INTO metadata (key, value) VALUES (?, ?)",
        ("created_at", datetime.now(timezone.utc).isoformat()),
    )

    conn.commit()
    conn.close()


def hash_message(message: str) -> str:
    return hashlib.sha1(message.encode()).hexdigest()


def ingest_metrics(cloc_data: dict, repo_name: str):
    """Insert cloc metrics into the DB."""
    db_path = get_repo_db_path(repo_name)
    init_db(db_path)

    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    for language, stats in cloc_data.items():
        if language in ("header", "SUM"):
            continue

        cursor.execute(
            """
            INSERT INTO metrics (
                tool,
                language,
                metric_type,
                value
            )
            VALUES (?, ?, ?, ?)
            """,
            ("cloc", language, "code_lines", stats.get("code", 0)),
        )

        cursor.execute(
            """
            INSERT INTO metrics (
                tool,
                language,
                metric_type,
                value
            )
            VALUES (?, ?, ?, ?)
            """,
            ("cloc", language, "files", stats.get("nFiles", 0)),
        )

    conn.commit()
    conn.close()


def ingest_findings(findings: List[dict], repo_name: str):
    """Insert findings into the DB with deduplication."""
    db_path = get_repo_db_path(repo_name)
    init_db(db_path)

    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    now = datetime.now(timezone.utc).isoformat()

    for f in findings:
        cursor.execute(
            """
        INSERT OR IGNORE INTO findings (
            repo, tool, file_path, line_number, rule_id, message, message_hash, severity, ingest_time
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
            (
                f.get("repo", repo_name),
                f["tool"],
                f["file_path"],
                f["line_number"],
                f["rule_id"],
                f["message"],
                hash_message(f["message"]),
                f.get("severity"),
                now,
            ),
        )
    conn.commit()
    conn.close()


def fetch_findings(
    repo_name: str, file: Optional[str] = None, tool: Optional[str] = None
):
    """Fetch findings from the DB for a given repo, optionally filtering by file or tool."""
    db_path = get_repo_db_path(repo_name)
    if not os.path.exists(db_path):
        return []

    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    query = "SELECT repo, tool, file_path, line_number, rule_id, message, severity FROM findings"
    params = []
    conditions = []

    if file:
        conditions.append("file_path = ?")
        params.append(file)
    if tool:
        conditions.append("tool = ?")
        params.append(tool)
    if conditions:
        query += " WHERE " + " AND ".join(conditions)

    cursor.execute(query, params)
    rows = cursor.fetchall()
    conn.close()

    return [
        {
            "repo": r[0],
            "tool": r[1],
            "file_path": r[2],
            "line_number": r[3],
            "rule_id": r[4],
            "message": r[5],
            "severity": r[6],
        }
        for r in rows
    ]


def get_metadata(repo_name: str) -> dict:
    """Return metadata for a given repo DB."""
    db_path = get_repo_db_path(repo_name)
    if not os.path.exists(db_path):
        return {}

    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute("SELECT key, value FROM metadata")
    data = dict(cursor.fetchall())
    conn.close()
    return data
