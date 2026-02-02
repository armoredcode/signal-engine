import os
import sqlite3
import hashlib
from datetime import datetime, timezone
from typing import List, Optional
from appdirs import user_data_dir
from signal_engine import __version__  # tool version

TOOL_FIELD_MAP = {
    "semgrep": {
        "file_path": "path",
        "line_number": "start.line",
        "rule_id": "check_id",
        "message": "extra.message",
    },
    "bandit": {
        "file_path": "filename",
        "line_number": "line_number",
        "rule_id": "test_id",
        "message": "issue_text",
    },
    # tools specific mappings go there...
}


def normalize_tool_fields(finding: dict, tool: str) -> dict:
    """Normalize a finding dict according to tool-specific mapping."""
    mapping = TOOL_FIELD_MAP.get(tool, {})
    normalized = {}

    # file_path
    path_key = mapping.get("file_path")
    normalized["file_path"] = (
        finding.get(path_key, "unknown_file") if path_key else "unknown_file"
    )

    # line_number
    line_key = mapping.get("line_number")
    # support nested keys like "start.line"
    if line_key:
        keys = line_key.split(".")
        value = finding
        for k in keys:
            value = value.get(k, None)
            if value is None:
                break
        normalized["line_number"] = value if value is not None else -1
    else:
        normalized["line_number"] = -1

    # rule_id
    rule_key = mapping.get("rule_id")
    normalized["rule_id"] = (
        finding.get(rule_key, "unknown_rule") if rule_key else "unknown_rule"
    )

    # message
    msg_key = mapping.get("message")
    normalized["message"] = finding.get(msg_key, "") if msg_key else ""

    # tool
    normalized["tool"] = tool

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
