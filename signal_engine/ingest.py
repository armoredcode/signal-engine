import os
import json
import sqlite3
import hashlib
from datetime import datetime, timezone
from appdirs import user_data_dir
from typing import Optional

APP_NAME = "signal-engine"
DB_FILENAME = "signal_engine.db"
DATA_DIR = user_data_dir(APP_NAME)
os.makedirs(DATA_DIR, exist_ok=True)
DB_PATH = os.path.join(DATA_DIR, DB_FILENAME)


# --- Utility ---
def hash_message(message: str) -> str:
    return hashlib.sha256(message.encode("utf-8")).hexdigest()


def ingest_json(input_dir):
    findings = []
    for filename in os.listdir(input_dir):
        if filename.endswith(".json"):
            with open(os.path.join(input_dir, filename)) as f:
                data = json.load(f)
                findings.extend(data.get("results", []))
    return findings


def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
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
    conn.commit()
    conn.close()


def ingest_to_db(input_dir: Optional[str] = None, file: Optional[str] = None):
    """
    Ingest findings from a directory or a single file into SQLite DB
    with deduplication and timestamp.
    """
    if not input_dir and not file:
        raise ValueError("Specify either input_dir or file")

    init_db()
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    files = []
    if input_dir:
        for f in os.listdir(input_dir):
            if f.endswith(".json"):
                files.append(os.path.join(input_dir, f))
    elif file:
        files = [file]

    inserted = 0
    updated = 0

    for fpath in files:
        with open(fpath, "r", encoding="utf-8") as f:
            data = json.load(f)
            for finding in data.get("results", []):
                repo = finding.get("repo", "unknown")
                tool = finding.get("tool", "unknown")
                file_path_f = finding.get("file_path", "")
                line_number = finding.get("line_number", 0)
                rule_id = finding.get("rule_id", "")
                message = finding.get("message", "")
                severity = finding.get("severity", None)
                msg_hash = hash_message(message)
                ingest_time = datetime.now(timezone.utc).isoformat()

                try:
                    cursor.execute(
                        """
                        INSERT INTO findings
                        (repo, tool, file_path, line_number, rule_id, message, message_hash, severity, ingest_time)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                        (
                            repo,
                            tool,
                            file_path_f,
                            line_number,
                            rule_id,
                            message,
                            msg_hash,
                            severity,
                            ingest_time,
                        ),
                    )
                    inserted += 1
                except sqlite3.IntegrityError:
                    cursor.execute(
                        """
                        UPDATE findings
                        SET ingest_time = ?, severity = ?
                        WHERE repo = ? AND tool = ? AND file_path = ? 
                          AND line_number = ? AND rule_id = ? AND message_hash = ?
                    """,
                        (
                            ingest_time,
                            severity,
                            repo,
                            tool,
                            file_path_f,
                            line_number,
                            rule_id,
                            msg_hash,
                        ),
                    )
                    updated += 1

    conn.commit()
    conn.close()
    return inserted, updated
