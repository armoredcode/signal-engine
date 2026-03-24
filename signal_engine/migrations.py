import sqlite3
from importlib import resources
from pathlib import Path

MIGRATIONS_DIR = Path("migrations")


def iter_migrations():
    migrations_dir = resources.files("signal_engine").joinpath("migrations")
    for m in sorted(migrations_dir.iterdir()):
        if m.suffix == ".sql":
            yield m


def missing_migrations(db_path, all_versions):
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()

    try:
        applied = {
            row[0] for row in cur.execute("SELECT version FROM schema_migrations")
        }
    except sqlite3.OperationalError:
        # La tabella schema_migrations non esiste → tutte le migrazioni sono mancanti
        return all_versions

    return all_versions - applied


def apply_migrations(db_path, quiet=False):
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()

    cur.execute("""
        CREATE TABLE IF NOT EXISTS schema_migrations (
            version TEXT PRIMARY KEY,
            applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.commit()

    try:
        applied = {
            row[0] for row in cur.execute("SELECT version FROM schema_migrations")
        }
    except sqlite3.OperationalError:
        applied = set()

    for m in iter_migrations():
        version = m.stem
        if version in applied:
            continue

        try:
            sql = m.read_text()
            cur.executescript(sql)
        except sqlite3.Error as e:
            conn.rollback()
            raise RuntimeError(f"Errore applicando migrazione {version}: {e}") from e
        cur.execute("INSERT INTO schema_migrations (version) VALUES (?)", (version,))

        conn.commit()
        applied.add(version)

        if not quiet:
            print(f"Applied migration {version}")

    conn.close()
