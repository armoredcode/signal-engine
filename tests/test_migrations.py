import sqlite3
import pytest
from signal_engine.migrations import apply_migrations, missing_migrations, iter_migrations

def test_iter_migrations():
    migrations = list(iter_migrations())
    assert len(migrations) >= 1
    assert all(m.suffix == ".sql" for m in migrations)

def test_apply_migrations(temp_db_dir):
    db_path = temp_db_dir + "/test_migrate.db"
    
    # 1. Initially, no migrations applied
    all_versions = {m.stem for m in iter_migrations()}
    missing = missing_migrations(db_path, all_versions)
    assert len(missing) == len(all_versions)
    
    # 2. Apply migrations
    apply_migrations(db_path)
    
    # 3. Now, no migrations missing
    missing_after = missing_migrations(db_path, all_versions)
    assert len(missing_after) == 0
    
    # 4. Check if tables from migrations exist (e.g., metrics)
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='metrics'")
    assert cursor.fetchone() is not None
    
    # Check schema_migrations table
    cursor.execute("SELECT version FROM schema_migrations")
    applied = {row[0] for row in cursor.fetchall()}
    assert applied == all_versions
    conn.close()

def test_missing_migrations_table_not_exists(temp_db_dir):
    db_path = temp_db_dir + "/no_table.db"
    all_versions = {"v1", "v2"}
    missing = missing_migrations(db_path, all_versions)
    assert missing == all_versions
