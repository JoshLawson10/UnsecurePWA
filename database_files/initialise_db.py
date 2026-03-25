import os
import sqlite3 as sql

DB_PATH = "database_files/database.db"


def _get_column_names(con: sql.Connection, table: str) -> set:
    cur = con.execute(f"PRAGMA table_info({table})")
    return {row[1] for row in cur.fetchall()}


def initialise_db() -> None:
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)

    with sql.connect(DB_PATH) as con:
        con.executescript("""
            CREATE TABLE IF NOT EXISTS users (
                id       INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT    NOT NULL UNIQUE,
                password TEXT    NOT NULL,
                DoB      TEXT,
                email    TEXT    NOT NULL DEFAULT ''
            );

            CREATE TABLE IF NOT EXISTS feedback (
                id       INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT    NOT NULL,
                feedback TEXT    NOT NULL
            );

            CREATE TABLE IF NOT EXISTS otp_codes (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                username   TEXT    NOT NULL,
                code_hash  TEXT    NOT NULL,
                expires_at INTEGER NOT NULL,
                used       INTEGER NOT NULL DEFAULT 0
            );
        """)

        feedback_cols = _get_column_names(con, "feedback")
        if "username" not in feedback_cols:
            con.execute(
                "ALTER TABLE feedback ADD COLUMN username TEXT NOT NULL DEFAULT 'unknown'"
            )
            con.commit()

        users_cols = _get_column_names(con, "users")
        if "email" not in users_cols:
            con.execute("ALTER TABLE users ADD COLUMN email TEXT NOT NULL DEFAULT ''")
            con.commit()
