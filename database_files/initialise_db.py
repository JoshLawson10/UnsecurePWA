import os
import sqlite3 as sql

DB_PATH = "database_files/database.db"


def initialise_db() -> None:
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)

    with sql.connect(DB_PATH) as con:
        con.executescript("""
            CREATE TABLE IF NOT EXISTS users (
                id       INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT    NOT NULL UNIQUE,
                password TEXT    NOT NULL,
                DoB      TEXT
            );

            CREATE TABLE IF NOT EXISTS feedback (
                id       INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT    NOT NULL,
                feedback TEXT    NOT NULL
            );
        """)
