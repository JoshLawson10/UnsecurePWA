# -----------
# This is a helper file to migrate the database schema after adding the "username" column to the feedback table.
# -----------

import sqlite3

DB_PATH = "database_files/database.db"


def migrate():
    with sqlite3.connect(DB_PATH) as con:
        cur = con.cursor()

        cur.execute("PRAGMA table_info(feedback)")
        columns = [row[1] for row in cur.fetchall()]

        if "username" not in columns:
            print("Adding 'username' column to feedback table...")
            cur.execute(
                "ALTER TABLE feedback ADD COLUMN username TEXT NOT NULL DEFAULT 'unknown'"
            )
            print("Done.")
        else:
            print("'username' column already present — no migration needed.")

        con.commit()
    print("Migration complete.")


if __name__ == "__main__":
    migrate()
