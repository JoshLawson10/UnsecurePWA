import sqlite3 as sql

DB_PATH = "database_files/database.db"


def get_db_connection():
    return sql.connect(DB_PATH)


def insertUser(username: str, password: str, DoB: str) -> None:
    hashed_password = password

    with get_db_connection() as con:
        con.execute(
            "INSERT INTO users (username, password, DoB) VALUES (?, ?, ?)",
            (username, hashed_password, DoB),
        )


def authenticateUser(username: str, password: str) -> bool:
    with get_db_connection() as con:
        cur = con.execute("SELECT password FROM users WHERE username = ?", (username,))
        row = cur.fetchone()

        if row is None:
            return False

        stored_hash = row[0]

        return stored_hash == password


def insertFeedback(feedback):
    with get_db_connection() as con:
        con.execute("INSERT INTO feedback (feedback) VALUES (?)", (feedback,))


def getFeedbackList() -> list[str]:
    with get_db_connection() as con:
        data = con.execute("SELECT feedback FROM feedback").fetchall()
        feedback_list = [row[0] for row in data]
        return feedback_list
