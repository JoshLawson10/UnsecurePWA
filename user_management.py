import sqlite3 as sql

import bcrypt

DB_PATH = "database_files/database.db"

_MAX_USERNAME: int = 50
_MAX_PASSWORD: int = 128
_MAX_DOB: int = 10
_MAX_FEEDBACK: int = 500


def get_db_connection() -> sql.Connection:
    con = sql.connect(DB_PATH)
    con.row_factory = sql.Row
    return con


def insertUser(username: str, password: str, DoB: str) -> None:
    username = username[:_MAX_USERNAME]
    DoB = DoB[:_MAX_DOB]

    hashed_password: bytes = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())
    hashed_password_str: str = hashed_password.decode("utf-8")

    with get_db_connection() as con:
        con.execute(
            "INSERT INTO users (username, password, DoB) VALUES (?, ?, ?)",
            (username, hashed_password_str, DoB),
        )


def authenticateUser(username: str, password: str) -> bool:
    with get_db_connection() as con:
        cur = con.execute(
            "SELECT password FROM users WHERE username = ?",
            (username,),
        )
        row = cur.fetchone()

        if row is None:
            return False

        stored_hash: str = row[0]

        return bcrypt.checkpw(
            password.encode("utf-8"),
            stored_hash.encode("utf-8"),
        )


def userExists(username: str) -> bool:
    with get_db_connection() as con:
        cur = con.execute(
            "SELECT 1 FROM users WHERE username = ?",
            (username,),
        )
        return cur.fetchone() is not None


def insertFeedback(feedback: str) -> None:
    feedback = feedback[:_MAX_FEEDBACK]

    with get_db_connection() as con:
        con.execute(
            "INSERT INTO feedback (feedback) VALUES (?)",
            (feedback,),
        )


def getFeedbackList() -> list[str]:
    with get_db_connection() as con:
        data = con.execute("SELECT feedback FROM feedback").fetchall()
        return [row[0] for row in data]
