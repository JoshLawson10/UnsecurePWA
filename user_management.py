import sqlite3 as sql
import bcrypt

DB_PATH = "database_files/database.db"


def get_db_connection() -> sql.Connection:
    return sql.connect(DB_PATH)


def insertUser(username: str, password: str, DoB: str) -> None:
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


def insertFeedback(feedback: str) -> None:
    with get_db_connection() as con:
        con.execute(
            "INSERT INTO feedback (feedback) VALUES (?)",
            (feedback,),
        )


def getFeedbackList() -> list[str]:
    with get_db_connection() as con:
        data = con.execute("SELECT feedback FROM feedback").fetchall()
        return [row[0] for row in data]
