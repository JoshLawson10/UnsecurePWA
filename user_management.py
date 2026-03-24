import hmac
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
        con.commit()


def _is_bcrypt_hash(value: str) -> bool:
    return len(value) == 60 and value.startswith(("$2b$", "$2a$", "$2y$"))


def _rehash_password(username: str, plaintext: str) -> None:
    new_hash: str = bcrypt.hashpw(plaintext.encode("utf-8"), bcrypt.gensalt()).decode(
        "utf-8"
    )

    with get_db_connection() as con:
        con.execute(
            "UPDATE users SET password = ? WHERE username = ?",
            (new_hash, username),
        )
        con.commit()


def authenticateUser(username: str, password: str) -> bool:
    with get_db_connection() as con:
        cur = con.execute(
            "SELECT password FROM users WHERE username = ?",
            (username,),
        )
        row = cur.fetchone()

    if row is None:
        bcrypt.checkpw(
            password.encode("utf-8"),
            bcrypt.hashpw(b"dummy", bcrypt.gensalt()),
        )
        return False

    stored: str = row[0]

    if _is_bcrypt_hash(stored):
        return bcrypt.checkpw(password.encode("utf-8"), stored.encode("utf-8"))
    else:
        passwords_match: bool = hmac.compare_digest(stored, password)
        if passwords_match:
            _rehash_password(username, password)
        return passwords_match


def userExists(username: str) -> bool:
    with get_db_connection() as con:
        cur = con.execute(
            "SELECT 1 FROM users WHERE username = ?",
            (username,),
        )
        return cur.fetchone() is not None


def insertFeedback(username: str, feedback: str) -> None:
    """Insert a feedback entry. Raises RuntimeError on database failure."""
    username = username[:_MAX_USERNAME]
    feedback = feedback[:_MAX_FEEDBACK]

    try:
        with get_db_connection() as con:
            con.execute(
                "INSERT INTO feedback (username, feedback) VALUES (?, ?)",
                (username, feedback),
            )
            con.commit()
    except sql.Error as e:
        raise RuntimeError(f"Failed to insert feedback: {e}") from e


def getFeedbackList() -> list[dict]:
    with get_db_connection() as con:
        rows = con.execute(
            "SELECT username, feedback FROM feedback ORDER BY id DESC"
        ).fetchall()
        return [
            {"username": row["username"], "feedback": row["feedback"]} for row in rows
        ]
