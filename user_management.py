"""
user_management.py
------------------
All database interactions for the application.

Security notes
~~~~~~~~~~~~~~
* Every query uses parameterised placeholders (?) — never string interpolation —
  to eliminate SQL injection regardless of input content.
* Passwords are hashed with bcrypt before storage; plaintext is never persisted.
* OTP codes are hashed with SHA-256 before storage so that a database breach
  does not expose valid codes that could be replayed.
* bcrypt.checkpw and hmac.compare_digest perform constant-time comparisons,
  mitigating timing attacks that could reveal information about stored values.
"""

import hashlib
import hmac
import secrets
import sqlite3 as sql
import time

import bcrypt

DB_PATH = "database_files/database.db"

_MAX_USERNAME: int = 50
_MAX_PASSWORD: int = 128
_MAX_DOB: int = 10
_MAX_EMAIL: int = 254  # RFC 5321 maximum email address length
_MAX_FEEDBACK: int = 500

OTP_LENGTH: int = 6  # digits
OTP_EXPIRY_SECONDS: int = 600  # 10 minutes


def get_db_connection() -> sql.Connection:
    con = sql.connect(DB_PATH)
    con.row_factory = sql.Row
    return con


# ---------------------------------------------------------------------------
# User management
# ---------------------------------------------------------------------------


def insertUser(username: str, password: str, DoB: str, email: str) -> None:
    """Hash the password and insert a new user record."""
    username = username[:_MAX_USERNAME]
    DoB = DoB[:_MAX_DOB]
    email = email[:_MAX_EMAIL].lower().strip()

    hashed_password: bytes = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())
    hashed_password_str: str = hashed_password.decode("utf-8")

    with get_db_connection() as con:
        con.execute(
            "INSERT INTO users (username, password, DoB, email) VALUES (?, ?, ?, ?)",
            (username, hashed_password_str, DoB, email),
        )
        con.commit()


def _is_bcrypt_hash(value: str) -> bool:
    """Return True if value is a valid bcrypt hash string."""
    return len(value) == 60 and value.startswith(("$2b$", "$2a$", "$2y$"))


def _rehash_password(username: str, plaintext: str) -> None:
    """Replace a legacy plaintext password with a bcrypt hash."""
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
    """Return True if the credentials are valid, False otherwise.

    Handles bcrypt-hashed passwords (all new accounts) and legacy plaintext
    passwords (accounts created by the original unsecured app).  Performs a
    dummy bcrypt operation when the username is not found to equalise response
    time and prevent timing-based username enumeration.
    """
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
        # Legacy plaintext path — constant-time comparison.
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


def getEmailByUsername(username: str) -> str:
    """Return the registered email address for the given username, or ''."""
    with get_db_connection() as con:
        cur = con.execute(
            "SELECT email FROM users WHERE username = ?",
            (username,),
        )
        row = cur.fetchone()
    return row["email"] if row else ""


# ---------------------------------------------------------------------------
# OTP (2FA) management
# ---------------------------------------------------------------------------


def _hash_code(code: str) -> str:
    """Return a SHA-256 hex digest of the plaintext code.

    OTP codes are hashed before storage so that a database breach does not
    expose valid codes that could be replayed before they expire.
    """
    return hashlib.sha256(code.encode("utf-8")).hexdigest()


def generateOTPCode() -> str:
    """Return a cryptographically random 6-digit string.

    secrets.randbelow is used rather than random.randint because the secrets
    module is designed for security-sensitive token generation and is not
    predictable from observed outputs.
    """
    return str(secrets.randbelow(10**OTP_LENGTH)).zfill(OTP_LENGTH)


def storeOTPCode(username: str, code: str) -> None:
    """Hash the OTP code and persist it with an expiry timestamp.

    Any previous unused codes for this user are invalidated first, so
    only one valid code exists at a time.  This prevents an attacker from
    accumulating valid codes by triggering multiple login attempts.
    """
    # Invalidate any existing unused codes for this user.
    with get_db_connection() as con:
        con.execute(
            "UPDATE otp_codes SET used = 1 WHERE username = ? AND used = 0",
            (username,),
        )
        con.execute(
            "INSERT INTO otp_codes (username, code_hash, expires_at, used) "
            "VALUES (?, ?, ?, 0)",
            (username, _hash_code(code), int(time.time()) + OTP_EXPIRY_SECONDS),
        )
        con.commit()


def verifyOTPCode(username: str, code: str) -> bool:
    """Return True if the code is valid, unexpired, and unused, then mark it used.

    Uses hmac.compare_digest on the hex digests for a constant-time
    comparison, preventing timing attacks from leaking information about
    how close a guessed code is to the correct one.
    """
    with get_db_connection() as con:
        cur = con.execute(
            "SELECT id, code_hash, expires_at FROM otp_codes "
            "WHERE username = ? AND used = 0 "
            "ORDER BY id DESC LIMIT 1",
            (username,),
        )
        row = cur.fetchone()

        if row is None:
            return False

        # Check expiry.
        if int(time.time()) > row["expires_at"]:
            return False

        # Constant-time comparison of the hashed values.
        submitted_hash = _hash_code(code)
        if not hmac.compare_digest(submitted_hash, row["code_hash"]):
            return False

        # Mark the code as used so it cannot be replayed.
        con.execute(
            "UPDATE otp_codes SET used = 1 WHERE id = ?",
            (row["id"],),
        )
        con.commit()

    return True


# ---------------------------------------------------------------------------
# Feedback
# ---------------------------------------------------------------------------


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
