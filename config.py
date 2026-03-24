import os


class Config:
    SECRET_KEY: str = os.environ.get("SECRET_KEY", str(os.urandom(32)))

    SESSION_COOKIE_HTTPONLY: bool = True
    SESSION_COOKIE_SECURE: bool = True
    SESSION_COOKIE_SAMESITE: str = "Lax"
    SESSION_COOKIE_NAME: str = "session"

    REMEMBER_COOKIE_HTTPONLY: bool = True
    REMEMBER_COOKIE_SECURE: bool = True

    PERMANENT_SESSION_LIFETIME: int = 1800

    MAX_CONTENT_LENGTH: int = 16 * 1024 * 1024  # 16 MB
