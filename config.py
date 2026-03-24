import os


class Config:
    SECRET_KEY: str = os.environ.get("SECRET_KEY", str(os.urandom(32)))

    SESSION_COOKIE_HTTPONLY: bool = True
    SESSION_COOKIE_SECURE: bool = True
    SESSION_COOKIE_SAMESITE: str = "Lax"

    REMEMBER_COOKIE_HTTPONLY: bool = True
    REMEMBER_COOKIE_SECURE: bool = True

    PERMANENT_SESSION_LIFETIME: int = 1800
