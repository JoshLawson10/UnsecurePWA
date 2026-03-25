import os

from dotenv import load_dotenv

load_dotenv()


class Config:
    SECRET_KEY: str = os.environ["SECRET_KEY"]

    SESSION_COOKIE_HTTPONLY: bool = True
    SESSION_COOKIE_SECURE: bool = True
    SESSION_COOKIE_SAMESITE: str = "Lax"
    SESSION_COOKIE_NAME: str = "session"

    REMEMBER_COOKIE_HTTPONLY: bool = True
    REMEMBER_COOKIE_SECURE: bool = True

    PERMANENT_SESSION_LIFETIME: int = 1800

    MAX_CONTENT_LENGTH: int = 16 * 1024 * 1024  # 16 MB

    MAIL_SERVER: str = os.environ.get("MAIL_SERVER", "smtp.gmail.com")
    MAIL_PORT: int = int(os.environ.get("MAIL_PORT", "587"))
    MAIL_USE_TLS: bool = os.environ.get("MAIL_USE_TLS", "true").lower() == "true"
    MAIL_USERNAME: str = os.environ.get("MAIL_USERNAME", "")
    MAIL_PASSWORD: str = os.environ.get("MAIL_PASSWORD", "")
    MAIL_DEFAULT_SENDER: str = os.environ.get(
        "MAIL_USERNAME", "noreply@unsecurepwa.local"
    )
    MAIL_DISPLAY_NAME: str = os.environ.get(
        "MAIL_DISPLAY_NAME", "The Unsecure PWA Company"
    )
    MAIL_DISPLAY_FROM: str = os.environ.get(
        "MAIL_DISPLAY_FROM", "noreply@unsecurepwa.local"
    )
