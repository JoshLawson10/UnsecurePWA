import os
import re

from dotenv import load_dotenv

load_dotenv()

from flask import Flask, abort, redirect, render_template, request, session, url_for
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_login import (
    LoginManager,
    UserMixin,
    current_user,
    login_required,
    login_user,
    logout_user,
)
from flask_wtf.csrf import CSRFProtect

import user_management as dbHandler
from config import Config
from database_files.initialise_db import initialise_db
from mailer import mail, send_otp_email

# ---------- App Setup ----------
app = Flask(__name__)
app.config.from_object(Config)

# Ensure the database and schema exist before the first request is handled.
initialise_db()

CSRFProtect(app)
mail.init_app(app)

limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=[],
    storage_uri="memory://",
)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "home"  # type: ignore


# ---------- Input Validation ----------
MAX_USERNAME_LEN: int = 50
MAX_PASSWORD_LEN: int = 128
MAX_DOB_LEN: int = 10
MAX_EMAIL_LEN: int = 254
MAX_FEEDBACK_LEN: int = 500

USERNAME_RE: re.Pattern = re.compile(r"^[a-zA-Z0-9_\-]+$")
DOB_RE: re.Pattern = re.compile(r"^\d{4}-\d{2}-\d{2}$")
# RFC 5322 simplified — rejects obvious non-emails without over-validating.
EMAIL_RE: re.Pattern = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
OTP_RE: re.Pattern = re.compile(r"^\d{6}$")


def _validate_username(value: str) -> str:
    value = value.strip()
    if not value or len(value) > MAX_USERNAME_LEN:
        abort(400, "Username must be between 1 and 50 characters.")
    if not USERNAME_RE.match(value):
        abort(
            400, "Username may only contain letters, digits, underscores, and hyphens."
        )
    return value


def _validate_password(value: str) -> str:
    if not value or len(value) > MAX_PASSWORD_LEN:
        abort(400, "Password must be between 1 and 128 characters.")
    return value


def _validate_dob(value: str) -> str:
    value = value.strip()
    if not value:
        return ""
    if len(value) > MAX_DOB_LEN or not DOB_RE.match(value):
        abort(400, "Date of birth must be in YYYY-MM-DD format.")
    return value


def _validate_email(value: str) -> str:
    value = value.strip().lower()
    if not value or len(value) > MAX_EMAIL_LEN:
        abort(400, "Email must be between 1 and 254 characters.")
    if not EMAIL_RE.match(value):
        abort(400, "Please enter a valid email address.")
    return value


def _validate_otp(value: str) -> str:
    value = value.strip()
    if not OTP_RE.match(value):
        abort(400, "Verification code must be exactly 6 digits.")
    return value


def _validate_feedback(value: str) -> str:
    value = value.strip()
    if not value or len(value) > MAX_FEEDBACK_LEN:
        abort(400, f"Feedback must be between 1 and {MAX_FEEDBACK_LEN} characters.")
    return value


# ---------- User Model ----------
class User(UserMixin):
    def __init__(self, username: str):
        self.id = username


@login_manager.user_loader
def load_user(username: str):
    if dbHandler.userExists(username):
        return User(username)
    return None


# ---------- Security Headers ----------
@app.after_request
def add_security_headers(response):
    csp = (
        "default-src 'self'; "
        "style-src 'self' https://cdn.jsdelivr.net; "
        "script-src 'self' https://cdn.jsdelivr.net; "
        "img-src 'self' data:; "
        "font-src 'self'; "
        "connect-src 'self'; "
        "manifest-src 'self'; "
        "worker-src 'self'; "
        "object-src 'none'; "
        "base-uri 'self'; "
        "frame-ancestors 'none'; "
        "form-action 'self'; "
        "upgrade-insecure-requests"
    )
    response.headers["Content-Security-Policy"] = csp
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Strict-Transport-Security"] = (
        "max-age=31536000; includeSubDomains"
    )
    response.headers.pop("Server", None)
    return response


# ---------- Error Handlers ----------
@app.errorhandler(400)
def bad_request(e):
    return render_template("error.html", code=400, message="Bad request."), 400


@app.errorhandler(403)
def forbidden(e):
    return render_template("error.html", code=403, message="Forbidden."), 403


@app.errorhandler(404)
def not_found(e):
    return render_template("error.html", code=404, message="Page not found."), 404


@app.errorhandler(405)
def method_not_allowed(e):
    return render_template("error.html", code=405, message="Method not allowed."), 405


@app.errorhandler(413)
def request_too_large(e):
    return render_template("error.html", code=413, message="Request too large."), 413


@app.errorhandler(429)
def rate_limited(e):
    return render_template(
        "error.html", code=429, message="Too many requests. Please wait and try again."
    ), 429


@app.errorhandler(500)
def internal_error(e):
    return render_template(
        "error.html", code=500, message="An internal error occurred."
    ), 500


# ---------- Routes ----------


@app.route("/success.html", methods=["GET", "POST"])
@login_required
def addFeedback():
    if request.method == "POST":
        feedback = _validate_feedback(request.form.get("feedback", ""))
        dbHandler.insertFeedback(current_user.id, feedback)

    feedback_list = dbHandler.getFeedbackList()
    return render_template(
        "/success.html",
        state=True,
        value=current_user.id,
        feedback_list=feedback_list,
    )


@app.route("/signup.html", methods=["GET", "POST"])
@limiter.limit("10 per minute")
def signup():
    if request.method == "GET":
        return render_template("/signup.html")

    # Validate each field individually and return the error inline on the
    # form rather than aborting with a bare 400, so the user knows exactly
    # what to fix without losing what they already typed.
    try:
        username = _validate_username(request.form.get("username", ""))
        password = _validate_password(request.form.get("password", ""))
        DoB = _validate_dob(request.form.get("dob", ""))
        email = _validate_email(request.form.get("email", ""))
    except Exception as e:  # noqa: BLE001
        msg = getattr(e, "description", "Invalid input. Please check your details.")
        return render_template("/signup.html", msg=msg), 400

    if dbHandler.userExists(username):
        return render_template("/signup.html", msg="Username already exists.")

    dbHandler.insertUser(username, password, DoB, email)
    return redirect(url_for("home", msg="Account created successfully! Please log in."))


@app.route("/index.html", methods=["GET", "POST"])
@app.route("/", methods=["GET", "POST"])
@limiter.limit("20 per minute", methods=["POST"])
def home():
    if request.method == "GET":
        msg = request.args.get("msg", "")[:200]
        return render_template("/index.html", msg=msg)

    try:
        username = _validate_username(request.form.get("username", ""))
        password = _validate_password(request.form.get("password", ""))
    except Exception as e:  # noqa: BLE001
        msg = getattr(e, "description", "Invalid input.")
        return render_template("/index.html", msg=msg), 400

    if not dbHandler.authenticateUser(username, password):
        return render_template("/index.html", msg="Invalid username or password.")

    # Credentials are valid — begin 2FA flow.
    # Store the username in the session under a pending key so the /verify
    # route knows who is mid-login.  We do NOT call login_user() yet because
    # the second factor has not been verified.
    email = dbHandler.getEmailByUsername(username)

    if not email:
        return render_template(
            "/index.html",
            msg="Your account has no email address registered. "
            "Please contact an administrator to update your account.",
        )

    # Generate a fresh OTP and attempt to email it BEFORE persisting anything.
    # Only store the code and advance the session once delivery is confirmed,
    # so the user is never redirected to /verify with no valid code waiting.
    code = dbHandler.generateOTPCode()

    try:
        send_otp_email(email, code)
    except Exception:
        app.logger.exception("Failed to send OTP email to %s", email)
        return render_template(
            "/index.html",
            msg="Could not send verification email. Please try again later.",
        )

    # Email confirmed sent — now persist the hashed code and set the session.
    dbHandler.storeOTPCode(username, code)
    session["2fa_pending"] = True
    session["2fa_user"] = username

    return redirect(url_for("verify"))


@app.route("/verify", methods=["GET", "POST"])
@limiter.limit("10 per minute")
def verify():
    # Guard: only allow access if a 2FA flow is in progress.
    if not session.get("2fa_pending") or not session.get("2fa_user"):
        return redirect(url_for("home"))

    if request.method == "GET":
        return render_template("/verify.html")

    code = _validate_otp(request.form.get("code", ""))
    username = session["2fa_user"]

    if not dbHandler.verifyOTPCode(username, code):
        return render_template(
            "/verify.html", msg="Invalid or expired code. Please try again."
        )

    # Code is valid — complete the login.
    session.pop("2fa_pending", None)
    session.pop("2fa_user", None)

    user = User(username)
    login_user(user)

    return redirect(url_for("addFeedback"))


@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("home", msg="Logged out successfully."))


if __name__ == "__main__":
    app.config["TEMPLATES_AUTO_RELOAD"] = True
    app.config["SEND_FILE_MAX_AGE_DEFAULT"] = 0
    app.run(
        debug=os.environ.get("FLASK_DEBUG", "0") == "1",
        host="127.0.0.1",
        port=3000,
    )
