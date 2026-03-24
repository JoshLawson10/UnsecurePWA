import re

from flask import Flask, redirect, render_template, request, url_for
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

app = Flask(__name__)
app.config.from_object(Config)

CSRFProtect(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "home"  # type: ignore

MAX_USERNAME_LEN: int = 50
MAX_PASSWORD_LEN: int = 128
MAX_DOB_LEN: int = 10  # "YYYY-MM-DD"
MAX_FEEDBACK_LEN: int = 500

USERNAME_RE: re.Pattern = re.compile(r"^[a-zA-Z0-9_\-]+$")
DOB_RE: re.Pattern = re.compile(r"^\d{4}-\d{2}-\d{2}$")


def _validate_username(value: str) -> str:
    """Return the username if valid, otherwise abort with 400."""
    value = value.strip()
    if not value or len(value) > MAX_USERNAME_LEN:
        app.logger.critical(400, "Username must be between 1 and 50 characters.")
    if not USERNAME_RE.match(value):
        app.logger.critical(
            400, "Username may only contain letters, digits, underscores, and hyphens."
        )
    return value


def _validate_password(value: str) -> str:
    """Return the password if valid, otherwise abort with 400."""
    if not value or len(value) > MAX_PASSWORD_LEN:
        app.logger.critical(400, "Password must be between 1 and 128 characters.")
    return value


def _validate_dob(value: str) -> str:
    """Return the date-of-birth string if valid, otherwise abort with 400."""
    value = value.strip()
    if not value:
        return ""  # DoB is optional on signup
    if len(value) > MAX_DOB_LEN or not DOB_RE.match(value):
        app.logger.critical(400, "Date of birth must be in YYYY-MM-DD format.")
    return value


def _validate_feedback(value: str) -> str:
    """Return the feedback string if valid, otherwise abort with 400."""
    value = value.strip()
    if not value or len(value) > MAX_FEEDBACK_LEN:
        app.logger.critical(
            400, f"Feedback must be between 1 and {MAX_FEEDBACK_LEN} characters."
        )
    return value


class User(UserMixin):
    def __init__(self, username: str):
        self.id = username


@login_manager.user_loader
def load_user(username: str):
    if dbHandler.userExists(username):
        return User(username)
    return None


@app.after_request
def add_security_headers(response):
    csp = (
        "default-src 'self'; "
        "style-src 'self' https://cdn.jsdelivr.net;"
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

    return response


@app.route("/success.html", methods=["GET", "POST"])
@login_required
def addFeedback():
    if request.method == "POST":
        feedback = _validate_feedback(request.form.get("feedback", ""))
        dbHandler.insertFeedback(feedback)

    feedback_list = dbHandler.getFeedbackList()

    return render_template(
        "/success.html",
        state=True,
        value=current_user.id,
        feedback_list=feedback_list,
    )


@app.route("/signup.html", methods=["GET", "POST"])
def signup():
    if request.method == "GET":
        return render_template("/signup.html")

    username = _validate_username(request.form.get("username", ""))
    password = _validate_password(request.form.get("password", ""))
    DoB = _validate_dob(request.form.get("dob", ""))

    if dbHandler.userExists(username):
        return render_template(
            "/signup.html",
            msg="Username already exists.",
        )

    dbHandler.insertUser(username, password, DoB)

    return redirect(url_for("home", msg="Account created successfully! Please log in."))


@app.route("/index.html", methods=["GET", "POST"])
@app.route("/", methods=["GET", "POST"])
def home():
    if request.method == "GET":
        msg = request.args.get("msg", "")
        return render_template("/index.html", msg=msg)

    username = _validate_username(request.form.get("username", ""))
    password = _validate_password(request.form.get("password", ""))

    if not dbHandler.authenticateUser(username, password):
        return render_template(
            "/index.html",
            msg="Invalid username or password.",
        )

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
    app.run(debug=True, host="0.0.0.0", port=3000)
