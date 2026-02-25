from flask import Flask, render_template, request, redirect, url_for
from flask_wtf.csrf import CSRFProtect
from flask_login import (
    LoginManager,
    UserMixin,
    login_user,
    logout_user,
    login_required,
    current_user,
)

from config import Config
import user_management as dbHandler

app = Flask(__name__)
app.config.from_object(Config)

CSRFProtect(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "home"  # type: ignore


class User(UserMixin):
    def __init__(self, username: str):
        self.id = username


@login_manager.user_loader
def load_user(username: str):
    if dbHandler.userExists(username):
        return User(username)
    return None


@app.route("/success.html", methods=["GET", "POST"])
@login_required
def addFeedback():
    if request.method == "POST":
        feedback = request.form["feedback"]
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

    username = request.form.get("username", "")
    password = request.form.get("password", "")
    DoB = request.form.get("dob", "")

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

    username = request.form.get("username", "")
    password = request.form.get("password", "")

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
